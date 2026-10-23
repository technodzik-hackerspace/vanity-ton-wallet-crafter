//! The wallet kinds the search supports, and how each turns a recovery phrase into an address.
//!
//! | kind       | phrase                         | key                                   | contract |
//! |------------|--------------------------------|---------------------------------------|----------|
//! | `telegram` | 12-word BIP-39                 | wallet-engine anchor key              | Telegram wallet, subwallet 0x7FFF7F11 (testnet 0x7FFF7FFD) |
//! | `v4r2`     | 24-word TON mnemonic           | PBKDF2 "TON default seed" (100k)      | V4R2, subwallet 698983191 |
//! | `v5r1`     | 24-word TON mnemonic           | PBKDF2 "TON default seed" (100k)      | V5R1, wallet id 0x7FFFFF11 (testnet 0x7FFFFFFD) |
//! | `ledger`   | 24-word BIP-39                 | SLIP-10 m/44'/607'/net'/0'/0'/0'      | V4R2, subwallet 698983191 |
//!
//! The Ledger path, curve mode and contract follow the Ledger TON app
//! (`HDW_ED25519_SLIP10`, `DEFAULT_SUBWALLET_ID`) and `@ton-community/ton-ledger`.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac as _};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest as _, Sha256, Sha512};
use ton::ton_wallet::{
    KeyPair, Mnemonic, TonWallet, WALLET_ID_DEFAULT, WALLET_SUBWALLET_ID_DEFAULT,
    WALLET_SUBWALLET_ID_DEFAULT_TESTNET, WALLET_V5R1_ID_DEFAULT, WALLET_V5R1_ID_DEFAULT_TESTNET,
    WalletVersion,
};
use wallet_engine::{
    ImportWalletRequest, MnemonicScheme, Network, TonAddressFormat, WalletDescriptor, WalletLifecycle,
};
use zeroize::Zeroizing;

use crate::DiscardHost;

/// BIP-39 test vectors: all-zero entropy, and the anchor key wallet-engine pins for the 12-word one.
const ZERO_ENTROPY_PHRASE_12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ZERO_ENTROPY_PHRASE_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon art";
const ZERO_ENTROPY_ANCHOR_KEY: &str = "7952e94118f34607c75e23258dd9220d66ccac5a3ee074125c25068e8107bfbf";

/// TON-mnemonic test vectors from the `ton` crate's own wallet tests.
const TON_V4R2_PHRASE: &str = "fancy carpet hello mandate penalty trial consider property top vicious \
    exit rebuild tragic profit urban major total month holiday sudden rib gather media vicious";
const TON_V4R2_ADDRESS: &str = "EQCDM_QGggZ3qMa_f3lRPk4_qLDnLTqdi6OkMAV2NB9r5TG3";
const TON_V5R1_PHRASE: &str = "section garden tomato dinner season dice renew length useful spin \
    trade intact use universe what post spike keen mandate behind concert egg doll rug";
const TON_V5R1_ADDRESS_MAINNET: &str = "UQDv2YSmlrlLH3hLNOVxC8FcQf4F9eGNs4vb2zKma4txo6i3";
const TON_V5R1_ADDRESS_TESTNET: &str = "0QA_6fh0aRAkD7n1MNfAUx8TvyCUw2iTQfzVM-0isMze2anN";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletKind {
    Telegram,
    V4R2,
    V5R1,
    Ledger,
}

impl WalletKind {
    pub const NAMES: &str = "\"telegram\", \"v4r2\", \"v5r1\" or \"ledger\"";

    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "telegram" | "tg" => Some(Self::Telegram),
            "v4r2" | "v4" => Some(Self::V4R2),
            "v5r1" | "v5" => Some(Self::V5R1),
            "ledger" => Some(Self::Ledger),
            _ => None,
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::Telegram => "Telegram wallet (12-word phrase)",
            Self::V4R2 => "wallet V4R2 (24-word TON phrase)",
            Self::V5R1 => "wallet V5R1 (24-word TON phrase)",
            Self::Ledger => "Ledger, account 0 (24-word BIP-39 phrase, V4R2)",
        }
    }

    /// Where to import the phrase to see the address.
    pub fn import_hint(self) -> &'static str {
        match self {
            Self::Telegram => "import it into Telegram's wallet",
            Self::V4R2 => "import it into Tonkeeper / MyTonWallet / Tonhub and pick wallet version v4R2",
            Self::V5R1 => "import it into Tonkeeper / MyTonWallet and pick wallet version W5 (v5R1)",
            Self::Ledger => {
                "restore a Ledger with it and open account #1 (index 0) in Ledger Live or Tonkeeper"
            }
        }
    }
}

/// One derived candidate. `address` is the non-bounceable user-friendly form (`UQ…` / `0Q…`).
pub struct Candidate {
    pub words: Vec<String>,
    pub address: String,
    pub public_key: [u8; 32],
}

pub struct Deriver {
    kind: WalletKind,
    network: Network,
    lifecycle: Arc<WalletLifecycle>,
    /// BIP-39 English, index-ordered.
    wordlist: Vec<String>,
}

impl Deriver {
    pub fn new(kind: WalletKind, network: Network) -> Self {
        let mut wordlist = wallet_engine::mnemonic_wordlist();
        wordlist.sort_unstable(); // BIP-39 English is ASCII-sorted: sorting recovers the indices
        assert_eq!(wordlist.len(), 2048, "unexpected word list size");
        Self { kind, network, lifecycle: WalletLifecycle::new(Arc::new(DiscardHost)), wordlist }
    }

    /// A fresh phrase from the OS CSPRNG, valid for this wallet kind.
    pub fn random_words(&self) -> Vec<String> {
        match self.kind {
            WalletKind::Telegram => {
                let mut entropy = Zeroizing::new([0_u8; 16]);
                getrandom::fill(entropy.as_mut()).expect("OS random generator failed");
                entropy_to_words(entropy.as_ref(), &self.wordlist)
            }
            WalletKind::Ledger => {
                let mut entropy = Zeroizing::new([0_u8; 32]);
                getrandom::fill(entropy.as_mut()).expect("OS random generator failed");
                entropy_to_words(entropy.as_ref(), &self.wordlist)
            }
            // As TON wallets generate it: 24 uniform words, redrawn until the seed is a "basic" one.
            WalletKind::V4R2 | WalletKind::V5R1 => loop {
                let mut random = Zeroizing::new([0_u8; 48]);
                getrandom::fill(random.as_mut()).expect("OS random generator failed");
                // 2048 = 2^11 words, so the low 11 bits of each u16 pick one without bias.
                let words: Vec<String> = random
                    .chunks_exact(2)
                    .map(|pair| u16::from_be_bytes([pair[0], pair[1]]) & 0x7FF)
                    .map(|index| self.wordlist[usize::from(index)].clone())
                    .collect();
                if ton_mnemonic(&words).is_some() {
                    return words;
                }
            },
        }
    }

    pub fn derive(&self, words: Vec<String>) -> Candidate {
        let mainnet = self.network == Network::Mainnet;
        let wallet = match self.kind {
            // `import_wallet` derives the anchor and the signing key, which for a 12-word phrase
            // are the same derivation run twice. Only the anchor sets the address, so derive it
            // alone; `confirm` re-checks the hit through the full import.
            WalletKind::Telegram => {
                let anchor = wallet_engine::rotation_mnemonic_public_key(words.join(" "))
                    .expect("engine rejected a generated phrase");
                let public_key = anchor.as_slice().try_into().expect("32-byte key");
                let wallet_id =
                    if mainnet { WALLET_SUBWALLET_ID_DEFAULT } else { WALLET_SUBWALLET_ID_DEFAULT_TESTNET };
                let key_pair = KeyPair { public_key, secret_key: [0; 64] };
                TonWallet::new_with_params(WalletVersion::Wallet, key_pair, 0, wallet_id)
            }
            WalletKind::V4R2 | WalletKind::V5R1 => {
                let key_pair = ton_mnemonic(&words)
                    .expect("not a TON mnemonic")
                    .to_key_pair()
                    .expect("TON key derivation failed");
                let (version, wallet_id) = match (self.kind, mainnet) {
                    (WalletKind::V4R2, _) => (WalletVersion::V4R2, WALLET_ID_DEFAULT),
                    (_, true) => (WalletVersion::V5R1, WALLET_V5R1_ID_DEFAULT),
                    (_, false) => (WalletVersion::V5R1, WALLET_V5R1_ID_DEFAULT_TESTNET),
                };
                TonWallet::new_with_params(version, key_pair, 0, wallet_id)
            }
            WalletKind::Ledger => {
                let seed = bip39_seed(&words);
                let network_index = if mainnet { 0 } else { 1 };
                let key = slip10_ed25519(seed.as_ref(), &[44, 607, network_index, 0, 0, 0]);
                TonWallet::new_with_params(WalletVersion::V4R2, key_pair(&key), 0, WALLET_ID_DEFAULT)
            }
        }
        .expect("wallet address derivation failed");
        Candidate {
            words,
            address: wallet.address.to_base64(mainnet, false, true),
            public_key: wallet.key_pair.public_key,
        }
    }

    /// False when the phrase also validates under another scheme, so a wallet app could
    /// import it as something else (TEP-0003 section 8). About 1 in 128 hits; we skip those.
    pub fn is_unambiguous(&self, words: &[String]) -> bool {
        let schemes = wallet_engine::detect_mnemonic_schemes(words.to_vec());
        match self.kind {
            WalletKind::Telegram => true,
            WalletKind::V4R2 | WalletKind::V5R1 => {
                !schemes.contains(&MnemonicScheme::Bip39) && !schemes.contains(&MnemonicScheme::Rotation)
            }
            WalletKind::Ledger => {
                !schemes.contains(&MnemonicScheme::Ton) && !schemes.contains(&MnemonicScheme::Rotation)
            }
        }
    }

    /// Re-derives a hit and returns its raw `0:…` address. For Telegram this goes through the
    /// engine's separate TON Connect path from the anchor key.
    pub fn confirm(&self, hit: &Candidate) -> String {
        if self.kind == WalletKind::Telegram {
            let descriptor = self.import(hit.words.clone());
            assert_eq!(descriptor.address.as_str(), hit.address, "re-import changed the address");
            return self
                .lifecycle
                .ton_connect_account(descriptor)
                .expect("engine failed to re-derive the address from the anchor key")
                .address;
        }
        let again = self.derive(hit.words.clone());
        assert_eq!(again.address, hit.address, "re-derivation changed the address");
        raw(&hit.address)
    }

    /// Checks every derivation step this kind uses against known vectors. Panics on mismatch.
    pub fn self_test(&self) {
        let zero12 = entropy_to_words(&[0; 16], &self.wordlist);
        assert_eq!(zero12.join(" "), ZERO_ENTROPY_PHRASE_12, "BIP-39 encoder self-test failed");
        let zero24 = entropy_to_words(&[0; 32], &self.wordlist);
        assert_eq!(zero24.join(" "), squash(ZERO_ENTROPY_PHRASE_24), "BIP-39 encoder self-test failed");

        match self.kind {
            WalletKind::Telegram => {
                let anchor = wallet_engine::rotation_mnemonic_public_key(ZERO_ENTROPY_PHRASE_12.to_owned())
                    .expect("engine rejected the BIP-39 test vector");
                assert_eq!(hex(&anchor), ZERO_ENTROPY_ANCHOR_KEY, "anchor-key self-test failed");
                let descriptor = self.import(zero12.clone());
                assert_eq!(descriptor.public_key, anchor, "import self-test failed");
                assert_eq!(self.derive(zero12).address, descriptor.address.as_str(), "address self-test failed");
            }
            WalletKind::Ledger => {
                // Our BIP-39 seed + SLIP-10 reproduce the engine's pinned m/44'/607'/0' key.
                let key = slip10_ed25519(bip39_seed(&zero12).as_ref(), &[44, 607, 0]);
                let public_key = key_pair(&key).public_key;
                assert_eq!(hex(&public_key), ZERO_ENTROPY_ANCHOR_KEY, "SLIP-10 self-test failed");
            }
            WalletKind::V4R2 => {
                // The vector is in bounceable form; compare the raw addresses.
                let address = self.derive(split(TON_V4R2_PHRASE)).address;
                assert_eq!(raw(&address), raw(TON_V4R2_ADDRESS), "V4R2 self-test failed");
            }
            WalletKind::V5R1 => {
                let expected = match self.network {
                    Network::Mainnet => TON_V5R1_ADDRESS_MAINNET,
                    Network::Testnet => TON_V5R1_ADDRESS_TESTNET,
                };
                assert_eq!(self.derive(split(TON_V5R1_PHRASE)).address, expected, "V5R1 self-test failed");
            }
        }
    }

    fn import(&self, words: Vec<String>) -> WalletDescriptor {
        pollster::block_on(self.lifecycle.import_wallet(ImportWalletRequest {
            record_id: "vanity".to_owned(),
            network: self.network,
            recovery_words: words,
        }))
        .expect("wallet-engine rejected a generated phrase")
    }
}

/// Encodes 128 or 256 bits of entropy as a 12- or 24-word BIP-39 phrase.
fn entropy_to_words(entropy: &[u8], wordlist: &[String]) -> Vec<String> {
    let mut bits = Zeroizing::new([0_u8; 33]);
    bits[..entropy.len()].copy_from_slice(entropy);
    // Checksum: the first len/4 bits of SHA-256; only those bits are read below.
    bits[entropy.len()] = Sha256::digest(entropy)[0];
    let words = (entropy.len() * 8 + entropy.len() / 4) / 11;
    (0..words)
        .map(|word| {
            let index = (0..11).fold(0_usize, |acc, bit| {
                let pos = word * 11 + bit;
                (acc << 1) | usize::from((bits[pos / 8] >> (7 - pos % 8)) & 1)
            });
            wordlist[index].clone()
        })
        .collect()
}

/// Parses a passwordless TON mnemonic; `None` unless its seed is a "basic" one.
fn ton_mnemonic(words: &[String]) -> Option<Mnemonic> {
    Mnemonic::new(words.iter().map(String::as_str).collect(), None).ok()
}

/// BIP-39 seed with an empty passphrase.
fn bip39_seed(words: &[String]) -> Zeroizing<[u8; 64]> {
    let phrase = Zeroizing::new(words.join(" "));
    let mut seed = Zeroizing::new([0_u8; 64]);
    pbkdf2_hmac::<Sha512>(phrase.as_bytes(), b"mnemonic", 2048, seed.as_mut());
    seed
}

/// SLIP-10 Ed25519 private key on a path where every index is hardened.
fn slip10_ed25519(seed: &[u8], path: &[u32]) -> Zeroizing<[u8; 32]> {
    let mut node = hmac_sha512(b"ed25519 seed", &[seed]);
    for &index in path {
        let index = (index | 0x8000_0000).to_be_bytes();
        node = hmac_sha512(&node[32..], &[&[0], &node[..32], &index]);
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&node[..32]);
    key
}

fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    let mut out = Zeroizing::new([0_u8; 64]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn key_pair(private_key: &[u8; 32]) -> KeyPair {
    let signing = SigningKey::from_bytes(private_key);
    KeyPair { public_key: signing.verifying_key().to_bytes(), secret_key: signing.to_keypair_bytes() }
}

/// `0:…` form of a user-friendly address.
fn raw(address: &str) -> String {
    wallet_engine::convert_ton_address(address.to_owned(), TonAddressFormat::Raw)
        .expect("address conversion failed")
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn squash(phrase: &str) -> String {
    phrase.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn split(phrase: &str) -> Vec<String> {
    phrase.split_whitespace().map(str::to_owned).collect()
}
