//! PBKDF2-HMAC-SHA512 over eight passwords at once.
//!
//! The search spends nearly all its time here: 2048 rounds per BIP-39 seed, 100k per TON key.
//! With AVX-512 each 512-bit register holds the same SHA-512 word of eight independent
//! lanes. Without it, the eight passwords go through the `pbkdf2` crate one by one.

use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use zeroize::Zeroizing;

pub const LANES: usize = 8;

/// One 64-byte derived key per password. All lanes share `salt` and `rounds`.
pub fn pbkdf2_hmac_sha512_x8(
    passwords: &[&[u8]; LANES],
    salt: &[u8],
    rounds: u32,
) -> Zeroizing<[[u8; 64]; LANES]> {
    #[cfg(target_arch = "x86_64")]
    if simd_available() {
        // SAFETY: the CPU supports AVX-512F, checked just above.
        return unsafe { avx512::pbkdf2(passwords, salt, rounds) };
    }
    scalar(passwords, salt, rounds)
}

/// True when [`pbkdf2_hmac_sha512_x8`] runs its eight lanes in parallel.
pub fn simd_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    return std::arch::is_x86_feature_detected!("avx512f");
    #[cfg(not(target_arch = "x86_64"))]
    return false;
}

/// The reference path, also used to check the SIMD one.
pub fn scalar(passwords: &[&[u8]; LANES], salt: &[u8], rounds: u32) -> Zeroizing<[[u8; 64]; LANES]> {
    let mut out = Zeroizing::new([[0_u8; 64]; LANES]);
    for (password, key) in passwords.iter().zip(out.iter_mut()) {
        pbkdf2_hmac::<Sha512>(password, salt, rounds, key);
    }
    out
}

#[cfg(target_arch = "x86_64")]
mod avx512 {
    use std::arch::x86_64::{
        __m512i, _mm512_add_epi64, _mm512_ror_epi64, _mm512_set1_epi64, _mm512_setzero_si512,
        _mm512_srli_epi64, _mm512_ternarylogic_epi64, _mm512_xor_si512,
    };

    use sha2::{Digest as _, Sha512};
    use zeroize::Zeroizing;

    use super::LANES;

    /// Eight SHA-512 states: register `i` holds word `i` of every lane.
    type State = [__m512i; 8];
    type Block = [__m512i; 16];

    const IV: [u64; 8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];

    const K: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ];

    #[target_feature(enable = "avx512f")]
    pub(super) fn pbkdf2(
        passwords: &[&[u8]; LANES],
        salt: &[u8],
        rounds: u32,
    ) -> Zeroizing<[[u8; 64]; LANES]> {
        assert!(rounds > 0, "PBKDF2 needs at least one round");
        // Salt, the block index, the 0x80 pad byte and the 16-byte length fit one block.
        assert!(salt.len() <= 128 - 4 - 1 - 16, "salt longer than one SHA-512 block");

        // HMAC key blocks, word-major: the password, or its SHA-512 when longer than a block.
        let mut ipad = Zeroizing::new([[0_u64; LANES]; 16]);
        let mut opad = Zeroizing::new([[0_u64; LANES]; 16]);
        for (lane, password) in passwords.iter().enumerate() {
            let mut key = Zeroizing::new([0_u8; 128]);
            if password.len() > key.len() {
                key[..64].copy_from_slice(&Sha512::digest(password));
            } else {
                key[..password.len()].copy_from_slice(password);
            }
            for (word, chunk) in key.chunks_exact(8).enumerate() {
                let k = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk"));
                ipad[word][lane] = k ^ 0x3636_3636_3636_3636;
                opad[word][lane] = k ^ 0x5c5c_5c5c_5c5c_5c5c;
            }
        }
        let iv = IV.map(|word| splat(word));
        let inner = compress(&iv, &std::array::from_fn(|word| to_vector(ipad[word])));
        let outer = compress(&iv, &std::array::from_fn(|word| to_vector(opad[word])));

        // U1 = HMAC(password, salt || INT(1)): the message is one block after the key block.
        let mut first = [0_u8; 128];
        first[..salt.len()].copy_from_slice(salt);
        first[salt.len()..salt.len() + 4].copy_from_slice(&1_u32.to_be_bytes());
        first[salt.len() + 4] = 0x80;
        first[120..].copy_from_slice(&((128 + salt.len() as u64 + 4) * 8).to_be_bytes());
        let first: Block = std::array::from_fn(|word| {
            splat(u64::from_be_bytes(first[word * 8..word * 8 + 8].try_into().expect("8 bytes")))
        });

        let mut u = hash_digest(&outer, &compress(&inner, &first));
        let mut t = u;
        for _ in 1..rounds {
            u = hash_digest(&outer, &hash_digest(&inner, &u));
            for (t, u) in t.iter_mut().zip(&u) {
                *t = _mm512_xor_si512(*t, *u);
            }
        }

        let mut out = Zeroizing::new([[0_u8; 64]; LANES]);
        for (word, vector) in t.iter().enumerate() {
            for (lane, value) in to_lanes(*vector).iter().enumerate() {
                out[lane][word * 8..word * 8 + 8].copy_from_slice(&value.to_be_bytes());
            }
        }
        out
    }

    /// SHA-512 of a 64-byte digest, continuing from a state that has absorbed one key block.
    #[target_feature(enable = "avx512f")]
    fn hash_digest(state: &State, digest: &State) -> State {
        let zero = _mm512_setzero_si512();
        let mut block = [zero; 16];
        block[..8].copy_from_slice(digest);
        block[8] = splat(0x80 << 56);
        block[15] = splat((128 + 64) * 8);
        compress(state, &block)
    }

    #[target_feature(enable = "avx512f")]
    fn compress(state: &State, block: &Block) -> State {
        let mut w = *block;
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for (i, &k) in K.iter().enumerate() {
            if i >= 16 {
                let w15 = w[(i - 15) % 16];
                let w2 = w[(i - 2) % 16];
                let s0 = xor3(_mm512_ror_epi64::<1>(w15), _mm512_ror_epi64::<8>(w15), _mm512_srli_epi64::<7>(w15));
                let s1 = xor3(_mm512_ror_epi64::<19>(w2), _mm512_ror_epi64::<61>(w2), _mm512_srli_epi64::<6>(w2));
                w[i % 16] = add4(w[i % 16], s0, w[(i - 7) % 16], s1);
            }
            let s1 = xor3(_mm512_ror_epi64::<14>(e), _mm512_ror_epi64::<18>(e), _mm512_ror_epi64::<41>(e));
            let ch = _mm512_ternarylogic_epi64::<0xCA>(e, f, g); // e ? f : g
            let t1 = _mm512_add_epi64(add4(h, s1, ch, splat(k)), w[i % 16]);
            let s0 = xor3(_mm512_ror_epi64::<28>(a), _mm512_ror_epi64::<34>(a), _mm512_ror_epi64::<39>(a));
            let maj = _mm512_ternarylogic_epi64::<0xE8>(a, b, c); // majority
            h = g;
            g = f;
            f = e;
            e = _mm512_add_epi64(d, t1);
            d = c;
            c = b;
            b = a;
            a = add4(t1, s0, maj, _mm512_setzero_si512());
        }
        let worked = [a, b, c, d, e, f, g, h];
        std::array::from_fn(|i| _mm512_add_epi64(state[i], worked[i]))
    }

    #[target_feature(enable = "avx512f")]
    fn xor3(x: __m512i, y: __m512i, z: __m512i) -> __m512i {
        _mm512_ternarylogic_epi64::<0x96>(x, y, z)
    }

    #[target_feature(enable = "avx512f")]
    fn add4(w: __m512i, x: __m512i, y: __m512i, z: __m512i) -> __m512i {
        _mm512_add_epi64(_mm512_add_epi64(w, x), _mm512_add_epi64(y, z))
    }

    #[target_feature(enable = "avx512f")]
    fn splat(value: u64) -> __m512i {
        _mm512_set1_epi64(value as i64)
    }

    fn to_vector(lanes: [u64; LANES]) -> __m512i {
        // SAFETY: both are 64 bytes of plain integers; element `i` is lane `i`.
        unsafe { std::mem::transmute(lanes) }
    }

    fn to_lanes(vector: __m512i) -> [u64; LANES] {
        // SAFETY: as in `to_vector`.
        unsafe { std::mem::transmute(vector) }
    }
}
