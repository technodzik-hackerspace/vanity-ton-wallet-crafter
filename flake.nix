{
  description = "Offline vanity-address generator for TON wallets: Telegram, V4R2, V5R1 and Ledger";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
    in
    {
      packages = forAllSystems (pkgs: {
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.vanity-ton-wallet-crafter;

        vanity-ton-wallet-crafter =
          assert pkgs.lib.assertMsg (pkgs.lib.versionAtLeast pkgs.rustc.version "1.96.1")
            "wallet-engine needs Rust >= 1.96.1, nixpkgs has ${pkgs.rustc.version}";
          pkgs.rustPlatform.buildRustPackage {
            pname = cargoToml.package.name;
            version = cargoToml.package.version;

            src = pkgs.lib.fileset.toSource {
              root = ./.;
              fileset = pkgs.lib.fileset.unions [
                ./Cargo.toml
                ./Cargo.lock
                ./src
              ];
            };

            cargoLock = {
              lockFile = ./Cargo.lock;
              # One fetch of the pinned wallet-engine revision; it also provides ton and ton-connect-*.
              outputHashes = {
                "wallet-engine-0.0.7" = "sha256-v2vrfrMrJ5mpfHft5FFkVJrzXakKr6+jL03FWm41hrs=";
              };
            };

            # Every wallet kind self-tests its derivation against known vectors before searching;
            # run the fast ones on a 1-character suffix. stdout (a throwaway phrase) is discarded.
            doInstallCheck = true;
            installCheckPhase = ''
              runHook preInstallCheck
              for kind in telegram ledger; do
                $out/bin/vanity-ton-wallet-crafter --threads 2 --wallet $kind --config /dev/null A > /dev/null
              done
              runHook postInstallCheck
            '';

            meta = {
              description = cargoToml.package.description;
              homepage = "https://github.com/technodzik-hackerspace/vanity-ton-wallet-crafter";
              license = pkgs.lib.licenses.mit;
              mainProgram = "vanity-ton-wallet-crafter";
              platforms = systems;
            };
          };
      });

      overlays.default = final: _prev: {
        vanity-ton-wallet-crafter = self.packages.${final.stdenv.hostPlatform.system}.default;
      };

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = pkgs.lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          meta.description = cargoToml.package.description;
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.default ];
          packages = [
            pkgs.clippy
            pkgs.rustfmt
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
