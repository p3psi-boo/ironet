{
  description = "Development environment for the Linux-only ironet prototype";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    systems.url = "github:nix-systems/default-linux";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      systems,
      ...
    }:
    {
      nixosModules.default =
        { pkgs, ... }@moduleArgs:
        import ./nixos/module.nix (
          moduleArgs
          // {
            defaultPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          }
        );
    }
    // flake-utils.lib.eachSystem (import systems) (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        rust = pkgs.rust-bin.stable."1.95.0".default.override {
          extensions = [
            "clippy"
            "rust-src"
            "rustfmt"
          ];
          targets = [
            "x86_64-unknown-linux-musl"
            # WASM policy guests (crates/ironet-policy-*) build for wasm32.
            "wasm32-unknown-unknown"
          ];
        };
        rustFuzz = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [ "rust-src" ];
        };
        rustPlatform = pkgs.makeRustPlatform {
          cargo = rust;
          rustc = rust;
        };
        # Expose musl-gcc without adding musl itself to the shell inputs.  A
        # direct musl build input injects its headers and libraries into host
        # build-script links, which breaks fresh cross-target builds.
        muslGcc = pkgs.writeShellScriptBin "musl-gcc" ''
          exec ${pkgs.musl.dev}/bin/musl-gcc "$@"
        '';
      in
      {
        packages.default = rustPlatform.buildRustPackage {
          pname = "ironet";
          version = "0.1.0";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.removeReferencesTo
          ];
          postInstall = ''
            # Rust embeds source paths used by panic locations. They are not
            # runtime dependencies and would otherwise retain the toolchain.
            remove-references-to -t ${rust} "$out/bin/ironet"
            remove-references-to -t ${rust} "$out/bin/ironetd"
          '';
          doCheck = true;
          meta.mainProgram = "ironet";
        };

        devShells.default = pkgs.mkShell {
          packages = [
            rust
            pkgs.cacert
            pkgs.git
            pkgs.iproute2
            pkgs.iptables
            pkgs.pkg-config
            pkgs.python3
            # scripts/profile-v2-netns*.sh: netem labs, iperf3 saturation,
            # concurrent ping, perf + FlameGraph post-processing.
            pkgs.iperf3
            pkgs.perf
            pkgs.flamegraph
            pkgs.ethtool
            pkgs.iputils
            pkgs.util-linux
            pkgs.coreutils
            pkgs.bc
            pkgs.file
            # WASM policy guest toolchain: component packaging / validation
            # (wasm-tools) and WIT binding generation (wit-bindgen CLI).
            pkgs.wasm-tools
            pkgs.wit-bindgen
            pkgs.b3sum
          ];

          RUST_SRC_PATH = "${rust}/lib/rustlib/src/rust/library";
          shellHook = ''
            echo "ironet dev shell"
            echo "  rustc:  $(rustc --version)"
          '';
        };

        devShells.static = pkgs.mkShell {
          packages = [
            rust
            muslGcc
            pkgs.binutils
            pkgs.dpkg
            pkgs.pkg-config
            pkgs.systemd
          ];

          CC_x86_64_unknown_linux_musl = "${muslGcc}/bin/musl-gcc";

          shellHook = ''
            echo "ironet static release shell"
            echo "  scripts/build-deb.sh"
          '';
        };

        devShells.fuzz = pkgs.mkShell {
          packages = [
            rustFuzz
            pkgs.cargo-fuzz
            pkgs.cacert
            pkgs.git
            pkgs.llvmPackages.clang
            pkgs.pkg-config
            pkgs.python3
          ];

          RUST_SRC_PATH = "${rustFuzz}/lib/rustlib/src/rust/library";
          shellHook = ''
            echo "ironet V2 fuzz shell"
            echo "  rustc:      $(rustc --version)"
            echo "  cargo-fuzz: $(cargo fuzz --version)"
          '';
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
