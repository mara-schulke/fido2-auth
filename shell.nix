let
  moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
  rust = (pkgs.rustChannelOf { date = "2022-04-10"; }).rust.override {
    targets = [ "wasm32-unknown-unknown" ];
    extensions = [
      "rust-std"
      "rust-src"
      "rls-preview"
      "rustfmt-preview"
      "clippy-preview"
    ];
  };
  pkgs = import <nixpkgs> { overlays = [ moz_overlay ]; };
in
  with pkgs;
  pkgs.stdenv.mkDerivation {
    name = "fido2-auth";

    buildInputs = with pkgs; [
      rust
      libsodium
      gcc
      openssl
      pkgconfig
    ];

    shellHook = with pkgs; ''
      export OPENSSL_DIR="${openssl.dev}"
      export OPENSSL_LIB_DIR="${openssl.out}/lib"
    '';
  }
