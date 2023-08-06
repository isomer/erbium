{ nixpkgs ? import <nixpkgs> {} }:
let cargo_nix = import ./Cargo.nix { pkgs = nixpkgs; };
in cargo_nix.workspaceMembers.erbium.build
