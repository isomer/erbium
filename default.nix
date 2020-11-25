{ nixpkgs ? import <nixpkgs> {} }:
(nixpkgs.callPackage ./Cargo.nix { inherit nixpkgs; }).rootCrate.build
