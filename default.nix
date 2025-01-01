let
  nixpkgs = fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-24.05";
  pkgs = import nixpkgs {};
in
{
  knock_x86-64 = pkgs.pkgsStatic.callPackage ./knock.nix { };
  knock_aarch64 = pkgs.pkgsCross.aarch64-multiplatform-musl.pkgsStatic.callPackage ./knock.nix { };
}
