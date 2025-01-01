{ lib, stdenv, fetchFromGitHub, substituteAll
, meson, ninja, pkg-config
, glib, jansson, sqlite, nghttp2, libsoup_3, nftables
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "httpknock";
  version = "0.1";

  src = ./.;

  strictDeps = true;
  depsBuildBuild = [
    pkg-config
  ];

  nativeBuildInputs = [
    meson ninja pkg-config
  ];

  buildInputs = [
    glib
    jansson
    sqlite
    nghttp2
    libsoup_3
    (nftables.override { withCli = false; })
  ];

  installPhase = ''
    mkdir -p $out
    mv httpknock-server $out/
    mv httpknock-addcred $out/
    mv httpknock $out/
  '';
})
