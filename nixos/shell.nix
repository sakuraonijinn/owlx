# `nix-shell nixos/shell.nix` from the checkout root gives you everything the
# engine and CLI need: aiohttp, websockets, Frida bindings, mitmproxy, curl.
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    python3
    python3Packages.aiohttp
    python3Packages.websockets
    frida-tools
    mitmproxy
    curl
  ];
}
