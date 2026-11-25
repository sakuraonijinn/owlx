# Optional NixOS module: imports a systemd *user* unit for the engine.
# In configuration.nix:
#   imports = [ /path/to/owlx/nixos/owlx.nix ];
#   services.owlx = {
#     enable = true;
#     root = /home/me/owlx;
#     tabletIP = "10.10.10.119";
#   };
# Create ~/.config/owlx/token (chmod 600) and, optionally,
# ~/.config/owlx/engine.env for further overrides. Dependencies are supplied by
# `nix-shell nixos/shell.nix` (or your system packages); no secret is stored in
# the Nix store or in git.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.owlx;
in {
  options.services.owlx = {
    enable = lib.mkEnableOption "owlx Frida/mitmproxy engine";

    root = lib.mkOption {
      type = lib.types.path;
      example = /home/me/owlx;
      description = "Path to the owlx checkout containing nixos/start-engine.sh.";
    };

    tabletIP = lib.mkOption {
      type = lib.types.str;
      default = "10.10.10.119";
      description = "LAN address of the tablet running frida-server.";
    };

    fridaPort = lib.mkOption {
      type = lib.types.port;
      default = 27042;
      description = "frida-server port on the tablet.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8787;
      description = "Port for the control API and OWL dashboard.";
    };

    mitm = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Start mitmproxy together with the engine.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.user.services.owlx-engine = {
      description = "owlx engine (Frida + mitmproxy control service)";
      wantedBy = [ "default.target" ];
      serviceConfig = {
        Type = "simple";
        WorkingDirectory = "%h";
        UMask = "0077";
        Environment = [
          "OWLX_ROOT=${cfg.root}"
          "TABLET_IP=${cfg.tabletIP}"
          "FRIDA_PORT=${toString cfg.fridaPort}"
          "OWLX_HOST=0.0.0.0"
          "OWLX_PORT=${toString cfg.port}"
          "OWLX_MITM=${if cfg.mitm then "1" else "0"}"
          "OWLX_TOKEN_FILE=%h/.config/owlx/token"
        ];
        EnvironmentFile = "-%h/.config/owlx/engine.env";
        ExecStart = "${cfg.root}/nixos/start-engine.sh foreground";
        Restart = "on-failure";
        RestartSec = "5s";
        RestartPreventExitStatus = "2";
        TimeoutStopSec = "20s";
        KillMode = "control-group";
      };
    };
  };
}
