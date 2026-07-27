{
  description = "ESP32 firmware dependencies for ssh-mesh mesh expansion";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        python = pkgs.python313;
        py = python.pkgs;

        meshtasticPackage = py.buildPythonPackage rec {
          pname = "meshtastic";
          version = "2.7.10";
          format = "wheel";

          src = py.fetchPypi {
            inherit pname version;
            format = "wheel";
            python = "py3";
            dist = "py3";
            hash = "sha256-5VyazF86WNwGGxx0CL25IPwI4gkk2fv1aYgRzKx0dH0=";
          };

          pythonRelaxDeps = [ "tabulate" ];

          dependencies = with py; [
            argcomplete
            bleak
            dotmap
            packaging
            print-color
            protobuf
            pypubsub
            pyqrcode
            pyserial
            pyyaml
            requests
            tabulate
            wcwidth
          ];

          pythonImportsCheck = [ "meshtastic" ];
          doCheck = false;
        };

        meshtastic = py.toPythonApplication meshtasticPackage;

        meshcore = py.buildPythonPackage rec {
          pname = "meshcore";
          version = "2.3.7";
          format = "wheel";

          src = py.fetchPypi {
            inherit pname version;
            format = "wheel";
            python = "py3";
            dist = "py3";
            hash = "sha256-lS8CiyVScVXngQPQFZj6OJfMz6eTuiAooyvDbIZ1nxQ=";
          };

          dependencies = with py; [
            bleak
            pycayennelpp
            pycryptodome
            pyserial-asyncio-fast
          ];

          pythonImportsCheck = [ "meshcore" ];
          doCheck = false;
        };

        meshcore-cli-package = py.buildPythonPackage rec {
          pname = "meshcore-cli";
          version = "1.5.7";
          format = "wheel";

          src = py.fetchPypi {
            pname = "meshcore_cli";
            inherit version;
            format = "wheel";
            python = "py3";
            dist = "py3";
            hash = "sha256-MsX4Un/kOZRj/rWiezi5u42BrtONd3Eo+6LmaIfkEB8=";
          };

          dependencies = with py; [
            bleak
            meshcore
            prompt-toolkit
            requests
          ];

          pythonImportsCheck = [ "meshcore_cli" ];
          doCheck = false;
        };

        meshcore-cli = py.toPythonApplication meshcore-cli-package;

        pythonEnv = python.withPackages (_: [
          meshtasticPackage
          meshcore
          meshcore-cli-package
        ]);

        esp32-deps = pkgs.symlinkJoin {
          name = "ssh-mesh-esp32-firmware-deps";
          paths = with pkgs; [
            cmake
            dfu-util
            espflash
            espup
            git
            ldproxy
            meshcore-cli
            meshtastic
            ninja
            pythonEnv
          ];
        };
      in
      {
        packages = {
          inherit esp32-deps meshtastic meshcore meshcore-cli pythonEnv;
          default = esp32-deps;
        };

        devShells.default = pkgs.mkShell {
          packages = [ esp32-deps ];
        };
      });
}
