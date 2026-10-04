{
  description = "DMesh device-mesh, Android, MUSL, and ESP32 build dependencies";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config = {
              android_sdk.accept_license = true;
              allowUnfree = true;
            };
          };

          android = pkgs.androidenv.composeAndroidPackages {
            platformVersions = [ ];
            buildToolsVersions = [ ];
            includeNDK = false;
            includeEmulator = false;
            includeSources = false;
            includeSystemImages = false;
          };

          androidSdk = android.androidsdk;
          androidHome = "${androidSdk}/libexec/android-sdk";

          # Keep the real-hardware NAN/USD test binary in the DMesh flake.
          # The ordinary nixpkgs build does not enable the wpa_cli NAN
          # control surface used by the lmesh compatibility path.
          wpa-supplicant-nan = pkgs.wpa_supplicant.overrideAttrs (old: {
            pname = "wpa-supplicant-nan";
            extraConfig = (old.extraConfig or "") + ''

              CONFIG_CTRL_IFACE=y
              CONFIG_DRIVER_NL80211=y
              CONFIG_LIBNL32=y
              CONFIG_NAN_USD=y
              CONFIG_P2P=y
            '';
          });

          dmeshSetenv = pkgs.writeShellScriptBin "dmesh-setenv" ''
            _dmesh_repo="''${DMESH_REPO:-$PWD}"
            _dmesh_sdk="''${DMESH_ANDROID_SDK:-$_dmesh_repo/target/android-sdk}"

            if [ -d "$_dmesh_sdk/platforms" ]; then
              export ANDROID_HOME="$_dmesh_sdk"
            else
              export ANDROID_HOME="${androidHome}"
            fi
            export ANDROID_SDK_ROOT="$ANDROID_HOME"
            export JAVA_HOME="${pkgs.jdk17.home}"
            _dmesh_sdkmanager="$(find "${androidHome}/cmdline-tools" -path '*/bin/sdkmanager' -type f | sort -V | tail -n 1)"
            _dmesh_cmdline_bin="$(dirname "$_dmesh_sdkmanager")"
            if [ -d "$ANDROID_HOME/ndk" ]; then
              export ANDROID_NDK_HOME="$(find "$ANDROID_HOME/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)"
            fi

            if [ -n "''${BASH_SOURCE:-}" ]; then
              _dmesh_profile_bin="$(cd "$(dirname "''${BASH_SOURCE[0]}")" && pwd)"
            else
              _dmesh_profile_bin="$(cd "$(dirname "$0")" && pwd)"
            fi

            export PATH="$_dmesh_profile_bin:$JAVA_HOME/bin:$_dmesh_sdk/platform-tools:$_dmesh_sdk/emulator:$_dmesh_cmdline_bin:${androidHome}/platform-tools:$PATH"
          '';

          dmeshAndroidSdk = pkgs.writeShellScriptBin "dmesh-android-sdk" ''
            set -euo pipefail

            sdk_root="''${DMESH_ANDROID_SDK:-$PWD/target/android-sdk}"
            mkdir -p "$sdk_root"

            sdkmanager="$(find "${androidHome}/cmdline-tools" -path '*/bin/sdkmanager' -type f | sort -V | tail -n 1)"
            packages=(
              "platform-tools"
              "platforms;android-36"
              "build-tools;36.0.0"
              "ndk;29.0.14206865"
              "emulator"
            )

            yes | "$sdkmanager" --sdk_root="$sdk_root" --licenses >/dev/null || true
            "$sdkmanager" --sdk_root="$sdk_root" "''${packages[@]}"

            rustup target add \
              aarch64-linux-android \
              armv7-linux-androideabi \
              i686-linux-android \
              x86_64-linux-android

            echo "Installed Android SDK components in $sdk_root"
            echo "Load with: . target/nix/profile/bin/dmesh-setenv"
          '';

          deps = pkgs.symlinkJoin {
            name = "dmesh-deps";
            paths = [
              androidSdk
              dmeshAndroidSdk
              dmeshSetenv
              pkgs.bashInteractive
              pkgs.bluez
              pkgs.cargo-ndk
              pkgs.coreutils
              pkgs.findutils
              pkgs.gawk
              pkgs.git
              pkgs.gnugrep
              pkgs.gnused
              pkgs.gradle
              pkgs.iw
              pkgs.jdk17
              pkgs.openssh
              pkgs.python3
              pkgs.ripgrep
              pkgs.rustc
              pkgs.socat
              # Packet-level NAN diagnostics and Android PHY-rate capture.
              pkgs.tshark
              pkgs.rustup
              pkgs.unzip
              pkgs.which
              wpa-supplicant-nan
              pkgs.zip
              pkgs.stdenv.cc
              # `/usr/bin/time` is not guaranteed in the base runner; keep
              # timing evidence for device flashing reproducible.
              (pkgs.lib.hiPrio pkgs.time)
              musl-toolchain
            ];
            # Win command-name collisions with the sibling ssh-mesh BusyBox
            # runtime bundle. DMesh diagnostics require GNU coreutils and GNU
            # time semantics (notably timeout --foreground and time -f).
            meta.priority = 1;
          };

          # Host Linux binaries for the device mesh services and terminal
          # tooling. This builds the same artifacts as `scripts/build.sh musl`
          # (without the musl/Android toolchain: NixOS targets run the GNU
          # build), so deployments can come from the flake like other DMesh
          # dependencies instead of prebuilt `target/` files.
          mkDmesh = firmwareRoot: sourceRoot: sshMeshRoot: pkgs.rustPlatform.buildRustPackage {
            pname = "dmesh";
            version = "0.1.0";
            src = pkgs.lib.cleanSourceWith {
              src = sourceRoot;
              filter = path: type:
                let name = builtins.baseNameOf (toString path);
                in !(builtins.elem name [ ".git" "target" "result" ".vscode" ".agents" "android" ]);
            };
            nativeBuildInputs = [ pkgs.makeWrapper ];
            cargoLock = {
              lockFile = ./Cargo.lock;
              # mesh-api is sourced from the pinned ssh-mesh git revision.
              outputHashes."mesh-api-0.1.0" = "sha256-C3eWQxWt+g6jOACLZvyDX0P2MBTQK0DXvigLP/gg/Fs=";
            };
            postPatch = pkgs.lib.optionalString (sshMeshRoot != null) ''
              cat >> Cargo.toml <<'EOF'
              [patch."https://github.com/costinm/ssh-mesh"]
              ssh-mesh = { path = "${sshMeshRoot}/crates/ssh-mesh" }
              mesh = { path = "${sshMeshRoot}/crates/mesh" }
              EOF
            '';
            doCheck = false;
            cargoBuildFlags = [
              "-p" "lmesh"
              "-p" "dmesh-cli"
              "-p" "mesh-tun"
              "-p" "dmeshtui"
            ];
            postInstall = ''
              install -Dm644 crates/lmesh/resources/tools.json "$out/etc/schemas/tools.json"
              install -Dm644 crates/lmesh/resources/tools.json "$out/etc/schemas/lmesh/tools.json"
              wrapProgram "$out/bin/dmesh-cli" --set-default MESH_SCHEMA_DIR "$out/etc/schemas"
              ln -s ${pkgs.espflash}/bin/espflash "$out/bin/espflash"
              install -Dm755 scripts/flash-device.py "$out/libexec/dmesh/flash-device.py"
              makeWrapper ${pkgs.python3}/bin/python3 "$out/bin/dmesh-flash" \
                --add-flags "$out/libexec/dmesh/flash-device.py" \
                --set DMESH_INSTALL_ROOT "$out" \
                --prefix PATH : "$out/bin"
              install -Dm644 docs/flashing.md "$out/share/doc/dmesh/flashing.md"
            '' + pkgs.lib.optionalString (firmwareRoot != null) ''
              for cpu in esp32 esp32s3 esp32c6; do
                for image in recovery.bin main-app.bin; do
                  source="${firmwareRoot}/$cpu/$image"
                  if [ ! -s "$source" ]; then
                    echo "missing firmware artifact: $source" >&2
                    exit 1
                  fi
                  install -Dm644 "$source" "$out/share/dmesh/flash/$cpu/$image"
                done
                for size in 4mb 8mb; do
                  for image in stage2.bin partition-table.bin; do
                    source="${firmwareRoot}/$cpu/$size/$image"
                    if [ ! -s "$source" ]; then
                      echo "missing firmware artifact: $source" >&2
                      exit 1
                    fi
                    install -Dm644 "$source" "$out/share/dmesh/flash/$cpu/$size/$image"
                  done
                done
                default_size=4mb
                if [ "$cpu" = esp32s3 ]; then default_size=8mb; fi
                for image in stage2.bin partition-table.bin; do
                  cp "$out/share/dmesh/flash/$cpu/$default_size/$image" \
                     "$out/share/dmesh/flash/$cpu/$image"
                done
              done
            '';
            passthru.withFirmware = firmware: mkDmesh firmware sourceRoot sshMeshRoot;
            meta.priority = 5;
          };
          dmesh = mkDmesh null self null;
          firmwareRoot = builtins.getEnv "DMESH_FIRMWARE_ROOT";
          localSourceRoot = builtins.getEnv "DMESH_SOURCE_ROOT";
          sshMeshSourceRoot = builtins.getEnv "DMESH_SSH_MESH_DIR";
          localSource =
            if localSourceRoot == "" then self else
              builtins.path {
                path = localSourceRoot;
                name = "dmesh-source";
                filter = path: type:
                  let name = builtins.baseNameOf (toString path);
                  in !(builtins.elem name [ ".git" "target" "result" ".vscode" ".agents" "android" ]);
              };
          sshMeshSource =
            if sshMeshSourceRoot == "" then null else
              builtins.path {
                path = sshMeshSourceRoot;
                name = "ssh-mesh-source";
                filter = path: type:
                  let name = builtins.baseNameOf (toString path);
                  in !(builtins.elem name [ ".git" "target" "result" ".vscode" ".agents" ]);
              };
          musl-toolchain = pkgs.runCommand "dmesh-musl-toolchain" { } ''
            mkdir -p "$out/bin"
            for tool in ${pkgs.pkgsCross.musl64.stdenv.cc}/bin/*; do
              ln -s "$tool" "$out/bin/$(basename "$tool")"
            done
            for tool in gcc g++ cc c++ cpp ar as ld ld.bfd ld.gold nm objcopy objdump ranlib readelf size strings strip; do
              if [ -e "$out/bin/x86_64-unknown-linux-musl-$tool" ] &&
                 [ ! -e "$out/bin/x86_64-linux-musl-$tool" ]; then
                ln -s "x86_64-unknown-linux-musl-$tool" "$out/bin/x86_64-linux-musl-$tool"
              fi
            done
          '';
          muslDeps = pkgs.symlinkJoin {
            name = "dmesh-musl-deps";
            paths = [
              pkgs.stdenv.cc
              (pkgs.lib.hiPrio pkgs.time)
              pkgs.coreutils
              pkgs.findutils
              pkgs.git
              pkgs.gnugrep
              pkgs.gnused
              pkgs.ripgrep
              pkgs.rustc
              pkgs.rustup
              pkgs.which
              musl-toolchain
            ];
            meta.priority = 1;
          };
        in
        {
          inherit deps musl-toolchain wpa-supplicant-nan dmesh;
          dmesh-with-firmware =
            if firmwareRoot == "" then
              pkgs.runCommand "dmesh-with-firmware-unset" {} ''
                echo "Set DMESH_FIRMWARE_ROOT to the flash directory with all three CPUs and 4mb/8mb Stage2 variants, then use nix build --impure .#dmesh-with-firmware" >&2
                exit 1
              ''
            else
              mkDmesh (builtins.path { path = firmwareRoot; name = "dmesh-firmware"; }) localSource sshMeshSource;
          musl-deps = muslDeps;
          default = dmesh;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config = {
              android_sdk.accept_license = true;
              allowUnfree = true;
            };
          };
          deps = self.packages.${system}.deps;
        in
        {
          default = pkgs.mkShell {
            packages = [ deps ];
            shellHook = ''
              if [ -f target/nix/profile/bin/dmesh-setenv ]; then
                . target/nix/profile/bin/dmesh-setenv
              fi
              export CARGO_HOME="''${CARGO_HOME:-$PWD/target/.cargo}"
              export GRADLE_USER_HOME="''${GRADLE_USER_HOME:-$PWD/target/.gradle}"
            '';
          };
        }
      );
    };
}
