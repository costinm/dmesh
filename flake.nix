{
  description = "ssh-mesh — SSH library and L4 proxy with certificate/JWT authentication";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    (flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        muslTarget = "x86_64-unknown-linux-musl";

        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" ];
          targets = [ muslTarget ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

        # Filter source to Cargo/Rust files plus compile-time resources used by
        # include_str!/RustEmbed. This still excludes .git, target/, java/,
        # python/, etc.
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            (craneLib.filterCargoSources path type)
            || pkgs.lib.hasInfix "/resources/" (toString path)
            || pkgs.lib.hasInfix "/web/" (toString path);
        };

        nativeBuildInputs = with pkgs; [
          pkg-config
          curl
          python3
        ];

        # Common args for static MUSL builds
        commonArgs = {
          inherit src nativeBuildInputs;
          version = "0.1.0";
          strictDeps = true;
          doCheck = false; # Tests require network/system resources

          CARGO_BUILD_TARGET = muslTarget;
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        };

        # Native glibc build args for Python.
        # defaults and is intentionally kept out of the static MUSL aggregate.
        nativeArgs = {
          inherit src nativeBuildInputs;
          version = "0.1.0";
          strictDeps = true;
          doCheck = false;
        };

        mainCargoExtraArgs = "--workspace --bins";

        # Build main workspace deps once — shared by all main binary outputs.
        # Kernel, VM, and rootfs packages remain separate opt-in outputs.
        cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
          pname = "ssh-mesh";
          cargoExtraArgs = mainCargoExtraArgs;
        });

        # Helper to define a package with minimal boilerplate
        mkPackage = pname: cargoExtraArgs:
          craneLib.buildPackage (commonArgs // {
            inherit pname cargoArtifacts;
            cargoExtraArgs = cargoExtraArgs;
            postInstall = ''
              mkdir -p "$out/share/ssh-mesh/nixos"
              cp ${./nixos/module.nix} "$out/share/ssh-mesh/nixos/module.nix"
              cp ${./nixos/example.nix} "$out/share/ssh-mesh/nixos/example.nix"
              mkdir -p "$out/share/mesh-init/defaults"
              cp -rL ${./crates}/mesh-init/defaults/. "$out/share/mesh-init/defaults/"
              for app in ssh-mesh mesh-init; do
                if [ -d "${./crates}/$app/resources" ]; then
                  mkdir -p "$out/opt/$app/etc/schemas"
                  for schema in tools.json schema.json; do
                    if [ -f "${./crates}/$app/resources/$schema" ]; then
                      cp -L "${./crates}/$app/resources/$schema" \
                        "$out/opt/$app/etc/schemas/$schema"
                    fi
                  done
                fi
              done
              chmod -R +w "$out"
            '';
          });

        # ── Packages ──────────────────────────────────────────────

        musl-toolchain = pkgs.runCommand "ssh-mesh-musl-toolchain" { } ''
          mkdir -p "$out"
          for path in ${pkgs.pkgsCross.musl64.stdenv.cc}/*; do
            name="$(basename "$path")"
            if [ "$name" != bin ]; then
              ln -s "$path" "$out/$name"
            fi
          done

          mkdir -p "$out/bin"
          for path in ${pkgs.pkgsCross.musl64.stdenv.cc}/bin/*; do
            ln -s "$path" "$out/bin/$(basename "$path")"
          done
          for tool in gcc g++ cc c++ cpp ar as ld ld.bfd ld.gold nm objcopy objdump ranlib readelf size strings strip; do
            if [ -e "$out/bin/x86_64-unknown-linux-musl-$tool" ] &&
               [ ! -e "$out/bin/x86_64-linux-musl-$tool" ]; then
              ln -s "x86_64-unknown-linux-musl-$tool" "$out/bin/x86_64-linux-musl-$tool"
            fi
          done
        '';

        build-deps = pkgs.symlinkJoin {
          name = "ssh-mesh-build-deps";
          paths = with pkgs; [
            stdenv.cc
            musl-toolchain
            rustToolchain
            pkg-config
            curl
            python3
          ];
        };

        runtime-deps = pkgs.symlinkJoin {
          name = "ssh-mesh-runtime-deps";
          paths = [
            sshm-busybox-opt
            pkgs.bubblewrap
            pkgs.iperf3
            pkgs.iproute2
            pkgs.netcat
            pkgs.nftables
            pkgs.util-linux
          ];
        };

        # Python tools for the pure-Python mesh client. Keep this separate
        # from build-deps so runtime images do not gain Python test tooling.
        python-tools = pkgs.symlinkJoin {
          name = "ssh-mesh-python-tools";
          paths = [
            (pkgs.python3.withPackages (ps: [ ps.pip ps.pytest ]))
          ];
        };

        # Aggregate: main runtime binaries built in a single cargo invocation.
        ssh-mesh = mkPackage "ssh-mesh" mainCargoExtraArgs;

        # ── Docker image ──────────────────────────────────────────

        sshm-opt-bin = pkgs.runCommand "sshm-opt-bin" {} ''
          mkdir -p $out/opt/ssh-mesh
          ln -s ${ssh-mesh}/bin $out/opt/ssh-mesh/bin
          ln -s ${ssh-mesh}/share $out/opt/ssh-mesh/share
        '';

        sshm-busybox-opt = pkgs.runCommand "sshm-busybox-opt" {} ''
          mkdir -p $out/opt/busybox/bin
          for f in ${pkgs.pkgsStatic.busybox}/bin/*; do
            ln -s $f $out/opt/busybox/bin/$(basename $f)
          done
          ${pkgs.pkgsStatic.busybox}/bin/busybox --install -s $out/opt/busybox/bin
        '';

        # Baked-in configuration for users who prefer a pre-seeded image. It
        # reuses the canonical packaged defaults so the image cannot diverge
        # from first-start seeding; the image itself ships only the defaults
        # and lets mesh-init seed /home/system/etc/mesh-init at first start.
        sshm-config = pkgs.runCommand "sshm-config" {} ''
          mkdir -p $out/home/system/etc/mesh-init
          cp ${ssh-mesh}/share/mesh-init/defaults/ssh-mesh.toml \
            $out/home/system/etc/mesh-init/ssh-mesh.toml
        '';

        sshm = pkgs.dockerTools.buildLayeredImage {
          name = "docker.io/costinm/sshm";
          tag = "latest";
          contents = [
            sshm-opt-bin
            sshm-busybox-opt
            sshm-config
            pkgs.cacert
          ];
          extraCommands = ''
            mkdir -p tmp var/tmp var/run run root home/ssh-mesh/.ssh home/system/etc/mesh-init
            chmod 1777 tmp var/tmp
            chmod 0755 home/ssh-mesh root home/system/etc/mesh-init
            chmod 0700 home/ssh-mesh/.ssh
            chown -R 1001:1001 home/ssh-mesh 2>/dev/null || true
          '';
          config = {
            Entrypoint = [ "/opt/ssh-mesh/bin/mesh-init" ];
            Cmd = [];
            Env = [
              "PATH=/opt/ssh-mesh/bin:/opt/busybox/bin"
              "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-certificates.crt"
              "HOME=/root"
              "MESH_SSH_MESH_UID=1001"
            ];
            ExposedPorts = {
              "15022/tcp" = {};
              "8080/tcp" = {};
            };
          };
        };

      in
      {
        packages = {
            inherit ssh-mesh sshm sshm-config musl-toolchain build-deps runtime-deps python-tools;
            default = ssh-mesh;
        };

        checks = {
          inherit ssh-mesh;
          # Run clippy
          ssh-mesh-clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            pname = "ssh-mesh-clippy";
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });
          # Check formatting
          ssh-mesh-fmt = craneLib.cargoFmt {
            inherit src;
            pname = "ssh-mesh-fmt";
            version = "0.1.0";
          };
        };
      }
    )) // {
      nixosModules.mesh-init = ./nixos/module.nix;
      nixosModules.default = ./nixos/module.nix;

      nixosConfigurations = {
        containerSystem = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            ./nixos/module.nix
            ({ pkgs, ... }: {
              services.mesh-init = {
                enable = true;
                package = self.packages.x86_64-linux.ssh-mesh;
                authorizedKeys = [
                  (builtins.readFile ./crates/ssh-mesh/tests/testdata/alice/id_ecdsa.pub)
                ];
              };

              boot.isContainer = true;
              boot.loader.grub.enable = false;
              boot.loader.systemd-boot.enable = false;

              environment.systemPackages = with pkgs; [
                bash
                coreutils
                util-linux
              ];

              system.stateVersion = "26.05";
            })
          ];
        };
      };
    };
}
