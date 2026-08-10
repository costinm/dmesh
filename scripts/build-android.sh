#!/bin/bash
# Build, install, and test the DMesh Android apps.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DMESH_NIX_PROFILE="${DMESH_NIX_PROFILE:-$SCRIPT_DIR/target/nix/profile}"

# shellcheck disable=SC1091
. "$SCRIPT_DIR/env.sh"

export CARGO_HOME="${CARGO_HOME:-$SCRIPT_DIR/target/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$SCRIPT_DIR/target/rustup}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$SCRIPT_DIR/target/.gradle}"
export TMPDIR="${TMPDIR:-$SCRIPT_DIR/target/tmp}"
mkdir -p "$CARGO_HOME" "$RUSTUP_HOME" "$GRADLE_USER_HOME" "$TMPDIR"

SSH_MESH_GIT_URL="${SSH_MESH_GIT_URL:-https://github.com/costinm/ssh-mesh}"
SSH_MESH_OVERRIDE_ACTIVE=0
CARGO_LOCK_BACKUP=""

restore_cargo_lock() {
    if [ -n "${CARGO_LOCK_BACKUP:-}" ] && [ -f "$CARGO_LOCK_BACKUP" ]; then
        cp "$CARGO_LOCK_BACKUP" "$SCRIPT_DIR/Cargo.lock"
        rm -f "$CARGO_LOCK_BACKUP"
        CARGO_LOCK_BACKUP=""
    fi
}

configure_ssh_mesh_override() {
    SSH_MESH_OVERRIDE_ACTIVE=0
    local override_dir="${DMESH_SSH_MESH_DIR:-}"
    if [ -z "$override_dir" ]; then
        for candidate in "$DMESH_REPO/../rust/ssh-mesh" "$DMESH_REPO/../ssh-mesh"; do
            if [ -f "$candidate/crates/ssh-mesh/Cargo.toml" ]; then
                override_dir="$candidate"
                break
            fi
        done
    fi

    local config="$CARGO_HOME/config.toml"
    if [ -z "$override_dir" ] || [ ! -d "$override_dir" ]; then
        if [ -f "$config" ] && grep -q "BEGIN DMESH SSH_MESH OVERRIDE" "$config"; then
            sed -i '/# BEGIN DMESH SSH_MESH OVERRIDE/,/# END DMESH SSH_MESH OVERRIDE/d' "$config"
        fi
        return
    fi

    for crate_dir in crates/ssh-mesh crates/mesh; do
        if [ ! -f "$override_dir/$crate_dir/Cargo.toml" ]; then
            echo "ERROR: DMESH_SSH_MESH_DIR does not look like ssh-mesh: $override_dir"
            echo "Missing: $crate_dir/Cargo.toml"
            exit 1
        fi
    done

    mkdir -p "$CARGO_HOME"
    touch "$config"
    if grep -q "BEGIN DMESH SSH_MESH OVERRIDE" "$config"; then
        sed -i '/# BEGIN DMESH SSH_MESH OVERRIDE/,/# END DMESH SSH_MESH OVERRIDE/d' "$config"
    fi
    cat >>"$config" <<EOF
# BEGIN DMESH SSH_MESH OVERRIDE
[patch."$SSH_MESH_GIT_URL"]
ssh-mesh = { path = "$override_dir/crates/ssh-mesh" }
mesh = { path = "$override_dir/crates/mesh" }
# END DMESH SSH_MESH OVERRIDE
EOF
    SSH_MESH_OVERRIDE_ACTIVE=1
    echo "Using local ssh-mesh override: $override_dir"
}

preserve_cargo_lock_for_override() {
    if [ "${SSH_MESH_OVERRIDE_ACTIVE:-0}" != "1" ] || [ ! -f "$SCRIPT_DIR/Cargo.lock" ]; then
        return
    fi
    CARGO_LOCK_BACKUP="$CARGO_HOME/Cargo.lock.before-ssh-mesh-override"
    cp "$SCRIPT_DIR/Cargo.lock" "$CARGO_LOCK_BACKUP"
    trap restore_cargo_lock EXIT
}

load_nix_profile_env() {
    if [ -f "$DMESH_NIX_PROFILE/bin/dmesh-setenv" ]; then
        # shellcheck disable=SC1090
        . "$DMESH_NIX_PROFILE/bin/dmesh-setenv"
    elif command -v dmesh-setenv >/dev/null 2>&1; then
        # shellcheck disable=SC1090
        . "$(command -v dmesh-setenv)"
    elif [ -d "$DMESH_NIX_PROFILE/bin" ]; then
        export PATH="$DMESH_NIX_PROFILE/bin:$PATH"
    fi
}

use_rustup_toolchain() {
    local rustup_bin="$DMESH_NIX_PROFILE/bin/rustup"
    local rust_bin="$RUSTUP_HOME/toolchains/stable-x86_64-unknown-linux-gnu/bin"

    if ! "$rustup_bin" toolchain list | grep -q '^stable-'; then
        "$rustup_bin" toolchain install stable --profile minimal
    fi
    export PATH="$rust_bin:$PATH"
}

nix_cmd() {
    if command -v nix >/dev/null 2>&1; then
        command -v nix
    elif [ -x /nix/var/nix/profiles/default/bin/nix ]; then
        echo /nix/var/nix/profiles/default/bin/nix
    else
        echo "ERROR: nix not found on PATH." >&2
        exit 1
    fi
}

install_nix_deps() {
    mkdir -p "$(dirname "$DMESH_NIX_PROFILE")"
    "$(nix_cmd)" profile install \
        --profile "$DMESH_NIX_PROFILE" \
        "path:$SCRIPT_DIR#deps"
    # The profile may already contain this local flake.  Upgrade it explicitly
    # so `deps` reflects the current flake.nix instead of silently retaining
    # an earlier closure.
    "$(nix_cmd)" profile upgrade --profile "$DMESH_NIX_PROFILE" --all
    echo "Installed DMesh build dependencies in $DMESH_NIX_PROFILE"
    echo "Load with: . target/nix/profile/bin/dmesh-setenv"

    if [ ! -d "$SCRIPT_DIR/target/android-sdk/ndk" ]; then
        "$DMESH_NIX_PROFILE/bin/dmesh-android-sdk"
    fi
    use_rustup_toolchain
    "$DMESH_NIX_PROFILE/bin/rustup" target add \
        aarch64-linux-android \
        armv7-linux-androideabi \
        i686-linux-android \
        x86_64-linux-android
}

detect_android_env() {
    load_nix_profile_env
    use_rustup_toolchain

    if [ -z "${ANDROID_HOME:-}" ]; then
        echo "ERROR: ANDROID_HOME is unset. Run scripts/build-android.sh deps, then source env.sh."
        exit 1
    fi

    if [ -z "${ANDROID_NDK_HOME:-}" ]; then
        local ndk_dir
        ndk_dir=$(find "$ANDROID_HOME/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -V | tail -1 || true)
        if [ -z "$ndk_dir" ]; then
            echo "ERROR: No Android NDK found under $ANDROID_HOME/ndk."
            echo "Run: dmesh-android-sdk"
            exit 1
        fi
        export ANDROID_NDK_HOME="$ndk_dir"
    fi

    export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
}

gradle() {
    "$SCRIPT_DIR/gradlew" "$@"
}

APP_DMESH_PKG="com.github.costinm.dmesh.lm"
APP_WEB_PKG="com.github.costinm.dmesh.web"
APP_CHAT_PKG="com.github.costinm.dmesh.chat"
ANDROID_EVIDENCE_STAMP="${DMESH_ANDROID_EVIDENCE_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"

profile_dir() {
    echo "release"
}

target_triple() {
    case "$1" in
        arm64-v8a) echo "aarch64-linux-android" ;;
        armeabi-v7a) echo "armv7-linux-androideabi" ;;
        x86) echo "i686-linux-android" ;;
        x86_64) echo "x86_64-linux-android" ;;
        *)
            echo "ERROR: unsupported Android ABI: $1" >&2
            exit 1
            ;;
    esac
}

copy_android_lib() {
    local crate_name="$1"
    local lib_name="$2"
    local android_build_type="$3"
    local abi="$4"
    local triple
    triple="$(target_triple "$abi")"

    local rust_profile
    rust_profile="$(profile_dir "$android_build_type")"
    local so_path="$SCRIPT_DIR/target/$triple/$rust_profile/lib$lib_name.so"
    if [ ! -f "$so_path" ]; then
        echo "ERROR: Built library not found at $so_path"
        exit 1
    fi

    local strip_libs="${DMESH_STRIP_ANDROID_LIBS:-}"
    if [ -z "$strip_libs" ]; then
        if [ "$android_build_type" = "release" ]; then
            strip_libs=1
        else
            strip_libs=0
        fi
    fi

    local strip_bin=""
    if [ "$strip_libs" = "1" ]; then
        strip_bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
        if [ ! -x "$strip_bin" ]; then
            echo "ERROR: Android llvm-strip not found at $strip_bin"
            exit 1
        fi
    fi

    local app
    for app in ${DMESH_JNILIB_APPS:-app-dmesh}; do
        local jnilib_dir="$SCRIPT_DIR/android/$app/src/main/jniLibs/$abi"
        local jnilib_so="$jnilib_dir/lib$lib_name.so"
        mkdir -p "$jnilib_dir"
        cp "$so_path" "$jnilib_so"
        local copied_size
        copied_size="$(stat -c%s "$jnilib_so")"
        if [ "$strip_libs" = "1" ]; then
            "$strip_bin" --strip-unneeded "$jnilib_so"
            local stripped_size
            stripped_size="$(stat -c%s "$jnilib_so")"
            echo "Copied $crate_name (rust $rust_profile, android $android_build_type) to: $jnilib_so"
            echo "Stripped $jnilib_so: $copied_size -> $stripped_size bytes"
        else
            echo "Copied $crate_name (rust $rust_profile, android $android_build_type, unstripped) to: $jnilib_so ($copied_size bytes)"
        fi
    done
}

clean_android_lib_outputs() {
    local lib_name="$1"
    local app
    for app in ${DMESH_JNILIB_APPS:-app-dmesh}; do
        local jnilib_dir="$SCRIPT_DIR/android/$app/src/main/jniLibs"
        if [ -d "$jnilib_dir" ]; then
            find "$jnilib_dir" -name "lib$lib_name.so" -type f -delete
        fi
    done
}

clean_app_dmesh_dmeshui() {
    local jnilib_dir="$SCRIPT_DIR/android/app-dmesh/src/main/jniLibs"
    if [ -d "$jnilib_dir" ]; then
        find "$jnilib_dir" -name 'libdmeshui.so' -type f -delete
    fi
}

copy_dmeshui_android_lib() {
    local requested_apps="${DMESH_UI_APPS:-app-chat}"
    local ui_apps=""
    local app

    for app in $requested_apps; do
        if [ "$app" = "app-dmesh" ]; then
            echo "Skipping dmeshui copy to app-dmesh; dmeshui is owned by app-chat."
            continue
        fi
        ui_apps="$ui_apps $app"
    done

    clean_app_dmesh_dmeshui
    if [ -z "${ui_apps// /}" ]; then
        ui_apps=" app-chat"
    fi

    DMESH_JNILIB_APPS="$ui_apps" \
        build_rust_package dmeshui dmeshui "$1" "$2"
}

build_rust_package() {
    local package="$1"
    local lib_name="$2"
    local android_build_type="$3"
    local abi_list="$4"
    local cargo_args=(build -p "$package" --lib --release)

    if [ "$android_build_type" != "debug" ] && [ "$android_build_type" != "release" ]; then
        echo "Usage: $0 build [debug|release]"
        exit 1
    fi

    clean_android_lib_outputs "$lib_name"
    for abi in $abi_list; do
        echo "=== Building $package for $abi (rust release, android $android_build_type) ==="
        cargo ndk -t "$abi" -P 28 "${cargo_args[@]}"
        copy_android_lib "$package" "$lib_name" "$android_build_type" "$abi"
    done
}

build_rust_native() {
    local build_type="${1:-debug}"

    echo "Using NDK: $ANDROID_NDK_HOME"
    echo "Using SDK: $ANDROID_HOME"
    echo ""
    configure_ssh_mesh_override
    preserve_cargo_lock_for_override
    clean_app_dmesh_dmeshui
    build_rust_package dmesh dmesh "$build_type" "${DMESH_ANDROID_ABIS:-arm64-v8a}"
    copy_dmeshui_android_lib "$build_type" "${DMESH_UI_ANDROID_ABIS:-arm64-v8a}"
    clean_app_dmesh_dmeshui
    restore_cargo_lock
    trap - EXIT
}

build_apps() {
    local build_type="${1:-debug}"
    local dmesh_task=":android:app-dmesh:assembleDebug"
    local web_task=":android:app-web:assembleDebug"
    local chat_task=":android:app-chat:assembleDebug"

    if [ "$build_type" = "release" ]; then
        dmesh_task=":android:app-dmesh:assembleRelease"
        web_task=":android:app-web:assembleRelease"
        chat_task=":android:app-chat:assembleRelease"
    elif [ "$build_type" != "debug" ]; then
        echo "Usage: $0 build [debug|release]"
        exit 1
    fi

    build_rust_native "$build_type"
    clean_app_dmesh_dmeshui
    rm -rf \
        "$SCRIPT_DIR/android/app-dmesh/build/outputs/apk/$build_type" \
        "$SCRIPT_DIR/android/app-web/build/outputs/apk/$build_type" \
        "$SCRIPT_DIR/android/app-chat/build/outputs/apk/$build_type" \
        "$SCRIPT_DIR/target/apk/$build_type"
    echo ""
    echo "=== Building Android APKs ($build_type) ==="
    gradle "$dmesh_task" "$web_task" "$chat_task"
    stage_apks "$build_type"
}

stage_apks() {
    local build_type="${1:-debug}"
    local out_dir="$SCRIPT_DIR/target/apk/$build_type"
    mkdir -p "$out_dir"

    find "$SCRIPT_DIR/android" \
        -path "*/build/outputs/apk/$build_type/*.apk" \
        -type f \
        -exec cp -f {} "$out_dir/" \;

    echo ""
    echo "Staged APKs in target/apk/$build_type:"
    find "$out_dir" -maxdepth 1 -type f -name '*.apk' -printf '  %f\n' | sort
}

selected_android_devices() {
    # Physical includes USB and Wi-Fi ADB devices. The latter exercise Android
    # scheduling and background behavior differently, so they are first-class
    # validation targets. Use `usb` only for a cable-focused run.
    local selector="${DMESH_ANDROID_DEVICES:-physical}"
    local serial usb

    while read -r serial usb; do
        [ -n "$serial" ] || continue
        case "$selector" in
            all)
                printf '%s\n' "$serial"
                ;;
            physical)
                [[ "$serial" != emulator-* ]] && printf '%s\n' "$serial"
                ;;
            usb)
                [ "$usb" = "usb" ] && printf '%s\n' "$serial"
                ;;
            emulator)
                [[ "$serial" == emulator-* ]] && printf '%s\n' "$serial"
                ;;
            *)
                [[ ",$selector," == *",$serial,"* ]] && printf '%s\n' "$serial"
                ;;
        esac
    done < <(adb devices -l | awk 'NR > 1 && $2 == "device" { usb=""; for (i = 3; i <= NF; i++) if ($i ~ /^usb:/) usb="usb"; print $1, usb }')
    return 0
}

require_android_devices() {
    local devices
    devices="$(selected_android_devices)"
    if [ -z "$devices" ]; then
        echo "ERROR: no selected Android devices."
        echo "Connect a device, set DMESH_ANDROID_DEVICES=usb/all, or run '$0 emulator'."
        exit 1
    fi
    printf '%s\n' "$devices"
}

start_emulator() {
    local avd_name="${DMESH_AVD_NAME:-${ANDROID_AVD_NAME:-Medium_Desktop_2}}"
    local serial
    serial="$(selected_android_devices | head -1 || true)"
    if [ -n "$serial" ]; then
        echo "Reusing connected Android device/emulator: $serial"
        return
    fi

    if ! command -v emulator >/dev/null 2>&1; then
        echo "ERROR: emulator not found. Expected at $ANDROID_HOME/emulator."
        exit 1
    fi

    echo "=== Starting detached headless emulator: $avd_name ==="
    nohup setsid emulator \
        -avd "$avd_name" \
        -no-window \
        -no-audio \
        -no-boot-anim \
        -gpu swiftshader_indirect \
        -netdelay none \
        -no-snapshot-save \
        >"$SCRIPT_DIR/target/emulator.log" 2>&1 \
        </dev/null &
    local emulator_pid=$!
    disown || true

    sleep 2
    if ! kill -0 "$emulator_pid" >/dev/null 2>&1; then
        echo "ERROR: emulator failed to start for AVD '$avd_name'."
        echo "Available AVDs:"
        emulator -list-avds 2>/dev/null || true
        echo "See target/emulator.log"
        tail -40 "$SCRIPT_DIR/target/emulator.log" || true
        exit 1
    fi

    wait_for_emulator
}

wait_for_emulator() {
    local timeout="${DMESH_EMULATOR_TIMEOUT:-240}"
    local start
    start=$(date +%s)

    echo "=== Waiting for emulator boot ==="
    adb wait-for-device

    while true; do
        local booted
        booted="$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
        if [ "$booted" = "1" ]; then
            adb shell input keyevent 82 >/dev/null 2>&1 || true
            echo "Emulator booted"
            return
        fi
        if [ $(( $(date +%s) - start )) -gt "$timeout" ]; then
            echo "ERROR: emulator did not boot within ${timeout}s"
            echo "See target/emulator.log"
            exit 1
        fi
        sleep 2
    done
}

install_apps() {
    local build_type="${1:-debug}"
    local dmesh_apk="$SCRIPT_DIR/android/app-dmesh/build/outputs/apk/debug/app-dmesh-debug.apk"
    local web_apk="$SCRIPT_DIR/android/app-web/build/outputs/apk/debug/app-web-debug.apk"
    local chat_apk="$SCRIPT_DIR/android/app-chat/build/outputs/apk/debug/app-chat-debug.apk"

    if [ "$build_type" = "release" ]; then
        dmesh_apk="$SCRIPT_DIR/android/app-dmesh/build/outputs/apk/release/app-dmesh-release.apk"
        web_apk="$SCRIPT_DIR/android/app-web/build/outputs/apk/release/app-web-release.apk"
        chat_apk="$SCRIPT_DIR/android/app-chat/build/outputs/apk/release/app-chat-release.apk"
    elif [ "$build_type" != "debug" ]; then
        echo "Usage: $0 install [debug|release]"
        exit 1
    fi

    local serial index=0 failures=0
    local -a devices
    build_apps "$build_type"
    mapfile -t devices < <(require_android_devices)
    for serial in "${devices[@]}"; do
        if ! install_apps_on_device "$serial" "$dmesh_apk" "$web_apk" "$chat_apk"; then
            echo "ERROR: [$serial] install failed; continuing with remaining devices." >&2
            failures=1
            continue
        fi
        if ! setup_device "$serial"; then
            echo "ERROR: [$serial] service/NAN setup failed; continuing with remaining devices." >&2
            failures=1
            continue
        fi
        if ! create_host_forwards_for_device "$serial" "$index"; then
            echo "ERROR: [$serial] host-forward setup failed; continuing with remaining devices." >&2
            failures=1
            continue
        fi
        index=$((index + 1))
    done
    return "$failures"
}

install_all_apps() {
    local build_type="${1:-debug}"
    local dmesh_apk="$SCRIPT_DIR/android/app-dmesh/build/outputs/apk/$build_type/app-dmesh-$build_type.apk"
    local web_apk="$SCRIPT_DIR/android/app-web/build/outputs/apk/$build_type/app-web-$build_type.apk"
    local chat_apk="$SCRIPT_DIR/android/app-chat/build/outputs/apk/$build_type/app-chat-$build_type.apk"
    local serial index=0 failures=0
    local -a devices

    build_apps "$build_type"
    mapfile -t devices < <(require_android_devices)
    for serial in "${devices[@]}"; do
        if [ "${DMESH_CONFIRM_UNINSTALL:-0}" == "1" ]; then
            uninstall_apps_on_device "$serial"
        fi
        if ! install_apps_on_device "$serial" "$dmesh_apk" "$web_apk" "$chat_apk"; then
            echo "ERROR: [$serial] install failed; continuing with remaining devices." >&2
            failures=1
            continue
        fi
        if ! setup_device "$serial"; then
            echo "ERROR: [$serial] service/NAN setup failed; continuing with remaining devices." >&2
            failures=1
            continue
        fi
        if ! create_host_forwards_for_device "$serial" "$index"; then
            echo "ERROR: [$serial] host-forward setup failed; continuing with remaining devices." >&2
            failures=1
            continue
        fi
        index=$((index + 1))
    done
    return "$failures"
}

grant_app_permissions() {
    local serial="$1"
    local pkg="$2"

    echo "=== Granting runtime permissions for $pkg where possible ==="
    adb -s "$serial" shell pm grant "$pkg" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
    adb -s "$serial" shell pm grant "$pkg" android.permission.ACCESS_FINE_LOCATION >/dev/null 2>&1 || true
    adb -s "$serial" shell pm grant "$pkg" android.permission.ACCESS_COARSE_LOCATION >/dev/null 2>&1 || true
    adb -s "$serial" shell pm grant "$pkg" android.permission.NEARBY_WIFI_DEVICES >/dev/null 2>&1 || true
    adb -s "$serial" shell pm grant "$pkg" android.permission.BLUETOOTH_CONNECT >/dev/null 2>&1 || true
    adb -s "$serial" shell pm grant "$pkg" android.permission.BLUETOOTH_SCAN >/dev/null 2>&1 || true
    adb -s "$serial" shell pm grant "$pkg" android.permission.BLUETOOTH_ADVERTISE >/dev/null 2>&1 || true

    # ACTIVATE_VPN is an app-op on many emulator images rather than a runtime
    # permission. Ignore failures so the instrumentation can report unsupported
    # images with the actual VpnService.prepare state.
    adb -s "$serial" shell appops set "$pkg" ACTIVATE_VPN allow >/dev/null 2>&1 || true
    adb -s "$serial" shell cmd appops set "$pkg" ACTIVATE_VPN allow >/dev/null 2>&1 || true
}

install_apps_on_device() {
    local serial="$1"
    local dmesh_apk="$2"
    local web_apk="$3"
    local chat_apk="$4"
    echo "=== [$serial] Installing app-dmesh/app-web/app-chat ==="
    # ADB installs may block forever after a USB transport reset.  Bound the
    # operation so install-all can continue with other USB or Wi-Fi devices.
    local install_timeout="${DMESH_ADB_INSTALL_TIMEOUT:-120}"
    timeout --foreground "$install_timeout" adb -s "$serial" install -r "$dmesh_apk"
    timeout --foreground "$install_timeout" adb -s "$serial" install -r "$web_apk"
    timeout --foreground "$install_timeout" adb -s "$serial" install -r "$chat_apk"
}

uninstall_apps_on_device() {
    local serial="$1"
    local pkg
    echo "=== [$serial] Removing existing DMesh packages and their app data ==="
    for pkg in "$APP_DMESH_PKG" "$APP_WEB_PKG" "$APP_CHAT_PKG"; do
        adb -s "$serial" uninstall "$pkg" >/dev/null 2>&1 || true
    done
}

setup_device() {
    local serial="$1"
    local deadline=$((SECONDS + ${DMESH_SERVICE_START_TIMEOUT:-15}))
    grant_app_permissions "$serial" "$APP_DMESH_PKG"
    adb -s "$serial" shell am start-foreground-service -n "$APP_DMESH_PKG/.DMService" >/dev/null || \
        adb -s "$serial" shell am startservice -n "$APP_DMESH_PKG/.DMService" >/dev/null
    while ! adb -s "$serial" shell dumpsys activity services "$APP_DMESH_PKG/.DMService" \
        | grep -q 'isForeground=true'; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            echo "ERROR: [$serial] app-dmesh did not enter the foreground service state."
            adb -s "$serial" shell dumpsys activity services "$APP_DMESH_PKG/.DMService" | head -60 || true
            return 1
        fi
        sleep 1
    done
    echo "=== [$serial] app-dmesh service status ==="
    adb -s "$serial" shell dumpsys activity services "$APP_DMESH_PKG/.DMService" \
        | grep -E 'app=|startForegroundCount=|isForeground=|foregroundId=' || true
    configure_nan_role "$serial"
    capture_android_evidence "$serial" "post-start"
}

android_shell_command() {
    local serial="$1"
    local command="$2"
    # `adb shell` joins argv before Android's shell sees it. Quote the command
    # as one remote-shell argument or `wifi.nan.role sub-active` becomes two
    # content arguments and is silently rejected by the provider CLI.
    local escaped_command
    escaped_command="${command//\'/\'\\\'\'}"
    timeout --foreground "${DMESH_ADB_COMMAND_TIMEOUT:-30}" adb -s "$serial" shell \
        "content call --uri content://$APP_DMESH_PKG.shell --method command --arg '$escaped_command'"
}

nan_role_for_device() {
    local serial="$1"
    local entry key value
    local role="${DMESH_NAN_ROLE:-both}"
    local mapping="${DMESH_NAN_ROLE_MAP:-}"
    local -a entries
    IFS=',' read -r -a entries <<<"$mapping"
    for entry in "${entries[@]}"; do
        key="${entry%%=*}"
        value="${entry#*=}"
        if [ -n "$key" ] && [ "$key" = "$serial" ] && [ "$value" != "$entry" ]; then
            role="$value"
            break
        fi
    done
    printf '%s\n' "$role"
}

configure_nan_role() {
    local serial="$1"
    local role
    role="$(nan_role_for_device "$serial")"
    case "$role" in
        both|sub-active|sub-passive|sub-passive-empty-ssi|pub-solicited|pub-unsolicited) ;;
        *)
            echo "ERROR: [$serial] invalid NAN role '$role'" >&2
            return 1
            ;;
    esac
    echo "=== [$serial] NAN role: $role ==="
    android_shell_command "$serial" "wifi.nan.role role=$role" >/dev/null
    android_shell_command "$serial" "wifi.nan.status" >/dev/null
}

capture_android_evidence() {
    local serial="$1"
    local label="${2:-snapshot}"
    local history_duration_ms="${DMESH_NAN_HISTORY_DURATION_MS:-5000}"
    local safe_serial="${serial//[^A-Za-z0-9_.-]/_}"
    local out_dir="${DMESH_ANDROID_EVIDENCE_DIR:-$SCRIPT_DIR/target/android-evidence/$ANDROID_EVIDENCE_STAMP}/$safe_serial"
    mkdir -p "$out_dir"

    adb -s "$serial" shell dumpsys activity services "$APP_DMESH_PKG/.DMService" \
        >"$out_dir/$label-service.txt" 2>&1 || true
    # Android versions spell this service differently. Keep both raw outputs;
    # empty/unsupported output is evidence too and does not hide the other.
    adb -s "$serial" shell dumpsys wifiaware >"$out_dir/$label-wifiaware.txt" 2>&1 || true
    adb -s "$serial" shell dumpsys wifi aware >"$out_dir/$label-wifi-aware.txt" 2>&1 || true
    adb -s "$serial" shell dumpsys deviceidle >"$out_dir/$label-deviceidle.txt" 2>&1 || true
    adb -s "$serial" shell dumpsys package "$APP_DMESH_PKG" >"$out_dir/$label-package.txt" 2>&1 || true
    android_shell_command "$serial" \
        "history durationMs=$history_duration_ms limit=240 keys=net.NAN,wifi.nan" \
        >"$out_dir/$label-nan-history.txt" 2>&1 || true
    android_shell_command "$serial" "wifi.nan.status" \
        >"$out_dir/$label-nan-status-command.txt" 2>&1 || true
    cat >"$out_dir/$label-meta.env" <<EOF
DMESH_ADB_SERIAL=$serial
DMESH_NAN_ROLE=$(nan_role_for_device "$serial")
DMESH_EVIDENCE_TIMESTAMP=$ANDROID_EVIDENCE_STAMP
EOF
    echo "Saved Android NAN evidence: $out_dir"
}

create_host_forwards_for_device() {
    local serial="$1"
    local index="$2"
    local ssh_port=$(( ${DMESH_FORWARD_SSH_BASE:-11522} + index ))
    local http_port=$(( ${DMESH_FORWARD_HTTP_BASE:-18480} + index ))
    local lmesh_port=$(( ${DMESH_FORWARD_LMESH_BASE:-11622} + index ))
    local app_files="/data/user/0/$APP_DMESH_PKG/files"
    local lmesh_socket="$app_files/run/mesh/lmesh/mesh.sock"
    local env_dir="$SCRIPT_DIR/target/android-forwards"
    local socket_state="not-listening"

    mkdir -p "$env_dir"
    adb -s "$serial" forward --remove "tcp:$ssh_port" >/dev/null 2>&1 || true
    adb -s "$serial" forward --remove "tcp:$http_port" >/dev/null 2>&1 || true
    adb -s "$serial" forward --remove "tcp:$lmesh_port" >/dev/null 2>&1 || true
    adb -s "$serial" forward "tcp:$ssh_port" "tcp:${DMESH_DEVICE_SSH_PORT:-15022}"
    adb -s "$serial" forward "tcp:$http_port" "tcp:${DMESH_DEVICE_HTTP_PORT:-18480}"

    # Android's app-private UDS cannot be assumed to exist: app-dmesh currently
    # reaches lmesh through the generic proxy bridge. Keep this canonical path
    # stable for the future Binder-FD/UDS owner and expose it when a listener is
    # actually present.
    if adb -s "$serial" shell run-as "$APP_DMESH_PKG" test -S "files/run/mesh/lmesh/mesh.sock"; then
        if adb -s "$serial" forward "tcp:$lmesh_port" "localfilesystem:$lmesh_socket"; then
            socket_state="forwarded"
        else
            socket_state="present-but-adb-forward-failed"
        fi
    fi

    cat >"$env_dir/$serial.env" <<EOF
# Generated by scripts/build-android.sh forwards/install/install-all.
DMESH_ADB_SERIAL=$serial
DMESH_HOST_SSH_PORT=$ssh_port
DMESH_HOST_HTTP_PORT=$http_port
DMESH_HOST_LMESH_PORT=$lmesh_port
DMESH_DEVICE_LMESH_SOCKET=$lmesh_socket
DMESH_LMESH_SOCKET_STATE=$socket_state
EOF
    echo "=== [$serial] host forwards ==="
    adb -s "$serial" forward --list | grep "$serial" || true
    echo "Saved $env_dir/$serial.env"
}

create_host_forwards() {
    local serial index=0
    local -a devices
    mapfile -t devices < <(require_android_devices)
    for serial in "${devices[@]}"; do
        create_host_forwards_for_device "$serial" "$index"
        index=$((index + 1))
    done
}

capture_all_android_evidence() {
    local serial
    local -a devices
    mapfile -t devices < <(require_android_devices)
    for serial in "${devices[@]}"; do
        [ -n "$serial" ] || continue
        capture_android_evidence "$serial" "manual"
    done
}

send_nan_message() {
    local peer="${1:-${DMESH_NAN_PEER:-}}"
    local text="${2:-${DMESH_NAN_TEXT:-}}"
    if [ -z "$peer" ] || [ -z "$text" ]; then
        echo "Usage: $0 nan-message <peer-id> <text>" >&2
        echo "Or set DMESH_NAN_PEER and DMESH_NAN_TEXT." >&2
        return 2
    fi

    local serial safe_serial out_dir result failures=0
    local -a devices
    mapfile -t devices < <(require_android_devices)
    for serial in "${devices[@]}"; do
        safe_serial="${serial//[^A-Za-z0-9_.-]/_}"
        out_dir="${DMESH_ANDROID_EVIDENCE_DIR:-$SCRIPT_DIR/target/android-evidence/$ANDROID_EVIDENCE_STAMP}/$safe_serial"
        mkdir -p "$out_dir"
        capture_android_evidence "$serial" "nan-message-before"
        echo "=== [$serial] NAN follow-up to $peer ==="
        if ! result="$(android_shell_command "$serial" "wifi.nan.msg peer=$peer text=$text")"; then
            printf '%s\n' "$result" >"$out_dir/nan-message-command.txt"
            echo "ERROR: [$serial] NAN follow-up command failed." >&2
            failures=1
        else
            printf '%s\n' "$result" >"$out_dir/nan-message-command.txt"
        fi
        # WifiAware callbacks are asynchronous. Preserve both the command
        # acknowledgement and the bounded post-command history so `sent` is
        # never mistaken for ON_MESSAGE_SEND_SUCCEEDED or ESP receipt.
        sleep "${DMESH_NAN_FOLLOWUP_SETTLE_SEC:-3}"
        capture_android_evidence "$serial" "nan-message-after"
    done
    return "$failures"
}

arm_nan_followup() {
    local peer="${1:-${DMESH_NAN_PEER:-}}"
    local text="${2:-${DMESH_NAN_TEXT:-}}"
    if [ -z "$peer" ] || [ -z "$text" ]; then
        echo "Usage: $0 nan-arm <peer-id> <text>" >&2
        return 2
    fi
    local serial safe_serial out_dir failures=0
    local -a devices
    mapfile -t devices < <(require_android_devices)
    for serial in "${devices[@]}"; do
        safe_serial="${serial//[^A-Za-z0-9_.-]/_}"
        out_dir="${DMESH_ANDROID_EVIDENCE_DIR:-$SCRIPT_DIR/target/android-evidence/$ANDROID_EVIDENCE_STAMP}/$safe_serial"
        mkdir -p "$out_dir"
        echo "=== [$serial] arming immediate NAN follow-up for $peer ==="
        if ! android_shell_command "$serial" "wifi.nan.arm peer=$peer text=$text" \
            >"$out_dir/nan-arm-command.txt"; then
            echo "ERROR: [$serial] NAN follow-up arm failed." >&2
            failures=1
        fi
    done
    return "$failures"
}

configure_all_nan_roles() {
    local serial failures=0
    local -a devices
    mapfile -t devices < <(require_android_devices)
    for serial in "${devices[@]}"; do
        [ -n "$serial" ] || continue
        if ! configure_nan_role "$serial"; then
            echo "ERROR: [$serial] NAN role control timed out or failed." >&2
            capture_android_evidence "$serial" "role-control-failed"
            failures=1
            continue
        fi
        capture_android_evidence "$serial" "post-role"
    done
    return "$failures"
}

reset_all_nan_sessions() {
    local serial failures=0
    local -a devices
    mapfile -t devices < <(require_android_devices)
    for serial in "${devices[@]}"; do
        echo "=== [$serial] restarting NAN attachment and discovery sessions ==="
        if ! android_shell_command "$serial" "wifi.nan.stop" >/dev/null; then
            echo "ERROR: [$serial] NAN stop failed." >&2
            failures=1
            continue
        fi
        sleep "${DMESH_NAN_RESTART_SETTLE_SEC:-2}"
        if ! configure_nan_role "$serial"; then
            echo "ERROR: [$serial] NAN restart failed." >&2
            failures=1
            continue
        fi
        capture_android_evidence "$serial" "nan-reset"
    done
    return "$failures"
}

stop_all_nan_sessions() {
    local serial failures=0
    local -a devices
    mapfile -t devices < <(require_android_devices)
    for serial in "${devices[@]}"; do
        echo "=== [$serial] stopping NAN attachment and discovery sessions ==="
        if ! android_shell_command "$serial" "wifi.nan.stop" >/dev/null; then
            echo "ERROR: [$serial] NAN stop failed." >&2
            failures=1
            continue
        fi
        capture_android_evidence "$serial" "nan-stop"
    done
    return "$failures"
}

prepare_connected_devices() {
    local dmesh_apk="$SCRIPT_DIR/android/app-dmesh/build/outputs/apk/debug/app-dmesh-debug.apk"
    local web_apk="$SCRIPT_DIR/android/app-web/build/outputs/apk/debug/app-web-debug.apk"
    local chat_apk="$SCRIPT_DIR/android/app-chat/build/outputs/apk/debug/app-chat-debug.apk"
    local serial
    local -a devices
    mapfile -t devices < <(require_android_devices)
    for serial in "${devices[@]}"; do
        install_apps_on_device "$serial" "$dmesh_apk" "$web_apk" "$chat_apk"
        setup_device "$serial"
    done
}

run_tests() {
    build_apps debug
    echo "=== Running JVM tests ==="
    gradle testDebugUnitTest

    if [ "${DMESH_SKIP_ANDROID_TESTS:-0}" = "1" ]; then
        return
    fi

    prepare_connected_devices
    local serial
    while read -r serial; do
        echo "=== [$serial] Running connected Android tests ==="
        ANDROID_SERIAL="$serial" gradle connectedDebugAndroidTest
    done < <(require_android_devices)
}

run_native_health() {
    build_apps debug
    prepare_connected_devices
    local serial
    while read -r serial; do
        echo "=== [$serial] Running app-dmesh native JNI health test ==="
        ANDROID_SERIAL="$serial" gradle :android:app-dmesh:connectedDebugAndroidTest \
            -Pandroid.testInstrumentationRunnerArguments.class=com.github.costinm.lm.NativeInstrumentedTest
    done < <(require_android_devices)
}

run_ssh_forward_smoke() {
    build_apps debug
    prepare_connected_devices
    local serial index=0
    while read -r serial; do
        echo "=== [$serial] Checking adb forward to app-dmesh Rust SSH port ==="
        DMESH_ADB_SERIAL="$serial" DMESH_HOST_SSH_PORT="$((11522 + index))" \
            "$SCRIPT_DIR/scripts/test_emulator_ssh_forward.sh"
        index=$((index + 1))
    done < <(require_android_devices)
}

run_ssh_jsonl_smoke() {
    build_apps debug
    prepare_connected_devices
    local serial index=0
    while read -r serial; do
        echo "=== [$serial] Checking SSH JSONL MsgMux bridge ==="
        DMESH_ADB_SERIAL="$serial" DMESH_HOST_SSH_PORT="$((11522 + index))" \
            "$SCRIPT_DIR/scripts/test_emulator_ssh_jsonl.sh"
        index=$((index + 1))
    done < <(require_android_devices)
}

open_web_admin() {
    start_emulator
    adb shell am start \
        -n com.github.costinm.dmesh.web/.WebActivity \
        -a com.github.costinm.dmesh.web.OPEN \
        --es url http://127.0.0.1:18480/_m/adm
}

usage() {
    cat <<EOF
Usage: $0 [command] [debug|release]

Commands:
  deps                    Install Nix build dependencies into target/nix/profile.
  build [debug|release]   Build Rust UI and Android apps. Default.
  emulator                Start a headless emulator and wait for boot.
  install [debug|release] Build and install all apps on selected physical devices.
  install-all [debug|release] Remove old DMesh apps, install all apps, and set permissions.
  forwards                Create and record SSH/HTTP/lmesh host forwards for selected devices.
  nan-configure           Apply the selected NAN discovery role to each selected device.
  nan-evidence            Save per-device NAN counters, shell history, and dumpsys snapshots.
  nan-reset               Restart selected NAN sessions, apply their configured roles, and save evidence.
  nan-stop                Stop selected NAN sessions and save evidence; use nan-reset to restore.
  nan-message <peer> <text>
                          Send one NAN follow-up and save pre/post callback evidence.
  nan-arm <peer> <text>   Arm one follow-up for the peer's next discovery callback.
  test                    Build and run JVM tests plus connected Android tests.
  native-health           Run the app-dmesh JNI health test on selected devices.
  ssh-forward-smoke       Build/install app-dmesh and verify every selected adb SSH forward.
  ssh-jsonl-smoke         Verify JSONL MsgMux command stream over SSH.
  open-web-admin          Open app-web on the localhost ssh-mesh admin URL.

Environment:
  DMESH_NIX_PROFILE       Nix profile path. Default: target/nix/profile.
  DMESH_SSH_MESH_DIR      Local ssh-mesh checkout override. A sibling checkout is detected automatically.
  SSH_MESH_GIT_URL        Default ssh-mesh Git URL. Default: https://github.com/costinm/ssh-mesh.
  DMESH_ANDROID_ABIS      ABIs for libdmesh.so. Default: arm64-v8a.
  DMESH_UI_ANDROID_ABIS   ABIs for libdmeshui.so. Default: arm64-v8a.
  DMESH_UI_APPS           Apps receiving libdmeshui.so. Default: app-chat.
  DMESH_STRIP_ANDROID_LIBS=0 disables native library stripping. Default: 1 for release APKs, 0 for debug APKs.
  DMESH_AVD_NAME          AVD name for emulator startup. Default: Medium_Desktop_2.
  DMESH_ANDROID_DEVICES   physical (default: USB + Wi-Fi), usb, all, emulator, or comma-separated adb serials.
  DMESH_CONFIRM_UNINSTALL Set to 1 to allow install-all to remove existing app data.
  DMESH_SERVICE_START_TIMEOUT Foreground-service startup timeout in seconds. Default: 15.
  DMESH_ADB_INSTALL_TIMEOUT Per-APK adb install timeout in seconds. Default: 120.
  DMESH_ADB_COMMAND_TIMEOUT ADB shell control/evidence timeout in seconds. Default: 30.
  DMESH_NAN_ROLE          Default Android NAN role: both, sub-active, sub-passive, sub-passive-empty-ssi, pub-solicited, or pub-unsolicited.
  DMESH_NAN_ROLE_MAP      Per-serial role overrides: serial=role,serial=role.
  DMESH_NAN_PEER          Peer identity for nan-message when no positional peer is supplied.
  DMESH_NAN_TEXT          Follow-up text for nan-message when no positional text is supplied.
  DMESH_NAN_FOLLOWUP_SETTLE_SEC Callback evidence delay for nan-message. Default: 3.
  DMESH_NAN_HISTORY_DURATION_MS Bounded NAN history capture duration. Default: 5000.
  DMESH_NAN_RESTART_SETTLE_SEC NAN stop-to-restart delay. Default: 2.
  DMESH_ANDROID_EVIDENCE_DIR Evidence base directory. Default: target/android-evidence/<UTC timestamp>.
  DMESH_EMULATOR_TIMEOUT Boot timeout in seconds. Default: 240.
  DMESH_HOST_SSH_PORT     Host port for ssh-forward-smoke. Default: 11522.
  DMESH_DEVICE_SSH_PORT   Device port for app-dmesh Rust SSH. Default: 15022.
  DMESH_FORWARD_SSH_BASE  Base SSH host port for forwards. Default: 11522.
  DMESH_FORWARD_HTTP_BASE Base HTTP host port for forwards. Default: 18480.
  DMESH_FORWARD_LMESH_BASE Base lmesh UDS host port. Default: 11622.
  DMESH_SKIP_ANDROID_TESTS=1 skips connected Android tests.
EOF
}

main() {
    local cmd="${1:-build}"
    case "$cmd" in
        deps)
            install_nix_deps
            ;;
        build)
            detect_android_env
            build_apps "${2:-debug}"
            ;;
        debug|release)
            detect_android_env
            build_apps "$cmd"
            ;;
        emulator)
            detect_android_env
            start_emulator
            ;;
        install)
            detect_android_env
            install_apps "${2:-debug}"
            ;;
        install-all)
            detect_android_env
            install_all_apps "${2:-debug}"
            ;;
        forwards)
            detect_android_env
            create_host_forwards
            ;;
        nan-configure)
            detect_android_env
            configure_all_nan_roles
            ;;
        nan-evidence)
            detect_android_env
            capture_all_android_evidence
            ;;
        nan-reset)
            detect_android_env
            reset_all_nan_sessions
            ;;
        nan-stop)
            detect_android_env
            stop_all_nan_sessions
            ;;
        nan-message)
            detect_android_env
            send_nan_message "${2:-}" "${3:-}"
            ;;
        nan-arm)
            detect_android_env
            arm_nan_followup "${2:-}" "${3:-}"
            ;;
        test)
            detect_android_env
            run_tests
            ;;
        native-health)
            detect_android_env
            run_native_health
            ;;
        ssh-forward-smoke)
            detect_android_env
            run_ssh_forward_smoke
            ;;
        ssh-jsonl-smoke)
            detect_android_env
            run_ssh_jsonl_smoke
            ;;
        open-web-admin)
            detect_android_env
            open_web_admin
            ;;
        help|-h|--help)
            usage
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
