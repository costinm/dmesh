#!/bin/bash
# Build, install, and test the DMesh Android apps.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DMESH_NIX_PROFILE="${DMESH_NIX_PROFILE:-$SCRIPT_DIR/target/nix/profile}"

export CARGO_HOME="${CARGO_HOME:-$SCRIPT_DIR/target/.cargo}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$SCRIPT_DIR/target/.gradle}"
mkdir -p "$CARGO_HOME" "$GRADLE_USER_HOME"

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
    local flake_src
    flake_src="$(mktemp -d "${TMPDIR:-/tmp}/dmesh-flake.XXXXXX")"
    trap 'rm -rf "$flake_src"' RETURN
    cp "$SCRIPT_DIR/flake.nix" "$flake_src/flake.nix"

    mkdir -p "$(dirname "$NIX_PROFILE")"
    "$(nix_cmd)" profile install \
        --profile "$NIX_PROFILE" \
        "path:$flake_src#deps"
    echo "Installed DMesh build dependencies in $NIX_PROFILE"
    echo "Load with: . target/nix/profile/bin/dmesh-setenv"

    rustup target add \
            aarch64-linux-android \
            x86_64-linux-android 
          
}

detect_android_env() {
    load_nix_profile_env

    if [ -z "${ANDROID_HOME:-}" ]; then
        if [ -d "$HOME/Android/Sdk" ]; then
            export ANDROID_HOME="$HOME/Android/Sdk"
        else
            echo "ERROR: ANDROID_HOME not set and ~/Android/Sdk not found."
            exit 1
        fi
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

profile_dir() {
    local build_type="${1:-debug}"
    if [ "$build_type" = "release" ]; then
        echo "release"
    else
        echo "debug"
    fi
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
    local build_type="$3"
    local abi="$4"
    local triple
    triple="$(target_triple "$abi")"

    local so_path="$SCRIPT_DIR/target/$triple/$(profile_dir "$build_type")/lib$lib_name.so"
    if [ ! -f "$so_path" ]; then
        echo "ERROR: Built library not found at $so_path"
        exit 1
    fi

    if [ "${DMESH_STRIP_ANDROID_LIBS:-1}" = "1" ]; then
        local strip_bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
        if [ ! -x "$strip_bin" ]; then
            echo "ERROR: Android llvm-strip not found at $strip_bin"
            exit 1
        fi
        "$strip_bin" --strip-unneeded "$so_path"
    fi

    local app
    for app in ${DMESH_JNILIB_APPS:-app-dmesh}; do
        local jnilib_dir="$SCRIPT_DIR/android/$app/src/main/jniLibs/$abi"
        mkdir -p "$jnilib_dir"
        cp "$so_path" "$jnilib_dir/lib$lib_name.so"
        echo "Copied $crate_name to: $jnilib_dir/lib$lib_name.so"
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
    local build_type="$3"
    local abi_list="$4"
    local cargo_args=(build -p "$package" --lib)

    if [ "$build_type" = "release" ]; then
        cargo_args+=(--release)
    elif [ "$build_type" != "debug" ]; then
        echo "Usage: $0 build [debug|release]"
        exit 1
    fi

    clean_android_lib_outputs "$lib_name"
    for abi in $abi_list; do
        echo "=== Building $package for $abi ($build_type) ==="
        cargo ndk -t "$abi" -P 28 "${cargo_args[@]}"
        copy_android_lib "$package" "$lib_name" "$build_type" "$abi"
    done
}

build_rust_native() {
    local build_type="${1:-debug}"

    echo "Using NDK: $ANDROID_NDK_HOME"
    echo "Using SDK: $ANDROID_HOME"
    echo ""
    clean_app_dmesh_dmeshui
    build_rust_package dmesh dmesh "$build_type" "${DMESH_ANDROID_ABIS:-x86_64}"
    copy_dmeshui_android_lib "$build_type" "${DMESH_UI_ANDROID_ABIS:-x86_64}"
    clean_app_dmesh_dmeshui
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

android_device_serial() {
    adb devices | awk 'NR > 1 && $2 == "device" { print $1; exit }'
}

start_emulator() {
    local avd_name="${DMESH_AVD_NAME:-${ANDROID_AVD_NAME:-Medium_Desktop_2}}"
    local serial
    serial="$(android_device_serial || true)"
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

    build_apps "$build_type"
    start_emulator

    echo "=== Installing app-dmesh ==="
    adb install -r "$dmesh_apk"
    echo "=== Installing app-web ==="
    adb install -r "$web_apk"
    echo "=== Installing app-chat ==="
    adb install -r "$chat_apk"
}

grant_app_permissions() {
    local pkg="$1"

    echo "=== Granting runtime permissions for $pkg where possible ==="
    adb shell pm grant "$pkg" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
    adb shell pm grant "$pkg" android.permission.ACCESS_FINE_LOCATION >/dev/null 2>&1 || true
    adb shell pm grant "$pkg" android.permission.ACCESS_COARSE_LOCATION >/dev/null 2>&1 || true
    adb shell pm grant "$pkg" android.permission.NEARBY_WIFI_DEVICES >/dev/null 2>&1 || true
    adb shell pm grant "$pkg" android.permission.BLUETOOTH_CONNECT >/dev/null 2>&1 || true

    # ACTIVATE_VPN is an app-op on many emulator images rather than a runtime
    # permission. Ignore failures so the instrumentation can report unsupported
    # images with the actual VpnService.prepare state.
    adb shell appops set "$pkg" ACTIVATE_VPN allow >/dev/null 2>&1 || true
    adb shell cmd appops set "$pkg" ACTIVATE_VPN allow >/dev/null 2>&1 || true
}

prepare_connected_device() {
    local dmesh_apk="$SCRIPT_DIR/android/app-dmesh/build/outputs/apk/debug/app-dmesh-debug.apk"
    local chat_apk="$SCRIPT_DIR/android/app-chat/build/outputs/apk/debug/app-chat-debug.apk"
    start_emulator
    echo "=== Installing app-dmesh for permission setup ==="
    adb install -r "$dmesh_apk" >/dev/null
    if [ -f "$chat_apk" ]; then
        echo "=== Installing app-chat for direct binder smoke ==="
        adb install -r "$chat_apk" >/dev/null
    fi
    grant_app_permissions "$APP_DMESH_PKG"
}

run_tests() {
    build_apps debug
    echo "=== Running JVM tests ==="
    gradle testDebugUnitTest

    if [ "${DMESH_SKIP_ANDROID_TESTS:-0}" = "1" ]; then
        return
    fi

    prepare_connected_device
    echo "=== Running connected Android tests ==="
    gradle connectedDebugAndroidTest
}

run_native_health() {
    build_apps debug
    prepare_connected_device
    echo "=== Running app-dmesh native JNI health test ==="
    gradle :android:app-dmesh:connectedDebugAndroidTest \
        -Pandroid.testInstrumentationRunnerArguments.class=com.github.costinm.lm.NativeInstrumentedTest
}

run_ssh_forward_smoke() {
    build_apps debug
    prepare_connected_device
    echo "=== Checking adb forward to app-dmesh Rust SSH port ==="
    "$SCRIPT_DIR/scripts/test_emulator_ssh_forward.sh"
}

run_ssh_jsonl_smoke() {
    build_apps debug
    prepare_connected_device
    echo "=== Checking SSH JSONL MsgMux bridge ==="
    "$SCRIPT_DIR/scripts/test_emulator_ssh_jsonl.sh"
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
  install [debug|release] Build, start emulator, and install app-dmesh/app-web.
  test                    Build and run JVM tests plus connected Android tests.
  native-health           Run the app-dmesh JNI health test on a headless emulator.
  ssh-forward-smoke       Build/install app-dmesh and verify adb SSH port forwarding.
  ssh-jsonl-smoke         Verify JSONL MsgMux command stream over SSH.
  open-web-admin          Open app-web on the localhost ssh-mesh admin URL.

Environment:
  DMESH_NIX_PROFILE       Nix profile path. Default: target/nix/profile.
  DMESH_ANDROID_ABIS      ABIs for libdmesh.so. Default: x86_64.
  DMESH_UI_ANDROID_ABIS   ABIs for libdmeshui.so. Default: x86_64.
  DMESH_UI_APPS           Apps receiving libdmeshui.so. Default: app-chat.
  DMESH_STRIP_ANDROID_LIBS=0 disables native library stripping. Default: 1.
  DMESH_AVD_NAME          AVD name for emulator startup. Default: Medium_Desktop_2.
  DMESH_EMULATOR_TIMEOUT Boot timeout in seconds. Default: 240.
  DMESH_HOST_SSH_PORT     Host port for ssh-forward-smoke. Default: 11522.
  DMESH_DEVICE_SSH_PORT   Device port for app-dmesh Rust SSH. Default: 15022.
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
