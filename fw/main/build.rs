mod iram_link_test;

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let partition = std::path::Path::new("../boot/partitions.csv");
    std::fs::copy(partition, format!("{out_dir}/partitions.csv"))
        .expect("copy Main partition table");
    println!("cargo:rerun-if-changed={}", partition.display());
    println!("cargo:rerun-if-changed=sdkconfig.defaults");
    println!("cargo:rerun-if-changed=sdkconfig.esp32s3.defaults");
    println!("cargo:rerun-if-changed=sdkconfig.esp32c6.defaults");
    println!("cargo:rerun-if-changed=../ble/native/dmesh_nimble/dmesh_nimble.c");
    println!("cargo:rerun-if-changed=../ble/native/dmesh_nimble/include/dmesh_nimble.h");
    println!("cargo:rerun-if-changed=../ble/native/dmesh_nimble/CMakeLists.txt");
    println!("cargo:rerun-if-changed=../modules/native/dmesh_module_loader/dmesh_module_loader.c");
    println!("cargo:rerun-if-changed=../modules/native/dmesh_module_loader/dmesh_hw_host.c");
    println!(
        "cargo:rerun-if-changed=../modules/native/dmesh_module_loader/dmesh_module_weak_platform.c"
    );
    println!("cargo:rerun-if-changed=../modules/native/dmesh_module_loader/CMakeLists.txt");
    println!("cargo:rerun-if-changed=native/dmesh_uart_log/CMakeLists.txt");
    // esp-wifi-loader component (library mode): rebuild the SDK when it changes.
    for f in ["CMakeLists.txt", "Kconfig", "include/esp_wifi_loader.h",
              "src/serve.c", "src/upload.c", "src/state.c", "src/state_core.c",
              "src/crypto_psa.c", "src/rtc.c", "src/internal.h"] {
        println!("cargo:rerun-if-changed=../esp-wifi-loader/components/esp_wifi_loader/{f}");
    }
    println!("cargo:rerun-if-changed=native/dmesh_uart_log/dmesh_uart_log.c");
    println!("cargo:rerun-if-env-changed=DMESH_QUIC_IRAM_TEST");
    println!("cargo:rerun-if-changed=iram_link_test.rs");
    if std::env::var("DMESH_QUIC_IRAM_TEST").as_deref() == Ok("1") {
        assert_eq!(std::env::var("TARGET").as_deref(), Ok("riscv32imac-esp-espidf"),
            "the private QUIC IRAM experiment is for the RISC-V canary only");
        if let Some(cfg) = embuild::espidf::sysenv::cfg_args() { cfg.output(); }
        let mut args = embuild::espidf::sysenv::link_args().expect("SDK linker arguments");
        let source = args.args.iter().filter_map(|arg| arg.strip_prefix("-L"))
            .map(|directory| std::path::Path::new(directory).join("sections.ld"))
            .find(|path| path.is_file()).expect("SDK sections.ld");
        println!("cargo:rerun-if-changed={}", source.display());
        let script = std::fs::read_to_string(&source).expect("read SDK sections.ld");
        // Use the SDK's existing IRAM output section and heap accounting.
        // Never add a separate section which its DRAM mirror/heap cannot see.
        let script = iram_link_test::place_quic_hot_functions(&script)
            .expect("supported SDK IRAM layout");
        let destination = std::path::Path::new(&out_dir).join("quic-iram-test.ld");
        std::fs::write(&destination, script).expect("write private linker experiment");
        let selected = args.args.iter_mut().find(|arg| arg.as_str() == "sections.ld")
            .expect("SDK section script argument");
        *selected = destination.to_string_lossy().into_owned();
        args.output();
    } else {
        embuild::espidf::sysenv::output();
    }
}
