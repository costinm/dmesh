fn main() {
    println!("cargo:rustc-check-cfg=cfg(esp_idf_version_at_least_6_0_0)");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let partition_file = std::path::Path::new("../../boot/partitions.csv");
    std::fs::copy(partition_file, format!("{out_dir}/partitions.csv"))
        .unwrap_or_else(|err| panic!("copy {}: {err}", partition_file.display()));
    println!("cargo:rerun-if-changed={}", partition_file.display());
    println!("cargo:rerun-if-changed=native/dmesh_nimble/dmesh_nimble.c");
    println!("cargo:rerun-if-changed=native/dmesh_nimble/include/dmesh_nimble.h");
    println!("cargo:rerun-if-changed=native/dmesh_nimble/CMakeLists.txt");
    println!("cargo:rerun-if-changed=native/dmesh_hw/dmesh_hw.c");
    println!("cargo:rerun-if-changed=native/dmesh_hw/include/dmesh_hw.h");
    println!("cargo:rerun-if-changed=native/dmesh_hw/CMakeLists.txt");
    println!("cargo:rerun-if-changed=native/dmesh_pm/dmesh_pm.c");
    println!("cargo:rerun-if-changed=native/dmesh_pm/include/dmesh_pm.h");
    println!("cargo:rerun-if-changed=native/dmesh_pm/CMakeLists.txt");
    println!("cargo:rerun-if-changed=native/dmesh_wifi_filter/dmesh_wifi_filter.c");
    println!("cargo:rerun-if-changed=native/dmesh_wifi_filter/include/dmesh_wifi_filter.h");
    println!("cargo:rerun-if-changed=native/dmesh_wifi_filter/CMakeLists.txt");
    println!("cargo:rerun-if-changed=native/dmesh_boot_health/dmesh_boot_health.c");
    println!("cargo:rerun-if-changed=native/dmesh_boot_health/CMakeLists.txt");
    println!("cargo:rerun-if-changed=native/dmesh_module_loader/dmesh_module_loader.c");
    println!("cargo:rerun-if-changed=native/dmesh_module_loader/include/dmesh_module_loader.h");
    println!("cargo:rerun-if-changed=native/dmesh_module_loader/CMakeLists.txt");
    println!("cargo:rerun-if-changed=../../mod_hello/include/dmesh_module_abi.h");
    println!("cargo:rerun-if-changed=../../modules/include/dmesh_hw_abi.h");
    println!("cargo:rerun-if-changed=../../mod_lora/include/dmesh_lora_abi.h");
    println!("cargo:rerun-if-changed=native/dmesh_boot_health/boot_health_rtc.h");
    embuild::espidf::sysenv::output();
}
