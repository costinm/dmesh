fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    for partition_file in [
        "partitions_4mb_large_app.csv",
        "partitions_8mb_large_app_store.csv",
        "partitions_16mb_large_app_store.csv",
    ] {
        std::fs::copy(partition_file, format!("{out_dir}/{partition_file}"))
            .unwrap_or_else(|err| panic!("copy {partition_file}: {err}"));
        println!("cargo:rerun-if-changed={partition_file}");
    }
    println!("cargo:rerun-if-changed=native/dmesh_nimble/dmesh_nimble.c");
    println!("cargo:rerun-if-changed=native/dmesh_nimble/include/dmesh_nimble.h");
    println!("cargo:rerun-if-changed=native/dmesh_nimble/CMakeLists.txt");
    println!("cargo:rerun-if-changed=native/dmesh_hw/dmesh_hw.c");
    println!("cargo:rerun-if-changed=native/dmesh_hw/include/dmesh_hw.h");
    println!("cargo:rerun-if-changed=native/dmesh_hw/CMakeLists.txt");
    println!("cargo:rerun-if-changed=native/dmesh_pm/dmesh_pm.c");
    println!("cargo:rerun-if-changed=native/dmesh_pm/include/dmesh_pm.h");
    println!("cargo:rerun-if-changed=native/dmesh_pm/CMakeLists.txt");
    embuild::espidf::sysenv::output();
}
