fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let partition = std::path::Path::new("../boot/partitions.csv");
    std::fs::copy(partition, format!("{out_dir}/partitions.csv"))
        .expect("copy Recovery partition table");
    println!("cargo:rerun-if-changed={}", partition.display());
    println!("cargo:rerun-if-changed=sdkconfig.defaults");
    embuild::espidf::sysenv::output();
}
