fn main() {
    println!("cargo:rerun-if-changed=sdkconfig.defaults");
    println!("cargo:rerun-if-changed=partitions_e5.csv");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::copy("partitions_e5.csv", format!("{out_dir}/partitions_e5.csv"))
        .expect("copy E5 partition table");
    embuild::espidf::sysenv::output();
}
