extern crate anyhow;
extern crate cbindgen;

#[cfg(feature = "sqlite")]
fn main() -> anyhow::Result<()> {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS")?;
    if target_os != "macos" && target_os != "windows" && target_os != "linux" {
        println!("cargo:rustc-link-lib=static=sqlite3");
        if target_os.as_str() == "android" {
            println!("cargo:rustc-link-search=native=./sqlite3/obj/local/arm64-v8a");
        } else if target_os == "ios" {
            println!("cargo:rustc-link-search=native=./sqlite3/obj/local/arm64-ios");
        }

        cbindgen::Builder::new()
            .with_language(cbindgen::Language::C)
            .with_src("./src/ffi.rs")
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file("target/include/ssi_man.h");
    }
    Ok(())
}

#[cfg(not(feature = "sqlite"))]
fn main() {
    cbindgen::Builder::new()
        .with_language(cbindgen::Language::C)
        .with_src("./src/ffi.rs")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("target/include/ssi_man.h");
}
