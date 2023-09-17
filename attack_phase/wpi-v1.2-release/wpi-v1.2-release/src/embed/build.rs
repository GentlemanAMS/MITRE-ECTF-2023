//! This build script copies the `memory.x` file from the crate root into
//! a directory where the linker can always find it at build time.
//! For many projects this is optional, as the linker always searches the
//! project root directory -- wherever `Cargo.toml` is. However, if you
//! are using a workspace or have a more complicated build setup, this
//! build script becomes required. Additionally, by requesting that
//! Cargo re-run the build script whenever `memory.x` is changed,
//! updating `memory.x` ensures a rebuild of the application with the
//! new memory settings.

extern crate bindgen;

use std::fs::{read_dir, write};

fn main() {
    // Unfortunately, afaik there is no better way to inform build.rs if we are building
    // the application, or just tests. There's an RFC in the rust repo, but no progress yet.
    if std::env::var("TARGET").unwrap() == "thumbv7em-none-eabihf" {
        println!("cargo:warning=Linking to tivaware...");
        println!("cargo:rustc-link-arg=-Tmemory.x");

        // Tell cargo to look for shared libraries in the specified directory
        println!("cargo:rustc-link-search=shared/lib/tivaware/driverlib/gcc");

        // Tell cargo to invalidate the built crate whenever the wrapper changes
        println!("cargo:rerun-if-changed=shared/header/bindings.h");

        let bindings = bindgen::Builder::default()
            .header("./shared/header/bindings.h")
            .use_core()
            .blacklist_type("*")
            .layout_tests(false)
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .expect("Failed to generate c bindings!");

        let mut cleaned = bindings
            .to_string()
            .replace("::std::os::raw::c_uchar", "u8");

        cleaned.insert_str(
            0,
            [
                "#![allow(dead_code)]",
                "#![allow(unused)]",
                "#![allow(non_upper_case_globals)]",
                "#![allow(non_camel_case_types)]",
                "#![allow(non_snake_case)]",
                "",
            ]
            .join("\n")
            .as_str(),
        );

        write("./src/tivaware.rs", cleaned).expect("Failed to write tivaware bindings to file!");

        cc::Build::new()
            .target("thumbv7em-none-eabihf")
            .compiler("arm-none-eabi-gcc")
            .include("./shared/lib/tivaware")
            .flag("-w")
            .define("gcc", None)
            .files({
                read_dir("./shared/lib/tivaware/driverlib")
                    .expect("Could not open Tivaware directory!")
                    .map(|f| f.expect("Could not get pathname!").path())
                    .filter(|f| match f.extension() {
                        Some(e) => e == "c",
                        _ => false,
                    })
            })
            .file("./shared/lib/tivaware/startup_gcc.c")
            .compile("tivaware");
    }
}
