use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};

fn main() {
    // Get the out directory.
    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());

    // Add out directory to the linker search path.
    println!("cargo:rustc-link-search={}", out.display());

    // Call "make clean" for rand_uninit_memory.
    Command::new("make")
        .arg("-C")
        .arg("../rand_uninit_memory")
        .arg("clean")
        .status()
        .unwrap();

    // Call "make debug" or "make" for rand_uninit_memory depending on profile.
    if env::var_os("PROFILE").unwrap() == "debug" {
        Command::new("make")
            .arg("-C")
            .arg("../rand_uninit_memory")
            .arg("debug")
            .status()
            .unwrap();
    } else {
        Command::new("make")
            .arg("-C")
            .arg("../rand_uninit_memory")
            .status()
            .unwrap();
    }

    // Put the rand_uninit_memory library somewhere the linker can find it.
    File::create(out.join("librand_uninit_memory.a"))
        .unwrap()
        .write_all(&fs::read("../rand_uninit_memory/librand_uninit_memory.a").unwrap())
        .unwrap();

    // Link to the rand_uninit_memory library.
    println!("cargo:rustc-link-lib=rand_uninit_memory");

    // Only re-run the build script when rand_uninit_memory or profile is changed.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../rand_uninit_memory");
    println!("cargo:rerun-if-env-changed=PROFILE");
}
