extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {

    // Tell cargo to tell rustc to link the netfilter_queue shared library
    println!("cargo:rustc-link-lib=netfilter_queue");

    let bindings = bindgen::Builder::default()
        .header("src/generation/wrapper.h")
        // White listings became necessary as I needed to included <stdint> in wrapper.h to
        // define the default integer types like uint32_t. I think I miss something but I
        // couldn't grab it.
        .whitelisted_type("(nfq|NFQ)_.*")
        .whitelisted_function("(nfq|NFQ)_.*")
        .whitelisted_var("(nfq|NFQ)_.*")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}