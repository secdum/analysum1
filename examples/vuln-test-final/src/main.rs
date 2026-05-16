// Intentionally vulnerable Rust code for SecDojo scanner testing
// DO NOT USE IN PRODUCTION

use std::slice;

// cargo-geiger flags this: raw pointer dereference
fn unsafe_pointer_dereference() {
    let x: i32 = 42;
    let raw = &x as *const i32;
    unsafe {
        println!("Raw pointer value: {}", *raw);
    }
}

// cargo-geiger flags this: unsafe slice from raw parts
fn unsafe_slice_creation() {
    let data: Vec<u8> = vec![1, 2, 3, 4, 5];
    let ptr = data.as_ptr();
    let len = data.len();
    unsafe {
        let slice = slice::from_raw_parts(ptr, len);
        println!("Unsafe slice: {:?}", slice);
    }
}

// Uses atty crate (RUSTSEC-2021-0145)
fn check_terminal() {
    if atty::is(atty::Stream::Stdout) {
        println!("Running in a terminal");
    }
}

// Uses yaml-rust crate (RUSTSEC-2021-0127)
fn parse_yaml() {
    let yaml_str = "key: value\nlist:\n  - item1\n  - item2";
    let docs = yaml_rust::YamlLoader::load_from_str(yaml_str).unwrap();
    println!("Parsed YAML: {:?}", docs[0]);
}

fn main() {
    println!("=== Vulnerable Rust Test Program ===");
    unsafe_pointer_dereference();
    unsafe_slice_creation();
    check_terminal();
    parse_yaml();
}
