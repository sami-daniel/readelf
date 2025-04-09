use bindgen::builder;

pub fn init() {
    if let Ok(binding) = builder().header("/usr/include/elf.h").allowlist_type("Elf64_Ehdr").generate() {
        _ = binding.write_to_file("./src/elf.rs")
    } else {
        panic!("Failed to write")
    }
}