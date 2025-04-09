use bindgen::builder;

pub fn init() {
    let binding = builder().header("/usr/include/elf.h")
            .allowlist_item("EV_CURRENT").allowlist_type("Elf64_Ehdr")
            .generate();
    
    if let Ok(binding) = binding {
        _ = binding.write_to_file("./src/elf/def.rs")
    } else {
        panic!("Failed to write")
    }
}