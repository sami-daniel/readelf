mod config;
mod elf;
mod utils;

fn main() {
    // this configs the bindgen lib to enable the 
    // (re)use of the structs defined in /usr/include/elf.h
    config::init();
}