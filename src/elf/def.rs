/* automatically generated by rust-bindgen 0.71.1 */
#[allow(non_camel_case_types)]
pub mod elf64fields {
    pub type Elf64_Half = u16;
    pub type Elf64_Word = u32;
    pub type Elf64_Addr = u64;
    pub type Elf64_Off = u64;
}

#[allow(non_camel_case_types)]
pub mod elf64strc {
    use super::elf64fields::*;

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct Elf64_Ehdr {
        pub e_ident: [::std::os::raw::c_uchar; 16usize],
        pub e_type: Elf64_Half,
        pub e_machine: Elf64_Half,
        pub e_version: Elf64_Word,
        pub e_entry: Elf64_Addr,
        pub e_phoff: Elf64_Off,
        pub e_shoff: Elf64_Off,
        pub e_flags: Elf64_Word,
        pub e_ehsize: Elf64_Half,
        pub e_phentsize: Elf64_Half,
        pub e_phnum: Elf64_Half,
        pub e_shentsize: Elf64_Half,
        pub e_shnum: Elf64_Half,
        pub e_shstrndx: Elf64_Half,
    }
    #[allow(clippy::unnecessary_operation, clippy::identity_op)]
    const _: () = {
        ["Size of Elf64_Ehdr"][::std::mem::size_of::<Elf64_Ehdr>() - 64usize];
        ["Alignment of Elf64_Ehdr"][::std::mem::align_of::<Elf64_Ehdr>() - 8usize];
        ["Offset of field: Elf64_Ehdr::e_ident"]
            [::std::mem::offset_of!(Elf64_Ehdr, e_ident) - 0usize];
        ["Offset of field: Elf64_Ehdr::e_type"]
            [::std::mem::offset_of!(Elf64_Ehdr, e_type) - 16usize];
        ["Offset of field: Elf64_Ehdr::e_machine"]
            [::std::mem::offset_of!(Elf64_Ehdr, e_machine) - 18usize];
        ["Offset of field: Elf64_Ehdr::e_version"]
            [::std::mem::offset_of!(Elf64_Ehdr, e_version) - 20usize];
        ["Offset of field: Elf64_Ehdr::e_entry"]
            [::std::mem::offset_of!(Elf64_Ehdr, e_entry) - 24usize];
        ["Offset of field: Elf64_Ehdr::e_phoff"]
            [::std::mem::offset_of!(Elf64_Ehdr, e_phoff) - 32usize];
        ["Offset of field: Elf64_Ehdr::e_shoff"]
            [::std::mem::offset_of!(Elf64_Ehdr, e_shoff) - 40usize];
        ["Offset of field: Elf64_Ehdr::e_flags"]
            [::std::mem::offset_of!(Elf64_Ehdr, e_flags) - 48usize];
        ["Offset of field: Elf64_Ehdr::e_ehsize"]
            [::std::mem::offset_of!(Elf64_Ehdr, e_ehsize) - 52usize];
        ["Offset of field: Elf64_Ehdr::e_phentsize"]
            [::std::mem::offset_of!(Elf64_Ehdr, e_phentsize) - 54usize];
        ["Offset of field: Elf64_Ehdr::e_phnum"]
            [::std::mem::offset_of!(Elf64_Ehdr, e_phnum) - 56usize];
        ["Offset of field: Elf64_Ehdr::e_shentsize"]
            [::std::mem::offset_of!(Elf64_Ehdr, e_shentsize) - 58usize];
        ["Offset of field: Elf64_Ehdr::e_shnum"]
            [::std::mem::offset_of!(Elf64_Ehdr, e_shnum) - 60usize];
        ["Offset of field: Elf64_Ehdr::e_shstrndx"]
            [::std::mem::offset_of!(Elf64_Ehdr, e_shstrndx) - 62usize];
    };
}
