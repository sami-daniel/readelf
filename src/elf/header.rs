use std::error::Error;

use crate::utils::parser::Parseable;
use crate::elf::def::Elf64_Ehdr;

impl Parseable for Elf64_Ehdr {
    fn parse(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        // first step is verify if is really an 64 bit elf file.
        // by default for 64 bits binary elf files, we have
        // the minimum size of 52 bytes in the bin file. This 52
        // bytes are provenient from the elf header struct, so we can
        // use it as a ruge and ugly validation for the elf file
        if bytes.len() < 52 {
            return Err(ParseErrors::NonELFFileError("The ELF file should contain 52 bytes minimum").into());
        }

        let eident = &bytes[0..15];
        let machine = 
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParseErrors<'a> {
    #[error("The ELF file cannot be identified as a ELF file. Reason: `{0}`")]
    NonELFFileError(&'a str),
    #[error("The ELF file cannot be identified as a 64 bit ELF file.")]
    Non64BitELF,
    #[error("The ELF file version cannot be setted to other value different of 1. See https://refspecs.linuxfoundation.org/ for more info")]
    InvalidELFVersion
}
