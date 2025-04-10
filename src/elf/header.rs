use crate::elf::validator::elf64bitvalidator::{self, elf64bitvalidationerrors};
use std::error::Error;

use crate::utils::parser::Parseable;
use crate::elf::def::Elf64_Ehdr;

impl Parseable for Elf64_Ehdr {
    fn parse(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        // the objective of this method is to validate AND
        // parse the bytes in an Elf64_Ehdr struct

        // first step is verify if is really an 64 bit elf file.
        // by default for 64 bits binary elf files, we have
        // the minimum size of 52 bytes in the bin file. This 52
        // bytes are provenient from the elf header struct, so we can
        // use it as a ruge and ugly validation for the elf file
        if bytes.len() < 52 {
            return Err(elf64bitvalidationerrors::Elf64BitEIdentValidationErrors::NonELFFileError.into());
        }

        // the first part of the elf header are a 16 bytes array that is called
        // e_ident. It contains important data about the bin file, like endiannes,
        // important offsets, if is 32 bit or not etc.
        
        let e_ident = &bytes[0..15];
        _ = elf64bitvalidator::validate_eident(e_ident);
        
        // now, we run out from elf e_ident, we can validate the others
        // field from elf file. The next bytes, uses other types than char,
        // that in this case, is definned to 1 byte each char (ASCII). But 
        // usually, the other parts cannot be defined with char, cause it 
        // uses more than one byte per field.
        
        // We have some types (witch are only symbols to raw unsigned values)
        // like Elf64_Half type, is u16 (in 64-bit object), and occupes the next
        // 2 bytes of mem

        // let e_type = &bytes[16..0];
        
        todo!()
    }
}
