use crate::elf::def::elf64strc::Elf64_Ehdr;
use crate::elf::validator::arch::arch64::{Elf64BitValidator, elf64bitvalidationerrors::*};
use crate::utils::parser::Parseable;
use std::error::Error;

impl Parseable for Elf64_Ehdr {
    fn parse(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        // offset: 0x0 -> 0x52

        // the objective of this method is to validate AND
        // parse the bytes in an Elf64_Ehdr struct

        // first step is verify if is really an 64 bit elf file.
        // by default for 64 bits binary elf files, we have
        // the minimum size of 52 bytes in the bin file. This 52
        // bytes are provenient from the elf header struct, so we can
        // use it as a ruge and ugly validation for the elf file
        if bytes.len() < 52 {
            return Err(Elf64BitEIdentValidationErrors::NonELFFileError.into());
        }

        // the first part of the elf header are a 16 bytes array that is called
        // e_ident. It contains important data about the bin file, like endiannes,
        // important offsets, if is 32 bit or not etc.
        let mut elf64bitvalidator = Elf64BitValidator::new(bytes);

        _ = elf64bitvalidator.validate_e_ident();

        // now, we run out from elf e_ident, we can validate the others
        // field from elf file. The next bytes, uses other types than char,
        // that in this case, is definned to 1 byte each char (ASCII). But
        // usually, the other parts cannot be defined with char, cause it
        // uses more than one byte per field.

        _ = elf64bitvalidator.validate_e_type();

        // We have some types (witch are only symbols to raw unsigned values)
        // like Elf64_Half type, is u16 (in 64-bit object), and occupes the next
        // 2 bytes of mem

        // let e_type = &bytes[16..0];

        todo!()
    }
}
