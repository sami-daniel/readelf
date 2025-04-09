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
            return Err(ParseErrors::NonELFFileError("The ELF file should contain 52 bytes minimum").into());
        }

        let eident = &bytes[0..15];
        
        // the first part of the elf header are a 16 bytes array that is called
        // e_ident. It contains important data about the bin file, like endiannes,
        // important offsets, if is 32 bit or not etc.

        // First part of the e_ident array is 4 bytes that should be always equal
        // to: 7f, 45, 4c, 46, respectively. They are called 'magic number' for some
        // reason that idk.

        let b1 = eident.get(0);
        let b2 = eident.get(1);
        let b3  = eident.get(2);
        let b4 = eident.get(3);

        if let (Some(&hex_mv1), Some(&hex_mv2), Some(&hex_mv3), Some(&hex_mv4)) = (b1, b2, b3, b4) {
            if hex_mv1 != 0x7f && hex_mv2 != 0x45 && hex_mv3 != 0x4c && hex_mv4 != 0x46 {
                return Err(ParseErrors::NonELFFileError("The first 4 bytes could not be identified as 7f, 45, 4c, 46").into());
            }
        }

        // the next byte identifies the file class, if is 32 bit or 64 bit
        // file or an Invalid Class (idk why this exists instead of simply 
        // throw a compiler exception or something like this)

        if eident[4] != 2 {
            // this means that is non 64-bit object, so its invalid
            return Err(ParseErrors::Non64BitELF(eident[4]).into());
        }
        
        // the next byte identifies the endiannes enconding of most of the
        // data present in this file.
        if eident[5] != 1 && eident[5] != 2 {
            return Err(ParseErrors::InvalidEndianness(eident[5]).into());
        }

        // the next byte identify if the ELF file is version number
        // witch is 1 (one) since 1995, so we dont have to think that
        // will be changed now (right?)
        
        if eident[6] != 1 {
            return Err(ParseErrors::InvalidELFVersion(eident[6]).into())
        }

        // here, would the validation of the EI_OSABI and EI_ABIVERSION
        // witch describes respectivily, the operational system ABI and
        // it version, but normally, we just accept them

        
        
        return Ok();
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParseErrors<'a> {
    #[error("The ELF file cannot be identified as a ELF file. Reason: `{0}`")]
    NonELFFileError(&'a str),
    #[error("The ELF file describes a non 64-bit value (`{0}`)")]
    Non64BitELF(u8),
    #[error("The ELF file version cannot be setted to other value different of 1. See https://refspecs.linuxfoundation.org/ for more info")]
    InvalidELFVersion(u8),
    #[error("The ELF file header describes an invalid endiannes value (`{0}`)")]
    InvalidEndianness(u8)
}
