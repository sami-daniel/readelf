use crate::utils::parser::Parseable;
use crate::elf::def::Elf64_Ehdr;

const INVALID_ELF_MSG: &str = "Invalid ELF file passed"; 
const INVALID_ELF_IDENT_CLASS_MSG: &str = "The ELF class is invalid";

impl Parseable for Elf64_Ehdr {
    fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        // first step is verify if is really an 64 bit elf file.
        // by default for 64 bits binary elf files, we have
        // the minimum size of 52 bytes in the bin file. This 52
        // bytes are provenient from the elf header struct, so we can
        // use it as a ruge and ugly validation for the elf file
        if bytes.len() < 52 {
            return Err("The ELF file should contain a minimum of 52 size bytes for the Header");
        }
        
        // the first part of the elf header are a 16 bytes array that is called
        // e_ident. It contains important data about the bin file, like endiannes,
        // important offsets, if is 32 bit or not etc.

        // First part of the e_ident array is 4 bytes that should be always equal
        // to: 7f, 45, 4c, 46, respectively. They are called 'magic number' for some
        // reason that idk.

        let b1 = bytes.get(0);
        let b2 = bytes.get(1);
        let b3  = bytes.get(2);
        let b4 = bytes.get(3);

        let mut eidentmag: [u8; 16] = [0; 16];
        if let (Some(&hex_mv1), Some(&hex_mv2), Some(&hex_mv3), Some(&hex_mv4)) = (b1, b2, b3, b4) {
            if hex_mv1 == 0x7f && hex_mv2 == 0x45 && hex_mv3 == 0x4c && hex_mv4 == 0x46 {
                eidentmag[0] = hex_mv1;
            } else {
                return Err(INVALID_ELF_MSG);
            }
        } else {
            return Err(INVALID_ELF_MSG);
        }

        // the next byte identifies the file class, if is 32 bit or 64 bit
        // file or an Invalid Class (idk why this exists instead of simply 
        // throw a compiler exception or something like this)

        if bytes[4] != 0 && bytes[4] != 1 && bytes[4] != 2 {
            return Err(INVALID_ELF_IDENT_CLASS_MSG);
        } else {
            if bytes[4] == 1 {
                // this means that is a 32-bit object, so its invalid
                return Err(INVALID_ELF_IDENT_CLASS_MSG);
            } else {
                
            }
        };
        


        return Ok(_);
    }
}

pub struct ElfHeader {
    class: BinClasses,

}

pub enum BinClasses {
    InvalidClass,
    Class32,
    Class64
}