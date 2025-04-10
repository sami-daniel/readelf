pub mod elf64bitvalidator {
    pub fn validate_eident(e_ident: &[u8]) -> Result<(), elf64bitvalidationerrors::Elf64BitEIdentValidationErrors> {
        // first, we need to verify if the e_ident byte arr is more than 16 bytes
        // of size
        if e_ident.len() != 16 {
            return Err(elf64bitvalidationerrors::Elf64BitEIdentValidationErrors::InvalidEIdentSize.into());
        }

        // First part of the e_ident array is 4 bytes that should be always equal
        // to: 7f, 45, 4c, 46, respectively. They are called 'magic number' for some
        // reason that idk, but they serve for identify the elf file as an valid
        // elf file.

        let b1 = e_ident.get(0);
        let b2 = e_ident.get(1);
        let b3  = e_ident.get(2);
        let b4 = e_ident.get(3);

        if let (Some(&hex_mv1), Some(&hex_mv2), Some(&hex_mv3), Some(&hex_mv4)) = (b1, b2, b3, b4) {
            if hex_mv1 != 0x7f && hex_mv2 != 0x45 && hex_mv3 != 0x4c && hex_mv4 != 0x46 {
                return Err(elf64bitvalidationerrors::Elf64BitEIdentValidationErrors::InvalidMagicNumbers.into());
            }
        }

        // the next byte identifies the file class, if is 32 bit or 64 bit
        // file or an Invalid Class (idk why this exists instead of simply 
        // throw a compiler exception or something like this)

        if e_ident[4] != 2 {
            // this means that is non 64-bit object, so its invalid
            return Err(elf64bitvalidationerrors::Elf64BitEIdentValidationErrors::Non64BitELF(e_ident[4]).into());
        }
        
        // the next byte identifies the endiannes enconding of most of the
        // data present in this file.
        if e_ident[5] != 1 && e_ident[5] != 2 {
            return Err(elf64bitvalidationerrors::Elf64BitEIdentValidationErrors::InvalidEndianness(e_ident[5]).into());
        }

        // the next byte identify if the ELF file is version number
        // witch is 1 (one) since 1995, so we dont have to think that
        // will be changed now (right?)
        
        if e_ident[6] != 1 {
            return Err(elf64bitvalidationerrors::Elf64BitEIdentValidationErrors::InvalidELFVersion(e_ident[6]).into())
        }

        // here, would the validation of the EI_OSABI and EI_ABIVERSION
        // witch describes respectivily, the operational system ABI and
        // it version, but normally, we just accept them

        if e_ident[9..16] != [0; 7] {
            return Err(elf64bitvalidationerrors::Elf64BitEIdentValidationErrors::InvalidPadding.into())
        }

        return Ok(());
    }

    pub mod elf64bitvalidationerrors {
        #[derive(thiserror::Error, Debug)]
        pub enum Elf64BitEIdentValidationErrors {
            #[error("The ELF file could not be identified as an valid ELF file")]
            NonELFFileError,
            #[error("The ELF file eident has an invalid eident size.")]
            InvalidEIdentSize,
            #[error("The ELF file cannot be identified as a ELF file.")]
            InvalidMagicNumbers,
            #[error("The ELF file eident describes a non 64-bit value (`{0}`)")]
            Non64BitELF(u8),
            #[error("The ELF file eident version cannot be setted to other value different of 1. See https://refspecs.linuxfoundation.org/ for more info")]
            InvalidELFVersion(u8),
            #[error("The ELF file eident describes an invalid endiannes value (`{0}`)")]
            InvalidEndianness(u8),
            #[error("The ELF file eident dont describes an right padding for ELF file, witch should be 0 for the 9 byte to the 15 ")]
            InvalidPadding,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::elf64bitvalidator::validate_eident;
    use super::elf64bitvalidator::elf64bitvalidationerrors::Elf64BitEIdentValidationErrors;

    macro_rules! assert_err_variant {
        ($result:expr, $pattern:pat_param) => {
            match &$result {
                Err($pattern) => {},
                _ => panic!(
                    "Esperado Err({}), mas foi {:?}",
                    stringify!($pattern),
                    $result
                ),
            }
        };
    }

    #[test]
    fn validate_eident_returns_non_elf_file_err_when_arr_size_is_less_than_16() {
        let e_ident = [0u8; 15]; 
        let result = validate_eident(&e_ident);

        assert_err_variant!(result, Elf64BitEIdentValidationErrors::InvalidEIdentSize)
    }

    #[test]
    fn validate_eident_return_non_elf_file_err_when_the_first_four_bytes_are_diff_than_the_recognized_magnumbers() {
        // the magic numbers are 0x7x, 0x45, 0x4c, 0x46
        
        let mut e_ident = [0u8; 16];
        e_ident[0] = 0;
        e_ident[1] = 1;
        e_ident[2] = 2;
        e_ident[3] = 3;

        let result = validate_eident(&e_ident);

        assert_err_variant!(result, Elf64BitEIdentValidationErrors::InvalidMagicNumbers)
    }

    #[test]
    fn validate_eident_returns_non_64bit_file_error_if_the_elf_class_is_diff_than_2() {
        let mut e_ident = [0u8; 16];
        e_ident[0] = 0x7f;
        e_ident[1] = 0x45;
        e_ident[2] = 0x4c;
        e_ident[3] = 0x46;
        e_ident[4] = 1; // means that is a 32-bit object

        let result = validate_eident(&e_ident);
        
        assert_err_variant!(result, Elf64BitEIdentValidationErrors::Non64BitELF(_))
    }

    #[test]
    fn validate_eident_returns_invalid_endianness_error_if_eident5_is_invalid() {
        let mut e_ident = [0u8; 16];
        e_ident[0] = 0x7f;
        e_ident[1] = 0x45;
        e_ident[2] = 0x4c;
        e_ident[3] = 0x46;
        e_ident[4] = 2; // Valid 64-bit class
        e_ident[5] = 3; // Invalid endianness (should be 1 or 2)

        let result = validate_eident(&e_ident);

        assert_err_variant!(result, Elf64BitEIdentValidationErrors::InvalidEndianness(_))
    }

    #[test]
    fn validate_eident_returns_invalid_elf_version_error_if_eident6_is_not_1() {
        let mut e_ident = [0u8; 16];
        e_ident[0] = 0x7f;
        e_ident[1] = 0x45;
        e_ident[2] = 0x4c;
        e_ident[3] = 0x46;
        e_ident[4] = 2; // valid 64-bit class
        e_ident[5] = 1; // valid endianness (little-endian)
        e_ident[6] = 2; // invalid ELF version (should be 1)

        let result = validate_eident(&e_ident);

        assert_err_variant!(result, Elf64BitEIdentValidationErrors::InvalidELFVersion(_))
    }

    #[test]
    fn validate_eident_returns_invalid_padding_error_if_padding_bytes_are_not_zero() {
        let mut e_ident = [0u8; 16];
        e_ident[0] = 0x7f;
        e_ident[1] = 0x45;
        e_ident[2] = 0x4c;
        e_ident[3] = 0x46;
        e_ident[4] = 2; // valid 64-bit class
        e_ident[5] = 1; // valid endianness
        e_ident[6] = 1; // valid ELF version
        e_ident[9] = 1; // padding should be zero, but here it's 1

        let result = validate_eident(&e_ident);

        assert_err_variant!(result, Elf64BitEIdentValidationErrors::InvalidPadding)
    }

    #[test]
    fn validate_eident_returns_ok_if_all_bytes_are_valid() {
        let mut e_ident = [0u8; 16];
        e_ident[0] = 0x7f;
        e_ident[1] = 0x45;
        e_ident[2] = 0x4c;
        e_ident[3] = 0x46;
        e_ident[4] = 2; // valid 64-bit
        e_ident[5] = 1; // valid endianness
        e_ident[6] = 1; // valid version
        e_ident[7] = 0; // OS ABI
        e_ident[8] = 0; // ABI Version
        // padding already 0 by default

        let result = validate_eident(&e_ident);

        assert!(result.is_ok())
    }

}