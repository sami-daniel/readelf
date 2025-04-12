use crate::utils::endianess::EndianRead;
use elf64bitvalidationerrors::*;

pub struct Elf64BitValidator<'a> {
    base: &'a [u8],
}

impl<'a> Elf64BitValidator<'a> {
    const EI_DATA: usize = 5;

    pub fn new(base_bytes: &'a [u8]) -> Self {
        Elf64BitValidator { base: base_bytes }
    }

    pub fn validate_e_ident(&mut self) -> Result<Box<&'a [u8]>, Elf64BitEIdentValidationErrors> {
        // offset: 0x0 -> 0x0F

        // first, we need to verify if the e_ident byte arr is more than 16 bytes
        // of size
        if self.base.len() < 16 {
            return Err(
                elf64bitvalidationerrors::Elf64BitEIdentValidationErrors::InvalidEIdentSize.into(),
            );
        }
        let e_ident = &self.base[..16];

        // First part of the e_ident array is 4 bytes that should be always equal
        // to: 7f, 45, 4c, 46, respectively. They are called 'magic number' for some
        // reason that idk, but they serve for identify the elf file as an valid
        // elf file.

        let b1 = e_ident.get(0);
        let b2 = e_ident.get(1);
        let b3 = e_ident.get(2);
        let b4 = e_ident.get(3);

        if let (Some(&hex_mv1), Some(&hex_mv2), Some(&hex_mv3), Some(&hex_mv4)) = (b1, b2, b3, b4) {
            if hex_mv1 != 0x7f && hex_mv2 != 0x45 && hex_mv3 != 0x4c && hex_mv4 != 0x46 {
                return Err(
                    elf64bitvalidationerrors::Elf64BitEIdentValidationErrors::InvalidMagicNumbers
                        .into(),
                );
            }
        }

        // the next byte identifies the file class, if is 32 bit or 64 bit
        // file or an Invalid Class (idk why this exists instead of simply
        // throw a compiler exception or something like this)

        if e_ident[4] != 2 {
            // this means that is non 64-bit object, so its invalid
            return Err(
                elf64bitvalidationerrors::Elf64BitEIdentValidationErrors::Non64BitELF(e_ident[4])
                    .into(),
            );
        }

        // the next byte identifies the endiannes enconding of most of the
        // data present in this file.
        if e_ident[5] != 1 && e_ident[5] != 2 {
            return Err(
                elf64bitvalidationerrors::Elf64BitEIdentValidationErrors::InvalidEndianness(
                    e_ident[5],
                )
                .into(),
            );
        }

        // the next byte identify if the ELF file is version number
        // witch is 1 (one) since 1995, so we dont have to think that
        // will be changed now (right?)

        if e_ident[6] != 1 {
            return Err(
                elf64bitvalidationerrors::Elf64BitEIdentValidationErrors::InvalidELFVersion(
                    e_ident[6],
                )
                .into(),
            );
        }

        // here, would the validation of the EI_OSABI and EI_ABIVERSION
        // witch describes respectivily, the operational system ABI and
        // it version, but normally, we just accept them

        if e_ident[9..16] != [0; 7] {
            return Err(
                elf64bitvalidationerrors::Elf64BitEIdentValidationErrors::InvalidPadding.into(),
            );
        }

        return Ok(Box::new(e_ident));
    }

    pub fn validate_e_type(&self) -> Result<Box<&'a [u8]>, Elf64BitETypeValidationErrors> {
        // the e_type field uses u16, that occuppes 2 bytes, so we have to cast to apropriatte endiannes
        // offset: 0x10 -> 0x11

        // the e_type field describes an way to say the type of file that are this elf. Usually, this
        // value is ET_REL, witch means that is an relocatable file (.o file without linking), ET_EXEC
        // witch means that is an executable file, like /bin/ls, ET_DYN for shared object files (.so)
        // and finally ET_CORE for core dumps (when the file crashes)

        if self.base.len() < 18 {
            // this means that e_type has not the required size for e_type, that is 2 bytes
            return Err(Elf64BitETypeValidationErrors::InvalidETypeSize);
        }

        let endianness = self.get_endianness();

        let e_type_bytes = &self.base[16..18];

        let end_blk_anlzr = {
            if endianness == 1 {
                true
            } else if endianness == 2 {
                false
            } else {
                return Err(Elf64BitETypeValidationErrors::InvalidEndianness(endianness));
            }
        };

        let e_type = u16::read_from(e_type_bytes, end_blk_anlzr);

        // validate e_type value (common values are 1=REL, 2=EXEC, 3=SHARED, 4=CORE, 0xff00=Processor-specific, 0xffff=Processor-specific)
        if !(matches!(e_type, 0 | 1 | 2 | 3 | 4)
            || (0xfe00..=0xfeff).contains(&e_type)
            || (0xff00..=0xffff).contains(&e_type))
        {
            return Err(Elf64BitETypeValidationErrors::InvalidETypeValue(e_type));
        }

        Ok(Box::new(e_type_bytes))
    }

    pub fn validate_e_machine(&self) -> Result<Box<&'a [u8]>, Elf64BitEMachineValidationErrors> {
        // offsett: 0x12 -> 0x13

        // here we are using also u16 (64 half) as representational val for theses bytes
        // the e_machine fields specifies some bunch of macros that expands to some valeus
        // that define specific arch for the binary. The kernel analizes this val and decides
        // if can be enable to run it or it should panic
        // Everytime a support for ELF for some specific arch is developed, is added to the elf.h
        // as some macro value. We can't validate it value for two reason. First, it have some bunch
        // of possible values to it, so we are constantly obligatted (if we do this validation) to add
        // it to our code, and our bindgen tool is not able to tranform the numeric macros of it in some
        // sort of constants of even enums. It's more easily to not validate it, since we dont have time
        // nor reason to create every constant in hand. In other way, the values are not easily defined.
        // It has not an well defined range for it, like from x to y. Apparently, they define the value
        // like they want it, like a good kernel developer.

        if self.base.len() < 20 {
            return Err(Elf64BitEMachineValidationErrors::InvalidEMachSize);
        }

        let endianness = self.get_endianness();

        let end_chk_blk = {
            if endianness == 1 {
                true
            } else if endianness == 2 {
                false
            } else {
                return Err(Elf64BitEMachineValidationErrors::InvalidEndianness(
                    endianness,
                ));
            }
        };

        let e_machine_bytes = &self.base[18..20];

        Ok(Box::new(e_machine_bytes))
    }

    fn get_endianness(&self) -> u8 {
        // offset: 0x5

        self.base[Self::EI_DATA]
    }
}

pub mod elf64bitvalidationerrors {
    #[derive(thiserror::Error, Debug)]
    pub enum Elf64BitEIdentValidationErrors {
        #[error("The ELF file could not be identified as an valid ELF file")]
        NonELFFileError,
        #[error("The ELF file e_ident has an invalid e_ident size.")]
        InvalidEIdentSize,
        #[error("The ELF file cannot be identified as a ELF file.")]
        InvalidMagicNumbers,
        #[error("The ELF file e_ident describes a non 64-bit value (`{0}`)")]
        Non64BitELF(u8),
        #[error(
            "The ELF file e_ident version cannot be setted to other value different of 1. See https://refspecs.linuxfoundation.org/ for more info"
        )]
        InvalidELFVersion(u8),
        #[error("The ELF file e_ident describes an invalid endiannes value (`{0}`)")]
        InvalidEndianness(u8),
        #[error(
            "The ELF file e_ident dont describes an right padding for ELF file, witch should be 0 for the 9 byte to the 15 "
        )]
        InvalidPadding,
    }

    #[derive(thiserror::Error, Debug)]
    pub enum Elf64BitETypeValidationErrors {
        #[error("The ELF file has an invalid e_type size.")]
        InvalidETypeSize,
        #[error("The ELF file e_type describes an invalid endiannes value (`{0}`)")]
        InvalidEndianness(u8),
        #[error("The ELF file e_type descibes an invalid e_type value (`{0}`)")]
        InvalidETypeValue(u16),
    }

    #[derive(thiserror::Error, Debug)]
    pub enum Elf64BitEMachineValidationErrors {
        #[error("The ELF file has an invalid e_machine size.")]
        InvalidEMachSize,
        #[error("The ELF file e_machine describes an invalid endiannes value (`{0}`)")]
        InvalidEndianness(u8),
    }
}

#[cfg(test)]
mod tests {
    macro_rules! assert_err_variant {
        ($result:expr, $pattern:pat_param) => {
            match &$result {
                Err($pattern) => {}
                _ => panic!(
                    "Expected Err({}), but was {:?}",
                    stringify!($pattern),
                    $result
                ),
            }
        };
    }

    mod validate_e_ident {
        use super::super::Elf64BitValidator;
        use super::super::elf64bitvalidationerrors::Elf64BitEIdentValidationErrors;

        #[test]
        fn validate_e_ident_returns_non_elf_file_err_when_arr_size_is_less_than_16() {
            let file = [0u8; 15];

            let result = Elf64BitValidator::new(&file).validate_e_ident();

            assert_err_variant!(result, Elf64BitEIdentValidationErrors::InvalidEIdentSize)
        }

        #[test]
        fn validate_e_ident_return_non_elf_file_err_when_the_first_four_bytes_are_diff_than_the_recognized_magnumbers()
         {
            // the magic numbers are 0x7x, 0x45, 0x4c, 0x46
            let mut file = [0u8; 16];
            file[0] = 0;
            file[1] = 1;
            file[2] = 2;
            file[3] = 3;

            let result = Elf64BitValidator::new(&file).validate_e_ident();

            assert_err_variant!(result, Elf64BitEIdentValidationErrors::InvalidMagicNumbers)
        }

        #[test]
        fn validate_e_ident_returns_non_64bit_file_error_if_the_elf_class_is_diff_than_2() {
            let mut file = [0u8; 16];
            file[0] = 0x7f;
            file[1] = 0x45;
            file[2] = 0x4c;
            file[3] = 0x46;
            file[4] = 1; // means that is a 32-bit object

            let result = Elf64BitValidator::new(&file).validate_e_ident();

            assert_err_variant!(result, Elf64BitEIdentValidationErrors::Non64BitELF(_))
        }

        #[test]
        fn validate_e_ident_returns_invalid_endianness_error_if_e_ident5_is_invalid() {
            let mut file = [0u8; 16];
            file[0] = 0x7f;
            file[1] = 0x45;
            file[2] = 0x4c;
            file[3] = 0x46;
            file[4] = 2; // valid 64-bit class
            file[5] = 3; // invalid endianness (should be 1 or 2)

            let result = Elf64BitValidator::new(&file).validate_e_ident();

            assert_err_variant!(result, Elf64BitEIdentValidationErrors::InvalidEndianness(_))
        }

        #[test]
        fn validate_e_ident_returns_invalid_elf_version_error_if_e_ident6_is_not_1() {
            let mut file = [0u8; 16];
            file[0] = 0x7f;
            file[1] = 0x45;
            file[2] = 0x4c;
            file[3] = 0x46;
            file[4] = 2; // valid 64-bit class
            file[5] = 1; // valid endianness (little-endian)
            file[6] = 2; // invalid ELF version (should be 1)

            let result = Elf64BitValidator::new(&file).validate_e_ident();

            assert_err_variant!(result, Elf64BitEIdentValidationErrors::InvalidELFVersion(_))
        }

        #[test]
        fn validate_e_ident_returns_invalid_padding_error_if_padding_bytes_are_not_zero() {
            let mut file = [0u8; 16];
            file[0] = 0x7f;
            file[1] = 0x45;
            file[2] = 0x4c;
            file[3] = 0x46;
            file[4] = 2; // valid 64-bit class
            file[5] = 1; // valid endianness
            file[6] = 1; // valid ELF version
            file[9] = 1; // padding should be zero, but here it's 1

            let result = Elf64BitValidator::new(&file).validate_e_ident();

            assert_err_variant!(result, Elf64BitEIdentValidationErrors::InvalidPadding)
        }

        #[test]
        fn validate_e_ident_returns_ok_if_all_bytes_are_valid() {
            let mut file = [0u8; 16];
            file[0] = 0x7f;
            file[1] = 0x45;
            file[2] = 0x4c;
            file[3] = 0x46;
            file[4] = 2; // valid 64-bit
            file[5] = 1; // valid endianness
            file[6] = 1; // valid version
            file[7] = 0; // OS ABI
            file[8] = 0; // ABI Version
            // padding already 0 by default

            let result = Elf64BitValidator::new(&file).validate_e_ident();

            assert!(result.is_ok())
        }
    }

    mod validate_e_type {
        use super::super::Elf64BitValidator;
        use super::super::elf64bitvalidationerrors::Elf64BitETypeValidationErrors;

        fn create_valid_file() -> Box<[u8]> {
            let mut file = [0u8; 52];
            file[0..4].copy_from_slice(&[0x7f, 0x45, 0x4c, 0x46]);
            file[5] = 2;
            file[4] = 2;
            file[6] = 1;

            Box::new(file)
        }

        #[test]
        fn validate_e_type_returns_invalid_elf_file_err_when_endianness_is_invalid() {
            let mut file = create_valid_file();
            file[5] = 3;

            let result = Elf64BitValidator::new(&file).validate_e_type();

            assert_err_variant!(result, Elf64BitETypeValidationErrors::InvalidEndianness(3))
        }

        #[test]
        fn validate_e_type_returns_invalid_e_type_size_when_file_size_is_less_than_18() {
            let file = [0u8; 17];

            let result = Elf64BitValidator::new(&file).validate_e_type();

            assert_err_variant!(result, Elf64BitETypeValidationErrors::InvalidETypeSize)
        }

        #[test]
        fn validate_e_type_returns_invalid_e_type_value_when_value_is_invalid() {
            let mut file = create_valid_file();
            file[16..18].copy_from_slice(&[0x00, 0x05]);

            let result = Elf64BitValidator::new(&file).validate_e_type();

            assert_err_variant!(result, Elf64BitETypeValidationErrors::InvalidETypeValue(5))
        }

        #[test]
        fn validate_e_type_returns_ok_for_valid_e_type() {
            let mut file = create_valid_file();
            file[5] = 1; // little endiann
            file[16..18].copy_from_slice(&[0x01, 0x00]);
            let result = Elf64BitValidator::new(&file).validate_e_type();

            assert!(result.is_ok());
        }

        #[test]
        fn validate_e_type_return_bytes_accordding_to_the_le_of_file() {
            let mut file = create_valid_file();
            file[5] = 1; // LE
            file[16..18].copy_from_slice(&[0x01, 0x00]); // one in LE

            let result = Elf64BitValidator::new(&file).validate_e_type().unwrap();

            assert!(result[0] == 0x01 && result[1] == 0x00);
        }

        #[test]
        fn validate_e_type_returns_bytes_according_to_the_be_of_file() {
            let mut file = create_valid_file();
            file[5] = 2; // BE
            file[16..18].copy_from_slice(&[0x00, 0x01]); // one in BE

            let result = Elf64BitValidator::new(&file).validate_e_type().unwrap();

            assert!(result[0] == 0x00 && result[1] == 0x01);
        }
    }

    mod validate_e_machine {
        use super::super::Elf64BitValidator;
        use super::super::elf64bitvalidationerrors::Elf64BitEMachineValidationErrors;

        fn create_valid_file() -> Box<[u8]> {
            let mut file = [0u8; 52];
            file[0..4].copy_from_slice(&[0x7f, 0x45, 0x4c, 0x46]);
            file[4] = 2; // 64-bit
            file[5] = 2; // BE
            file[6] = 1; // version
            file[16..18].copy_from_slice(&[0x01, 0x00]);

            Box::new(file)
        }

        #[test]
        fn validate_e_machine_returns_invalid_e_machine_size_when_file_size_is_less_than_20() {
            let file = [0u8; 19];

            let result = Elf64BitValidator::new(&file).validate_e_machine();

            assert_err_variant!(result, Elf64BitEMachineValidationErrors::InvalidEMachSize)
        }

        #[test]
        fn validate_e_machine_returns_invalid_endianness_error_when_endianness_is_invalid() {
            let mut file = create_valid_file();
            file[5] = 3; // invalid endianness

            let result = Elf64BitValidator::new(&file).validate_e_machine();

            assert_err_variant!(
                result,
                Elf64BitEMachineValidationErrors::InvalidEndianness(3)
            )
        }

        #[test]
        fn validate_e_machine_returns_ok_for_known_machine_types() {
            let mut file = create_valid_file();

            // test some know machine
            let machine_types = [
                0x00, // no one specific. This is interessant, cause our bin may describe no spec for atch
                0x02, // SPARC
                0x03, // x86
                0x08, // MIPS
                0x14, // PowerPC
                0x28, // ARM
                0x2A, // SuperH
                0x32, // IA-64
                0x3E, // x86-64
                0xB7, // AArch64
                0xF3, // RISC-V
            ];

            for machine_type in machine_types {
                file[18..20].copy_from_slice(&[0x00, machine_type]);
                let result = Elf64BitValidator::new(&file).validate_e_machine();
                assert!(result.is_ok());
            }
        }

        #[test]
        fn validate_e_machine_returns_bytes_according_to_le_endianness() {
            let mut file = create_valid_file();
            file[5] = 1; // LE
            file[18..20].copy_from_slice(&[0x3E, 0x00]); // x86-64 in LE

            let result = Elf64BitValidator::new(&file).validate_e_machine().unwrap();

            assert!(result[0] == 0x3E && result[1] == 0x00);
        }

        #[test]
        fn validate_e_machine_returns_bytes_according_to_be_endianness() {
            let mut file = create_valid_file();
            file[5] = 2; // BE
            file[18..20].copy_from_slice(&[0x00, 0x3E]); // x86-64 in BE

            let result = Elf64BitValidator::new(&file).validate_e_machine().unwrap();

            assert!(result[0] == 0x00 && result[1] == 0x3E);
        }
    }
}
