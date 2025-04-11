const MSG_SLC_INV_LEN: &str = "Slice with incorrect length";  

pub trait EndianRead: Sized {
    fn read_from(bytes: &[u8], is_little_endian: bool) -> Self;
}

impl EndianRead for u16 {
    fn read_from(bytes: &[u8], is_little_endian: bool) -> Self {
        let arr: [u8; 2] = bytes.try_into().expect(MSG_SLC_INV_LEN);
        if is_little_endian {
            Self::from_le_bytes(arr)
        } else {
            Self::from_be_bytes(arr)
        }
    }
}

impl EndianRead for u32 {
    fn read_from(bytes: &[u8], is_little_endian: bool) -> Self {
        let arr: [u8; 4] = bytes.try_into().expect(MSG_SLC_INV_LEN);
        if is_little_endian {
            Self::from_le_bytes(arr)
        } else {
            Self::from_be_bytes(arr)
        }
    }
}

impl EndianRead for u64 {
    fn read_from(bytes: &[u8], is_little_endian: bool) -> Self {
        let arr: [u8; 8] = bytes.try_into().expect(MSG_SLC_INV_LEN);
        if is_little_endian {
            Self::from_le_bytes(arr)
        } else {
            Self::from_be_bytes(arr)
        }
    }
}

