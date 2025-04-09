use std::error::Error;

pub trait Parseable : Sized {
    fn parse(bytes: &[u8]) -> Result<Self, &'static str>;
}