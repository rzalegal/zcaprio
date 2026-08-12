use crate::PrimitiveError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Encodes bytes as canonical lowercase hexadecimal.
pub fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Decodes canonical lowercase hexadecimal bytes.
pub fn bytes(value: &str) -> Result<Vec<u8>, PrimitiveError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|character| character.is_ascii_digit() || (b'a'..=b'f').contains(&character))
    {
        return Err(PrimitiveError::InvalidEncoding);
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|chunk| u8::from_str_radix(chunk, 16).ok())
                .ok_or(PrimitiveError::InvalidEncoding)
        })
        .collect()
}

pub(crate) fn canonical<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut encoded = Vec::new();
    value
        .serialize_compressed(&mut encoded)
        .expect("serialization into memory cannot fail");
    encoded
}

pub(crate) fn parse<T: CanonicalDeserialize>(value: &str) -> Result<T, PrimitiveError> {
    let encoded = bytes(value)?;
    let mut input = encoded.as_slice();
    let decoded =
        T::deserialize_compressed(&mut input).map_err(|_| PrimitiveError::InvalidEncoding)?;
    if !input.is_empty() {
        return Err(PrimitiveError::InvalidEncoding);
    }
    Ok(decoded)
}
