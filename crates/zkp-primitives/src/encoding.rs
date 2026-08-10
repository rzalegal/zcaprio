use crate::PrimitiveError;

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
