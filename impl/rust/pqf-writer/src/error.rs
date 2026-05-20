use std::fmt;

#[derive(Debug)]
pub enum WriterError {
    InvalidChunkSize(u32),
    HeaderTooLarge(usize),
    RecipientFieldLength {
        field: &'static str,
        got: usize,
        want: usize,
    },
    NotYetImplemented(&'static str),
}

impl fmt::Display for WriterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriterError::InvalidChunkSize(n) => write!(
                f,
                "invalid chunk_size {n}: must be power-of-two in [4096, 16777216]"
            ),
            WriterError::HeaderTooLarge(n) => write!(f, "header is {n} bytes; cap is 1048576"),
            WriterError::RecipientFieldLength { field, got, want } => write!(
                f,
                "recipient field {field}: got {got} bytes, expected {want}"
            ),
            WriterError::NotYetImplemented(what) => write!(f, "not yet implemented: {what}"),
        }
    }
}

impl std::error::Error for WriterError {}

pub type WriterResult<T> = Result<T, WriterError>;
