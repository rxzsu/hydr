use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    UnexpectedEof,
    InvalidData(&'static str),
    Message(String),
    AuthFailed,
    StreamClosed,
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::UnexpectedEof => write!(f, "unexpected end of buffer"),
            Error::InvalidData(msg) => write!(f, "invalid data: {msg}"),
            Error::Message(msg) => write!(f, "{msg}"),
            Error::AuthFailed => write!(f, "authentication failed"),
            Error::StreamClosed => write!(f, "stream closed"),
            Error::Unsupported => write!(f, "unsupported"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<std::io::ErrorKind> for Error {
    fn from(k: std::io::ErrorKind) -> Self {
        Error::Io(k.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;