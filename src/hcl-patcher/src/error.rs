use std::fmt;

#[derive(Debug)]
pub(crate) enum PatcherError {
    Io(std::io::Error),
    ParseHcl(String),
    XPathNotFound(String),
    InvalidType(String),
    InvalidValue { type_name: String, raw: String },
    XPathParse(String),
}

impl fmt::Display for PatcherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatcherError::Io(e) => write!(f, "I/O error: {e}"),
            PatcherError::ParseHcl(msg) => write!(f, "HCL parse error: {msg}"),
            PatcherError::XPathNotFound(path) => write!(f, "xpath not found: {path}"),
            PatcherError::InvalidType(t) => write!(f, "invalid type: {t}"),
            PatcherError::InvalidValue { type_name, raw } => {
                write!(f, "invalid {type_name} value: {raw}")
            }
            PatcherError::XPathParse(msg) => write!(f, "xpath parse error: {msg}"),
        }
    }
}

impl std::error::Error for PatcherError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PatcherError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PatcherError {
    fn from(e: std::io::Error) -> Self {
        PatcherError::Io(e)
    }
}

impl PatcherError {
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            PatcherError::Io(_) => 1,
            PatcherError::ParseHcl(_) | PatcherError::XPathParse(_) => 2,
            PatcherError::XPathNotFound(_)
            | PatcherError::InvalidType(_)
            | PatcherError::InvalidValue { .. } => 3,
        }
    }
}
