use dterror::{BoxError, CtxError, Location};

/// Errors produced while patching an HCL file.
///
/// The `#[error(...)]` messages are internal (they carry the source location and
/// are meant for logs); the strings that reach the user come from
/// [`PatcherError::client_message`], which renders HEAD-identical wording without
/// the location segment.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum PatcherError {
    #[error("I/O error [{location}]")]
    Io {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("HCL parse error [{location}]")]
    ParseHcl {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("xpath not found [{location}]")]
    XPathNotFound {
        #[context(borrow = str)]
        path: String,

        #[location]
        location: Location,
    },

    #[error("invalid type [{location}]")]
    InvalidType {
        #[context(borrow = str)]
        type_name: String,

        #[location]
        location: Location,
    },

    #[error("invalid value [{location}]")]
    InvalidValue {
        #[context(borrow = str)]
        type_name: String,

        #[context(borrow = str)]
        raw: String,

        #[location]
        location: Location,
    },

    #[error("xpath parse error [{location}]")]
    XPathParse {
        #[context(borrow = str)]
        message: String,

        #[location]
        location: Location,
    },
}

impl PatcherError {
    /// The message shown to the user on stderr.
    ///
    /// Renders HEAD-identical wording without the internal source-location
    /// segment that [`Display`](std::fmt::Display) appends for logs. The
    /// `ParseHcl` case renders its underlying source here, since HEAD surfaced
    /// the HCL parser's message to the user.
    pub(crate) fn client_message(&self) -> String {
        match self {
            PatcherError::Io { source, .. } => format!("I/O error: {source}"),
            PatcherError::ParseHcl { source, .. } => format!("HCL parse error: {source}"),
            PatcherError::XPathNotFound { path, .. } => format!("xpath not found: {path}"),
            PatcherError::InvalidType { type_name, .. } => format!("invalid type: {type_name}"),
            PatcherError::InvalidValue { type_name, raw, .. } => {
                format!("invalid {type_name} value: {raw}")
            }
            PatcherError::XPathParse { message, .. } => format!("xpath parse error: {message}"),
        }
    }

    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            PatcherError::Io { .. } => 1,
            PatcherError::ParseHcl { .. } | PatcherError::XPathParse { .. } => 2,
            PatcherError::XPathNotFound { .. }
            | PatcherError::InvalidType { .. }
            | PatcherError::InvalidValue { .. } => 3,
        }
    }
}
