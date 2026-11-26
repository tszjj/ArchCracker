// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Error type shared by the core and CLI.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AcxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("7z error: {0}")]
    SevenZ(#[from] sevenz_rust2::Error),

    #[error("external engine error: {0}")]
    External(String),

    #[error("unsupported archive: {0}")]
    Unsupported(String),

    #[error("archive is not encrypted")]
    NotEncrypted,

    #[error("missing archive volume: {0}")]
    MissingVolume(String),

    #[error("archive is truncated: {0}")]
    Truncated(String),

    #[error("archive is damaged: {0}")]
    Corrupt(String),

    #[error("operation cancelled")]
    Cancelled,

    #[error("checkpoint error: {0}")]
    Checkpoint(String),

    #[error("archive has no file entries")]
    EmptyArchive,

    #[error("dictionary error: {0}")]
    Dictionary(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AcxError>;
