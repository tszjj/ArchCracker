// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Shared fixture builders for W2-008 corpus generation and differential tests.
//! Fixtures are always generated at runtime; no archive is committed.

#![allow(dead_code)]

use sevenz_rust2::encoder_options::AesEncoderOptions;
use sevenz_rust2::{ArchiveEntry, ArchiveWriter, EncoderConfiguration, EncoderMethod, Password};
use std::io::{Cursor, Write};
use std::path::Path;
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

pub const HELLO: &[u8] = b"ArchCracker W2-008 differential fixture";

pub fn write_zipcrypto(path: &Path, password: &[u8]) {
    let file = std::fs::File::create(path).expect("create ZipCrypto fixture");
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .with_deprecated_encryption(password)
        .expect("ZipCrypto options");
    writer
        .start_file("hello.txt", options)
        .expect("start entry");
    writer.write_all(HELLO).expect("write entry");
    writer.finish().expect("finish ZipCrypto fixture");
}

pub fn write_aes_zip(path: &Path, password: &str) {
    let file = std::fs::File::create(path).expect("create AES ZIP fixture");
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .with_aes_encryption(zip::AesMode::Aes256, password);
    writer
        .start_file("hello.txt", options)
        .expect("start entry");
    writer.write_all(HELLO).expect("write entry");
    writer.finish().expect("finish AES ZIP fixture");
}

pub fn write_plain_zip(path: &Path) {
    let file = std::fs::File::create(path).expect("create plain ZIP fixture");
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    writer
        .start_file("hello.txt", options)
        .expect("start entry");
    writer.write_all(HELLO).expect("write entry");
    writer.finish().expect("finish plain ZIP fixture");
}

pub fn write_7z_password(path: &Path, password: &str) {
    let mut writer = ArchiveWriter::create(path).expect("create 7z fixture");
    let mut methods = vec![EncoderConfiguration::new(EncoderMethod::LZMA2)];
    methods.push(AesEncoderOptions::new(Password::from(password)).into());
    writer.set_content_methods(methods);
    writer
        .push_archive_entry(
            ArchiveEntry::new_file("hello.txt"),
            Some(Cursor::new(HELLO.to_vec())),
        )
        .expect("push entry");
    writer.finish().expect("finish 7z fixture");
}

pub fn truncate(path: &Path, keep_bytes: usize) {
    let bytes = std::fs::read(path).expect("read fixture to truncate");
    let keep = keep_bytes.min(bytes.len());
    std::fs::write(path, &bytes[..keep]).expect("write truncated fixture");
}

pub fn flip_byte(path: &Path, offset: usize) {
    let mut bytes = std::fs::read(path).expect("read fixture to corrupt");
    let index = offset.min(bytes.len().saturating_sub(1));
    if let Some(byte) = bytes.get_mut(index) {
        *byte ^= 0xff;
    }
    std::fs::write(path, bytes).expect("write corrupted fixture");
}
