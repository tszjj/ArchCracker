// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Durable checkpoint for dictionary and mask/brute runs.
//!
//! The format is deliberately small and dependency-free (key=value lines).
//! A checkpoint records a **contiguous completed candidate watermark**, not the
//! largest attempted index, so resuming can replay at most the in-flight
//! candidates and never skips one.
//!
//! Schema v2 makes the dictionary optional and adds an attack fingerprint
//! (`attack_mode` + SHA-256 `attack_signature`) for mask/brute/hybrid runs.
//! Schema v1 checkpoints are rejected rather than half-read.

use crate::archive::{ArchiveFormat, ArchiveSource};
use crate::error::{AcxError, Result};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: u32 = 2;
const FINGERPRINT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFingerprint {
    pub path: String,
    pub len: u64,
    pub modified_ms: u64,
    pub head_crc32: u32,
    pub tail_crc32: u32,
}

impl FileFingerprint {
    pub fn from_path(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path)?;
        let len = metadata.len();
        let modified_ms = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_millis() as u64);
        let (head_crc32, tail_crc32) = fingerprint_bytes(path, len)?;
        Ok(Self {
            path: absolute_display(path),
            len,
            modified_ms,
            head_crc32,
            tail_crc32,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveFingerprint {
    pub format: String,
    pub parts: Vec<FileFingerprint>,
}

impl ArchiveFingerprint {
    pub fn from_source(source: &ArchiveSource) -> Result<Self> {
        let parts = source
            .parts
            .iter()
            .map(|part| FileFingerprint::from_path(part))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            format: source.format.as_str().to_string(),
            parts,
        })
    }

    pub fn format(&self) -> ArchiveFormat {
        match self.format.as_str() {
            "zip" => ArchiveFormat::Zip,
            "7z" => ArchiveFormat::SevenZ,
            "rar4" => ArchiveFormat::Rar4,
            "rar5" => ArchiveFormat::Rar5,
            _ => ArchiveFormat::Zip,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackFingerprint {
    pub mode: String,
    pub signature: String,
}

impl AttackFingerprint {
    pub fn new(mode: &str, signature: &str) -> Self {
        Self {
            mode: mode.to_string(),
            signature: signature.to_string(),
        }
    }

    pub fn dictionary() -> Self {
        Self::new("dict", &sha256_hex(b"dict"))
    }
}

#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub schema: u32,
    pub tool_version: String,
    pub archive: ArchiveFingerprint,
    pub dictionary: Option<FileFingerprint>,
    pub attack: AttackFingerprint,
    pub threads: usize,
    pub completed_through: u64,
    pub tried: u64,
    pub total: u64,
    pub created_unix_ms: u64,
}

impl Checkpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        archive: ArchiveFingerprint,
        dictionary: Option<FileFingerprint>,
        attack: AttackFingerprint,
        threads: usize,
        completed_through: u64,
        tried: u64,
        total: u64,
    ) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            tool_version: crate::VERSION.to_string(),
            archive,
            dictionary,
            attack,
            threads,
            completed_through,
            tried,
            total,
            created_unix_ms: unix_ms(),
        }
    }

    /// Validate that a checkpoint belongs to the same archive/attack/total.
    pub fn validate(
        &self,
        archive: &ArchiveFingerprint,
        dictionary: Option<&FileFingerprint>,
        attack: &AttackFingerprint,
        total: u64,
    ) -> Result<()> {
        if self.schema != SCHEMA_VERSION {
            return Err(AcxError::Checkpoint(format!(
                "unsupported checkpoint schema {} (expected {SCHEMA_VERSION}; rerun without --resume)",
                self.schema
            )));
        }
        if self.archive != *archive {
            return Err(AcxError::Checkpoint(
                "archive fingerprint changed since the checkpoint".to_string(),
            ));
        }
        if self.dictionary.as_ref() != dictionary {
            return Err(AcxError::Checkpoint(
                "dictionary fingerprint changed since the checkpoint".to_string(),
            ));
        }
        if self.attack != *attack {
            return Err(AcxError::Checkpoint(
                "attack signature changed since the checkpoint".to_string(),
            ));
        }
        if self.total != total {
            return Err(AcxError::Checkpoint(format!(
                "checkpoint total {} does not match attack length {total}",
                self.total
            )));
        }
        if self.completed_through > total {
            return Err(AcxError::Checkpoint(format!(
                "checkpoint watermark {} exceeds total {total}",
                self.completed_through
            )));
        }
        if self.completed_through > self.tried {
            return Err(AcxError::Checkpoint(format!(
                "checkpoint watermark {} exceeds tried {}",
                self.completed_through, self.tried
            )));
        }
        Ok(())
    }
}

/// Sidecar checkpoint file with atomic replace.
#[derive(Debug, Clone)]
pub struct CheckpointStore {
    path: PathBuf,
}

impl CheckpointStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save(&self, checkpoint: &Checkpoint) -> Result<()> {
        let body = encode(checkpoint);
        let temp = PathBuf::from(format!(
            "{}.tmp.{}",
            self.path.display(),
            std::process::id()
        ));
        {
            let mut file = File::create(&temp)?;
            file.write_all(body.as_bytes())?;
            file.sync_all()?;
        }
        // Windows cannot rename over an existing file. Remove first; the
        // temp+rename still prevents a half-written checkpoint.
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        std::fs::rename(&temp, &self.path)?;
        Ok(())
    }

    pub fn load(&self) -> Result<Checkpoint> {
        let body = std::fs::read_to_string(&self.path).map_err(|error| {
            AcxError::Checkpoint(format!(
                "cannot read checkpoint {}: {error}",
                self.path.display()
            ))
        })?;
        decode(&body).map_err(|error| {
            AcxError::Checkpoint(format!(
                "cannot parse checkpoint {}: {error}",
                self.path.display()
            ))
        })
    }

    pub fn remove(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AcxError::Io(error)),
        }
    }

    /// Remove a stale lock. CLI resume calls this after a hard kill; the lock
    /// is advisory for W1's single-process CLI, not a multi-user lock.
    pub fn clear_lock(&self) -> Result<()> {
        let path = PathBuf::from(format!("{}.lock", self.path.display()));
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AcxError::Io(error)),
        }
    }

    /// Create a process lock beside the checkpoint. A stale lock is not
    /// removed automatically; callers must delete it after a crash.
    pub fn lock(&self) -> Result<CheckpointLock> {
        let path = PathBuf::from(format!("{}.lock", self.path.display()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                AcxError::Checkpoint(format!(
                    "checkpoint is locked or cannot be locked ({}): {error}",
                    path.display()
                ))
            })?;
        let mut file = file;
        let _ = writeln!(file, "pid={}", std::process::id());
        Ok(CheckpointLock { path })
    }
}

/// Removes the lock file when the run ends.
#[derive(Debug)]
pub struct CheckpointLock {
    path: PathBuf,
}

impl Drop for CheckpointLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn fingerprint_bytes(path: &Path, len: u64) -> Result<(u32, u32)> {
    let mut file = File::open(path)?;
    let head_len = len.min(FINGERPRINT_BYTES) as usize;
    let mut head = vec![0u8; head_len];
    file.read_exact(&mut head)?;

    let tail_start = len.saturating_sub(FINGERPRINT_BYTES);
    file.seek(SeekFrom::Start(tail_start))?;
    let mut tail = vec![0u8; (len - tail_start) as usize];
    file.read_exact(&mut tail)?;
    Ok((crc32fast::hash(&head), crc32fast::hash(&tail)))
}

fn absolute_display(path: &Path) -> String {
    std::path::absolute(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

fn encode(checkpoint: &Checkpoint) -> String {
    let mut output = String::new();
    output.push_str(&format!("schema={}\n", checkpoint.schema));
    output.push_str(&format!(
        "tool_version={}\n",
        escape(&checkpoint.tool_version)
    ));
    output.push_str(&format!(
        "archive_format={}\n",
        escape(&checkpoint.archive.format)
    ));
    for part in &checkpoint.archive.parts {
        output.push_str(&format!("part={}\n", encode_file(part)));
    }
    if let Some(dictionary) = &checkpoint.dictionary {
        output.push_str(&format!("dictionary={}\n", encode_file(dictionary)));
    }
    output.push_str(&format!(
        "attack_mode={}\n",
        escape(&checkpoint.attack.mode)
    ));
    output.push_str(&format!(
        "attack_signature={}\n",
        escape(&checkpoint.attack.signature)
    ));
    output.push_str(&format!("threads={}\n", checkpoint.threads));
    output.push_str(&format!(
        "completed_through={}\n",
        checkpoint.completed_through
    ));
    output.push_str(&format!("tried={}\n", checkpoint.tried));
    output.push_str(&format!("total={}\n", checkpoint.total));
    output.push_str(&format!("created_unix_ms={}\n", checkpoint.created_unix_ms));
    output
}

fn encode_file(file: &FileFingerprint) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        escape(&file.path),
        file.len,
        file.modified_ms,
        file.head_crc32,
        file.tail_crc32
    )
}

fn decode(body: &str) -> std::result::Result<Checkpoint, String> {
    let mut schema = None;
    let mut tool_version = None;
    let mut archive_format = None;
    let mut parts = Vec::new();
    let mut dictionary = None;
    let mut attack_mode = None;
    let mut attack_signature = None;
    let mut threads = None;
    let mut completed_through = None;
    let mut tried = None;
    let mut total = None;
    let mut created_unix_ms = None;

    for line in body.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "schema" => schema = Some(parse_u32(value)?),
            "tool_version" => tool_version = Some(unescape(value)?),
            "archive_format" => archive_format = Some(unescape(value)?),
            "part" => parts.push(decode_file(value)?),
            "dictionary" => dictionary = Some(decode_file(value)?),
            "attack_mode" => attack_mode = Some(unescape(value)?),
            "attack_signature" => attack_signature = Some(unescape(value)?),
            "threads" => threads = Some(parse_u64(value)? as usize),
            "completed_through" => completed_through = Some(parse_u64(value)?),
            "tried" => tried = Some(parse_u64(value)?),
            "total" => total = Some(parse_u64(value)?),
            "created_unix_ms" => created_unix_ms = Some(parse_u64(value)?),
            _ => {}
        }
    }

    let schema = schema.ok_or("missing schema")?;
    if schema != SCHEMA_VERSION {
        return Err(format!(
            "unsupported schema {schema} (expected {SCHEMA_VERSION}; rerun without --resume)"
        ));
    }
    Ok(Checkpoint {
        schema,
        tool_version: tool_version.ok_or("missing tool_version")?,
        archive: ArchiveFingerprint {
            format: archive_format.ok_or("missing archive_format")?,
            parts,
        },
        dictionary,
        attack: AttackFingerprint {
            mode: attack_mode.ok_or("missing attack_mode")?,
            signature: attack_signature.ok_or("missing attack_signature")?,
        },
        threads: threads.ok_or("missing threads")?,
        completed_through: completed_through.ok_or("missing completed_through")?,
        tried: tried.ok_or("missing tried")?,
        total: total.ok_or("missing total")?,
        created_unix_ms: created_unix_ms.ok_or("missing created_unix_ms")?,
    })
}

fn decode_file(value: &str) -> std::result::Result<FileFingerprint, String> {
    let mut fields = value.split('|');
    let path = unescape(fields.next().ok_or("missing path")?)?;
    let len = parse_u64(fields.next().ok_or("missing len")?)?;
    let modified_ms = parse_u64(fields.next().ok_or("missing mtime")?)?;
    let head_crc32 = parse_u64(fields.next().ok_or("missing head crc")?)? as u32;
    let tail_crc32 = parse_u64(fields.next().ok_or("missing tail crc")?)? as u32;
    if fields.next().is_some() {
        return Err("too many fields".to_string());
    }
    Ok(FileFingerprint {
        path,
        len,
        modified_ms,
        head_crc32,
        tail_crc32,
    })
}

fn parse_u64(value: &str) -> std::result::Result<u64, String> {
    value
        .parse()
        .map_err(|error| format!("invalid number `{value}`: {error}"))
}

fn parse_u32(value: &str) -> std::result::Result<u32, String> {
    value
        .parse()
        .map_err(|error| format!("invalid schema number `{value}`: {error}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.chars() {
        match byte {
            '\\' => output.push_str("\\\\"),
            '|' => output.push_str("\\p"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            other => output.push(other),
        }
    }
    output
}

fn unescape(value: &str) -> std::result::Result<String, String> {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        match chars.next() {
            Some('\\') => output.push('\\'),
            Some('p') => output.push('|'),
            Some('n') => output.push('\n'),
            Some('r') => output.push('\r'),
            Some(other) => return Err(format!("invalid escape `\\{other}`")),
            None => return Err("trailing escape".to_string()),
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;

    fn scratch_dir() -> &'static Path {
        static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
        SCRATCH.get_or_init(|| {
            let mut fallback = std::env::current_exe().unwrap_or_default();
            if fallback.pop() {
                fallback.pop();
            }
            fallback.push("acx-test-tmp");
            let _ = std::fs::create_dir_all(&fallback);
            fallback
        })
    }

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path =
                scratch_dir().join(format!("acx-checkpoint-{tag}-{}-{id}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn file_fixture(path: &Path) -> FileFingerprint {
        std::fs::write(path, b"checkpoint fixture").expect("write");
        FileFingerprint::from_path(path).expect("fingerprint")
    }

    #[test]
    fn round_trips_checkpoint_and_escapes_paths() {
        let temp = TempDir::new("roundtrip");
        let archive_path = temp.join("archive.zip");
        let dictionary_path = temp.join("dict.txt");
        let archive = ArchiveFingerprint {
            format: "zip".to_string(),
            parts: vec![file_fixture(&archive_path)],
        };
        let dictionary = file_fixture(&dictionary_path);
        let checkpoint = Checkpoint::new(
            archive,
            Some(dictionary),
            AttackFingerprint::dictionary(),
            4,
            3,
            7,
            10,
        );
        let store = CheckpointStore::new(temp.join("run.acx-checkpoint"));
        store.save(&checkpoint).expect("save");
        let loaded = store.load().expect("load");
        assert_eq!(loaded.completed_through, 3);
        assert_eq!(loaded.tried, 7);
        assert_eq!(
            loaded.archive.parts[0].path,
            checkpoint.archive.parts[0].path
        );
        assert_eq!(
            loaded.dictionary.as_ref().map(|file| file.path.as_str()),
            checkpoint
                .dictionary
                .as_ref()
                .map(|file| file.path.as_str())
        );

        let odd = "a|b\\c\nd";
        assert_eq!(unescape(&escape(odd)).expect("escape"), odd);
    }

    #[test]
    fn fingerprint_change_is_rejected() {
        let temp = TempDir::new("mismatch");
        let archive_path = temp.join("a.zip");
        let dictionary_path = temp.join("dict.txt");
        let archive = ArchiveFingerprint {
            format: "zip".to_string(),
            parts: vec![file_fixture(&archive_path)],
        };
        let dictionary = file_fixture(&dictionary_path);
        let checkpoint = Checkpoint::new(
            archive.clone(),
            Some(dictionary.clone()),
            AttackFingerprint::dictionary(),
            1,
            0,
            0,
            1,
        );

        std::fs::write(&dictionary_path, b"changed").expect("change dict");
        let changed = FileFingerprint::from_path(&dictionary_path).expect("fingerprint");
        let error = checkpoint
            .validate(
                &archive,
                Some(&changed),
                &AttackFingerprint::dictionary(),
                1,
            )
            .expect_err("changed dictionary must fail");
        assert!(matches!(error, AcxError::Checkpoint(_)));
    }

    #[test]
    fn round_trips_mask_checkpoint_without_dictionary() {
        let temp = TempDir::new("mask-roundtrip");
        let archive_path = temp.join("archive.zip");
        let archive = ArchiveFingerprint {
            format: "zip".to_string(),
            parts: vec![file_fixture(&archive_path)],
        };
        let attack = AttackFingerprint::new("mask", "abc123");
        let checkpoint = Checkpoint::new(archive.clone(), None, attack.clone(), 8, 4, 9, 32);
        let store = CheckpointStore::new(temp.join("mask.acx-checkpoint"));
        store.save(&checkpoint).expect("save");
        let loaded = store.load().expect("load");
        assert!(loaded.dictionary.is_none());
        assert_eq!(loaded.attack, attack);
        loaded
            .validate(&archive, None, &attack, 32)
            .expect("mask checkpoint validates");
    }

    #[test]
    fn schema_one_checkpoint_is_rejected() {
        let temp = TempDir::new("schema-one");
        let store = CheckpointStore::new(temp.join("old.acx-checkpoint"));
        std::fs::write(
            store.path(),
            "schema=1\ntool_version=old\narchive_format=zip\npart=a|1|0|0|0\n\
             dictionary=a|1|0|0|0\nmode=dict\nthreads=1\ncompleted_through=0\ntried=0\n\
             total=1\ncreated_unix_ms=0\n",
        )
        .expect("write old checkpoint");
        let error = store.load().expect_err("schema 1 must be rejected");
        assert!(matches!(error, AcxError::Checkpoint(_)));
        assert!(error.to_string().contains("schema 1"));
    }

    #[test]
    fn schema_overflow_is_rejected() {
        let temp = TempDir::new("schema-overflow");
        let store = CheckpointStore::new(temp.join("huge.acx-checkpoint"));
        std::fs::write(store.path(), "schema=4294967298\n").expect("write checkpoint");
        let error = store.load().expect_err("overflow schema must be rejected");
        assert!(matches!(error, AcxError::Checkpoint(_)));
        assert!(error.to_string().contains("invalid schema"));
    }

    #[test]
    fn lock_prevents_second_writer() {
        let temp = TempDir::new("lock");
        let store = CheckpointStore::new(temp.join("run.acx-checkpoint"));
        let _lock = store.lock().expect("first lock");
        assert!(store.lock().is_err());
    }
}
