// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Candidate encoding variants and the validation-stage wrapper.
//!
//! Candidate sources emit UTF-8 text (dictionaries are decoded to UTF-8;
//! mask/brute/hybrid positions are ASCII). Some archive formats expect a
//! different byte representation for the password, so the same candidate may
//! need to be tried as UTF-8, GBK, CP437, or the Windows OEM code page.
//!
//! Variants are expanded **inside the session**, never in the candidate source:
//! the global candidate index (and therefore the checkpoint watermark) must
//! keep pointing at the same logical candidate. A candidate is complete only
//! after every applicable variant has been tested.

use crate::archive::{
    ArchiveFormat, ArchiveInfo, ArchiveSession, ArchiveSessionFactory, ArchiveStats, PasswordTest,
};
use crate::engines::external::CancelToken;
use crate::error::{AcxError, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// One byte representation of a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingVariant {
    Utf8,
    Gbk,
    Cp437,
    Oem,
}

impl EncodingVariant {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Utf8 => "utf8",
            Self::Gbk => "gbk",
            Self::Cp437 => "cp437",
            Self::Oem => "oem",
        }
    }
}

/// CLI/manifest encoding selection, before the archive format is known.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum EncodingSelection {
    #[default]
    Auto,
    Explicit(Vec<EncodingVariant>),
}

impl EncodingSelection {
    /// Parse `auto` or a comma/space separated list such as `utf8,gbk`.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() || spec.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        let mut variants = Vec::new();
        for token in spec
            .split(['|', ',', ' '])
            .filter(|token| !token.is_empty())
        {
            let variant = match token.to_ascii_lowercase().as_str() {
                "utf8" | "utf-8" => EncodingVariant::Utf8,
                "gbk" | "gb18030" => EncodingVariant::Gbk,
                "cp437" => EncodingVariant::Cp437,
                "oem" => EncodingVariant::Oem,
                "auto" => {
                    return Err(AcxError::Attack(
                        "`auto` cannot be combined with explicit encoding variants".to_string(),
                    ))
                }
                other => {
                    return Err(AcxError::Attack(format!(
                        "unknown encoding variant `{other}` (expected auto, utf8, gbk, cp437, oem)"
                    )))
                }
            };
            if !variants.contains(&variant) {
                variants.push(variant);
            }
        }
        if variants.is_empty() {
            return Err(AcxError::Attack(
                "encoding variant list is empty".to_string(),
            ));
        }
        Ok(Self::Explicit(variants))
    }

    pub fn is_auto(&self) -> bool {
        matches!(self, Self::Auto)
    }

    /// Resolve against the archive format. Engine-internal conversions are not
    /// duplicated here: 7z converts UTF-8 to UTF-16LE internally, and the
    /// external RAR path converts UTF-8 to the OEM code page itself.
    pub fn resolve(&self, format: ArchiveFormat) -> Result<EncodingPlan> {
        match self {
            Self::Auto => Ok(EncodingPlan {
                format,
                variants: auto_variants(format),
                explicit: false,
            }),
            Self::Explicit(variants) => {
                for variant in variants {
                    if !variant_supported(format, *variant) {
                        return Err(AcxError::Attack(format!(
                            "encoding variant `{}` is not supported for {}; the engine handles that conversion internally",
                            variant.as_str(),
                            format.as_str()
                        )));
                    }
                }
                Ok(EncodingPlan {
                    format,
                    variants: variants.clone(),
                    explicit: true,
                })
            }
        }
    }
}

fn auto_variants(format: ArchiveFormat) -> Vec<EncodingVariant> {
    match format {
        ArchiveFormat::Zip => vec![
            EncodingVariant::Utf8,
            EncodingVariant::Gbk,
            EncodingVariant::Cp437,
        ],
        ArchiveFormat::Rar4 => vec![EncodingVariant::Utf8, EncodingVariant::Oem],
        ArchiveFormat::Rar5 | ArchiveFormat::SevenZ => vec![EncodingVariant::Utf8],
    }
}

fn variant_supported(format: ArchiveFormat, variant: EncodingVariant) -> bool {
    match format {
        ArchiveFormat::Zip => true,
        // The external RAR engine converts UTF-8 to OEM itself. Accepting
        // GBK/CP437 bytes here would double-encode a password that happens to
        // be valid UTF-8, so only UTF-8 and the (internally converted) OEM
        // choice are allowed.
        ArchiveFormat::Rar4 => matches!(variant, EncodingVariant::Utf8 | EncodingVariant::Oem),
        ArchiveFormat::Rar5 | ArchiveFormat::SevenZ => variant == EncodingVariant::Utf8,
    }
}

#[derive(Debug, Clone)]
pub struct EncodingPlan {
    format: ArchiveFormat,
    variants: Vec<EncodingVariant>,
    explicit: bool,
}

impl EncodingPlan {
    pub fn variants(&self) -> &[EncodingVariant] {
        &self.variants
    }

    pub fn max_variants(&self) -> usize {
        self.variants.len()
    }

    /// Signature label: `auto` (format-derived) or the explicit list.
    pub fn signature_label(&self) -> String {
        if self.explicit {
            self.variants
                .iter()
                .map(|variant| variant.as_str())
                .collect::<Vec<_>>()
                .join(",")
        } else {
            "auto".to_string()
        }
    }

    /// Encode one candidate into every applicable, de-duplicated representation.
    /// Unrepresentable variants are skipped.
    pub fn encode(&self, candidate: &[u8]) -> Vec<Vec<u8>> {
        self.encode_with_skips(candidate).0
    }

    /// Like [`Self::encode`], also returning how many variants were skipped as
    /// unrepresentable (for `--report-stats`).
    pub fn encode_with_skips(&self, candidate: &[u8]) -> (Vec<Vec<u8>>, usize) {
        let mut output: Vec<Vec<u8>> = Vec::with_capacity(self.variants.len());
        let mut skipped = 0usize;
        for variant in &self.variants {
            match encode_variant(candidate, *variant, self.format) {
                Some(bytes) => {
                    if !output.iter().any(|existing| existing == &bytes) {
                        output.push(bytes);
                    }
                }
                None => skipped += 1,
            }
        }
        (output, skipped)
    }
}

fn encode_variant(
    candidate: &[u8],
    variant: EncodingVariant,
    format: ArchiveFormat,
) -> Option<Vec<u8>> {
    match variant {
        EncodingVariant::Utf8 => {
            // A 7z password is UTF-16 internally. If a caller supplied raw
            // GBK bytes (for example a password reused from a ZIP job), decode
            // them to UTF-8 first instead of always returning a miss.
            if matches!(format, ArchiveFormat::SevenZ) && std::str::from_utf8(candidate).is_err() {
                let (decoded, had_errors) = encoding_rs::GBK.decode_without_bom_handling(candidate);
                if !had_errors && !decoded.is_empty() {
                    return Some(decoded.into_owned().into_bytes());
                }
            }
            Some(candidate.to_vec())
        }
        EncodingVariant::Gbk => {
            let text = std::str::from_utf8(candidate).ok()?;
            let (encoded, _, had_errors) = encoding_rs::GBK.encode(text);
            if had_errors {
                return None;
            }
            Some(encoded.into_owned())
        }
        EncodingVariant::Cp437 => {
            let text = std::str::from_utf8(candidate).ok()?;
            encode_cp437(text)
        }
        EncodingVariant::Oem => {
            let text = std::str::from_utf8(candidate).ok()?;
            // RAR4 already asks the external engine to convert UTF-8 to OEM;
            // an explicit `oem` variant would double-encode. Keep the candidate
            // as UTF-8 and let the engine do it.
            if matches!(format, ArchiveFormat::Rar4) {
                return Some(candidate.to_vec());
            }
            encode_oem(text)
        }
    }
}

/// CP437 high half (0x80..=0xFF), in code-point order.
const CP437_HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";

fn encode_cp437(text: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(text.len());
    for character in text.chars() {
        if character.is_ascii() {
            output.push(character as u8);
            continue;
        }
        let index = CP437_HIGH
            .chars()
            .position(|candidate| candidate == character)?;
        output.push(0x80 + index as u8);
    }
    Some(output)
}

#[cfg(windows)]
fn encode_oem(text: &str) -> Option<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Globalization::{GetOEMCP, WideCharToMultiByte, WC_NO_BEST_FIT_CHARS};

    // SAFETY: `GetOEMCP` has no preconditions.
    let code_page = unsafe { GetOEMCP() };
    if code_page == 65001 {
        return Some(text.as_bytes().to_vec());
    }
    let wide: Vec<u16> = text.encode_utf16().collect();
    if wide.is_empty() {
        return Some(Vec::new());
    }
    let wide_len = i32::try_from(wide.len()).ok()?;
    let mut used_default = 0i32;
    // SAFETY: valid UTF-16 slice and writable BOOL; output pointer is null for
    // the size query.
    let needed = unsafe {
        WideCharToMultiByte(
            code_page,
            WC_NO_BEST_FIT_CHARS,
            wide.as_ptr(),
            wide_len,
            null_mut(),
            0,
            null(),
            &mut used_default,
        )
    };
    if needed <= 0 {
        return None;
    }
    let mut output = vec![0u8; needed as usize];
    // SAFETY: `output` has exactly `needed` bytes; input/BOOL pointers valid.
    let written = unsafe {
        WideCharToMultiByte(
            code_page,
            WC_NO_BEST_FIT_CHARS,
            wide.as_ptr(),
            wide_len,
            output.as_mut_ptr(),
            needed,
            null(),
            &mut used_default,
        )
    };
    if written != needed || used_default != 0 {
        return None;
    }
    Some(output)
}

#[cfg(not(windows))]
fn encode_oem(text: &str) -> Option<Vec<u8>> {
    // No portable OEM code page exists; CP437 is the closest stable fallback.
    encode_cp437(text)
}

/// Shared counters for one job.
#[derive(Debug, Default)]
pub struct EncodingCounters {
    candidates: AtomicU64,
    attempts: AtomicU64,
    skipped: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EncodingStats {
    pub candidates: u64,
    pub attempts: u64,
    pub variants_skipped: u64,
}

impl EncodingCounters {
    pub fn snapshot(&self) -> EncodingStats {
        EncodingStats {
            candidates: self.candidates.load(Ordering::SeqCst),
            attempts: self.attempts.load(Ordering::SeqCst),
            variants_skipped: self.skipped.load(Ordering::SeqCst),
        }
    }
}

pub struct EncodingFactory {
    inner: Arc<dyn ArchiveSessionFactory>,
    plan: EncodingPlan,
    counters: Arc<EncodingCounters>,
}

impl EncodingFactory {
    pub fn new(
        inner: Arc<dyn ArchiveSessionFactory>,
        plan: EncodingPlan,
        counters: Arc<EncodingCounters>,
    ) -> Self {
        Self {
            inner,
            plan,
            counters,
        }
    }
}

impl ArchiveSessionFactory for EncodingFactory {
    fn open(&self) -> Result<Box<dyn ArchiveSession>> {
        Ok(Box::new(EncodingSession {
            inner: self.inner.open()?,
            plan: self.plan.clone(),
            counters: Arc::clone(&self.counters),
        }))
    }

    fn stats(&self) -> ArchiveStats {
        self.inner.stats()
    }
}

struct EncodingSession {
    inner: Box<dyn ArchiveSession>,
    plan: EncodingPlan,
    counters: Arc<EncodingCounters>,
}

impl ArchiveSession for EncodingSession {
    fn info(&self) -> &ArchiveInfo {
        self.inner.info()
    }

    fn test_password(&mut self, password: &[u8]) -> Result<PasswordTest> {
        self.counters.candidates.fetch_add(1, Ordering::Relaxed);
        let (variants, skipped) = self.plan.encode_with_skips(password);
        if skipped > 0 {
            self.counters
                .skipped
                .fetch_add(skipped as u64, Ordering::Relaxed);
        }
        if variants.is_empty() {
            return Ok(PasswordTest::Miss);
        }
        for variant in variants {
            self.counters.attempts.fetch_add(1, Ordering::Relaxed);
            let result = self.inner.test_password(&variant)?;
            if self.inner.was_variant_skipped() {
                // An engine-level encoding skip is a skipped variant, not an
                // attempt. `job_stats` folds `ArchiveStats::encoding_skipped`
                // into variants_skipped, so undo the attempt here to keep
                // attempts = fast_rejected + full_attempted (W2-007 §4.4).
                self.counters.attempts.fetch_sub(1, Ordering::Relaxed);
                continue;
            }
            if result == PasswordTest::Hit {
                return Ok(PasswordTest::Hit);
            }
        }
        Ok(PasswordTest::Miss)
    }

    fn set_cancel_token(&mut self, token: CancelToken) {
        self.inner.set_cancel_token(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cp437_table_has_128_entries() {
        assert_eq!(CP437_HIGH.chars().count(), 128);
    }

    #[test]
    fn ascii_variants_dedupe() {
        let plan = EncodingSelection::Auto
            .resolve(ArchiveFormat::Zip)
            .expect("plan");
        let encoded = plan.encode(b"P@ss");
        assert_eq!(encoded, vec![b"P@ss".to_vec()]);
        assert_eq!(plan.max_variants(), 3);
    }

    #[test]
    fn encodes_gbk_and_cp437() {
        let plan = EncodingSelection::parse("utf8,gbk,cp437")
            .expect("parse")
            .resolve(ArchiveFormat::Zip)
            .expect("plan");
        let encoded = plan.encode("中文".as_bytes());
        assert_eq!(encoded[0], "中文".as_bytes());
        assert_eq!(encoded[1], encoding_rs::GBK.encode("中文").0.as_ref());
        // CP437 cannot represent Chinese: that variant is skipped.
        assert_eq!(encoded.len(), 2);

        let accented = plan.encode("café".as_bytes());
        assert_eq!(accented.len(), 3);
        assert_eq!(accented[2], vec![b'c', b'a', b'f', 0x82]);
    }

    #[test]
    fn sevenz_decodes_raw_gbk_candidate_to_utf8() {
        let (gbk, _, had_errors) = encoding_rs::GBK.encode("中文密码");
        assert!(!had_errors);
        let plan = EncodingSelection::Auto
            .resolve(ArchiveFormat::SevenZ)
            .expect("plan");
        let (encoded, skipped) = plan.encode_with_skips(gbk.as_ref());
        assert_eq!(encoded, vec!["中文密码".as_bytes().to_vec()]);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn explicit_variant_rejects_engine_internal_formats() {
        let selection = EncodingSelection::parse("gbk").expect("parse");
        assert!(selection.resolve(ArchiveFormat::Rar5).is_err());
        assert!(selection.resolve(ArchiveFormat::SevenZ).is_err());
        assert!(selection.resolve(ArchiveFormat::Rar4).is_err());
        assert!(selection.resolve(ArchiveFormat::Zip).is_ok());
        assert!(EncodingSelection::parse("oem")
            .expect("parse")
            .resolve(ArchiveFormat::Rar4)
            .is_ok());
        assert!(EncodingSelection::parse("utf8")
            .expect("parse")
            .resolve(ArchiveFormat::Rar4)
            .is_ok());
    }

    #[test]
    fn auto_plan_per_format() {
        assert_eq!(
            EncodingSelection::Auto
                .resolve(ArchiveFormat::Zip)
                .expect("zip")
                .max_variants(),
            3
        );
        assert_eq!(
            EncodingSelection::Auto
                .resolve(ArchiveFormat::Rar4)
                .expect("rar4")
                .max_variants(),
            2
        );
        assert_eq!(
            EncodingSelection::Auto
                .resolve(ArchiveFormat::SevenZ)
                .expect("7z")
                .max_variants(),
            1
        );
    }

    struct SkipSession {
        info: ArchiveInfo,
        skipped: bool,
    }

    impl ArchiveSession for SkipSession {
        fn info(&self) -> &ArchiveInfo {
            &self.info
        }

        fn test_password(&mut self, _password: &[u8]) -> Result<PasswordTest> {
            self.skipped = true;
            Ok(PasswordTest::Miss)
        }

        fn was_variant_skipped(&self) -> bool {
            self.skipped
        }
    }

    struct SkipFactory;

    impl ArchiveSessionFactory for SkipFactory {
        fn open(&self) -> Result<Box<dyn ArchiveSession>> {
            Ok(Box::new(SkipSession {
                info: ArchiveInfo {
                    path: std::path::PathBuf::from("stub.rar"),
                    format: ArchiveFormat::Rar5,
                    encryption: crate::archive::Encryption::Rar,
                    selected: None,
                    whole_archive: true,
                    header_encrypted: false,
                    entries: Vec::new(),
                },
                skipped: false,
            }))
        }

        fn stats(&self) -> ArchiveStats {
            ArchiveStats {
                encoding_skipped: 1,
                ..Default::default()
            }
        }
    }

    #[test]
    fn engine_level_encoding_skip_is_not_an_attempt() {
        let counters = Arc::new(EncodingCounters::default());
        let plan = EncodingPlan {
            format: ArchiveFormat::Rar5,
            variants: vec![EncodingVariant::Utf8],
            explicit: false,
        };
        let factory = EncodingFactory::new(Arc::new(SkipFactory), plan, Arc::clone(&counters));
        let mut session = factory.open().expect("session");

        assert_eq!(
            session.test_password(b"candidate").expect("miss"),
            PasswordTest::Miss
        );
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.candidates, 1);
        assert_eq!(
            snapshot.attempts, 0,
            "an engine-level encoding skip must not enter attempts"
        );
        assert_eq!(factory.stats().encoding_skipped, 1);
    }
}
