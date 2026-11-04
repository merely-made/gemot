//! Reviewed effects over immutable bytes. Preparation never connects; sending
//! consumes the review and never follows a redirect or retries an upload.
use crate::{MAX_PAGE_BYTES, read_bounded};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

static TRUST_READY: AtomicBool = AtomicBool::new(false);

struct FileTrust {
    path: PathBuf,
}
impl FileTrust {
    fn read(&self) -> Result<BTreeMap<String, [u8; 32]>, String> {
        if !self.path.try_exists().map_err(|e| e.to_string())? {
            return Ok(BTreeMap::new());
        }
        serde_json::from_slice(&read_bounded(&self.path, MAX_PAGE_BYTES)?)
            .map_err(|e| e.to_string())
    }
}
impl gemini_protocol::TofuStore for FileTrust {
    fn fingerprint(&self, target: &str) -> Option<[u8; 32]> {
        self.read().ok()?.get(target).copied()
    }
    fn pin(&self, target: &str, fingerprint: [u8; 32]) {
        let _ = self.try_pin(target, fingerprint);
    }
    fn try_pin(&self, target: &str, fingerprint: [u8; 32]) -> Result<(), String> {
        use std::io::Write;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.path.with_extension("lock"))
            .map_err(|e| e.to_string())?;
        lock.lock().map_err(|e| e.to_string())?;
        let mut pins = self.read()?;
        if let Some(old) = pins.get(target) {
            return if old == &fingerprint {
                Ok(())
            } else {
                Err("Capsule certificate changed; upload refused".into())
            };
        }
        pins.insert(target.into(), fingerprint);
        let mut temp =
            tempfile::NamedTempFile::new_in(self.path.parent().ok_or("Trust path has no parent")?)
                .map_err(|e| e.to_string())?;
        temp.write_all(&serde_json::to_vec_pretty(&pins).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        temp.as_file().sync_all().map_err(|e| e.to_string())?;
        temp.persist(&self.path).map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Call once at host startup with its configured trust-record path. Certificates
/// are pinned on first contact; subsequent changes refuse uploads before bytes.
pub fn initialize_submission_trust(path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or("Trust path has no parent")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let store = FileTrust {
        path: path.to_path_buf(),
    };
    store.read()?;
    gemini_protocol::set_trust_store(Arc::new(store));
    TRUST_READY.store(true, Ordering::Release);
    Ok(())
}

pub struct PreparedSubmission {
    target: url::Url,
    mime: String,
    bytes: Vec<u8>,
}

pub struct SubmissionReceipt {
    pub code: u8,
    pub meta: String,
    pub body: Vec<u8>,
}

impl PreparedSubmission {
    pub fn from_saved_file(path: &Path, target: &str, mime: &str) -> Result<Self, String> {
        if !path.is_file() {
            return Err("Select a saved ordinary file".into());
        }
        Self::from_body(target, mime, read_bounded(path, MAX_PAGE_BYTES)?)
    }
    pub fn from_body(target: &str, mime: &str, bytes: Vec<u8>) -> Result<Self, String> {
        let target = url::Url::parse(target).map_err(|e| e.to_string())?;
        if !matches!(target.scheme(), "titan" | "spartan")
            || target.host_str().is_none()
            || !target.username().is_empty()
            || target.password().is_some()
            || target.fragment().is_some()
            || target.query().is_some()
            || (target.scheme() == "titan" && target.path().contains(';'))
        {
            return Err(
                "Use a Titan or Spartan endpoint without credentials, query or fragment".into(),
            );
        }
        if bytes.len() > MAX_PAGE_BYTES {
            return Err("Submission exceeds 1 MiB".into());
        }
        if mime.is_empty() || mime.len() > 256 || mime.chars().any(char::is_control) {
            return Err("A bounded MIME type is required".into());
        }
        if target.scheme() == "titan"
            && !mime
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b';')
        {
            return Err(
                "This Titan adapter requires a MIME type without whitespace or parameters".into(),
            );
        }
        Ok(Self {
            target,
            mime: mime.into(),
            bytes,
        })
    }
    pub fn target(&self) -> &str {
        self.target.as_str()
    }
    pub fn mime(&self) -> &str {
        &self.mime
    }
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }
    pub fn digest(&self) -> String {
        blake3::hash(&self.bytes).to_hex().to_string()
    }
    pub fn body(&self) -> &[u8] {
        &self.bytes
    }

    /// One explicit send. Errors after connecting can mean an unknown remote
    /// outcome; callers must not automatically resend.
    pub async fn send(self, token: Option<String>) -> Result<SubmissionReceipt, String> {
        let operation = async {
            if self.target.scheme() == "titan" {
                if !TRUST_READY.load(Ordering::Acquire) {
                    return Err("Upload certificate trust store is unavailable".into());
                }
                let response = gemini_protocol::titan::upload(
                    &self.target,
                    &self.bytes,
                    &self.mime,
                    token.as_deref(),
                )
                .await
                .map_err(|e| e.to_string())?;
                Ok(SubmissionReceipt {
                    code: response.code,
                    meta: response.meta,
                    body: response.body,
                })
            } else {
                if token.is_some() {
                    return Err("Spartan has no Titan token field".into());
                }
                let options = spartan_protocol::FetchOptions {
                    max_body: MAX_PAGE_BYTES,
                    timeout: Duration::from_secs(15),
                    ..Default::default()
                };
                let response =
                    spartan_protocol::submit(self.target.as_str(), &self.bytes, &options)
                        .await
                        .map_err(|e| e.to_string())?;
                Ok(SubmissionReceipt {
                    code: response.status.code(),
                    meta: response.meta,
                    body: response.body,
                })
            }
        };
        tokio::time::timeout(Duration::from_secs(30), operation)
            .await
            .map_err(|_| {
                "Submission timed out; remote outcome may be unknown. Review before retrying"
                    .to_string()
            })?
    }
}
