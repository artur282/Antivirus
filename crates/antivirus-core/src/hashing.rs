use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

const READ_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct HashedFile {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug)]
pub(crate) enum HashError {
    /// Regular-file contract not met: symlink, directory, socket, etc.
    Skipped,
    Failed(String),
}

/// Computes MD5, SHA1 and SHA256 in a single pass over the file contents.
pub(crate) fn hash_file(path: &Path) -> std::result::Result<HashedFile, HashError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| HashError::Failed(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HashError::Skipped);
    }

    let mut file = File::open(path).map_err(|error| HashError::Failed(error.to_string()))?;
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut buffer = vec![0_u8; READ_BUFFER_SIZE];

    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| HashError::Failed(error.to_string()))?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
    }

    Ok(HashedFile {
        md5: hex::encode(md5.finalize()),
        sha1: hex::encode(sha1.finalize()),
        sha256: hex::encode(sha256.finalize()),
        size: metadata.len(),
    })
}
