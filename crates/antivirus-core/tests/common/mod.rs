#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use antivirus_core::Core;
use rusqlite::Connection;

pub const HELLO_MD5: &str = "5d41402abc4b2a76b9719d911017c592";
pub const HELLO_SHA1: &str = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
pub const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

pub const WORLD_MD5: &str = "7d793037a0760186574b0282f2f435e7";
pub const WORLD_SHA1: &str = "7c211433f02071597741e6ff5a8ea34789abbf43";
pub const WORLD_SHA256: &str = "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7";

pub fn temp_dir() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("temporary directory")
}

pub fn write_file(path: &Path, bytes: &[u8]) -> PathBuf {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent directory");
    }
    fs::write(path, bytes).expect("write fixture file");
    path.to_path_buf()
}

pub fn create_signatures(path: &Path, md5: &[&str], sha1: &[&str], sha256: &[&str]) -> PathBuf {
    let connection = Connection::open(path).expect("open signatures db");
    connection
        .execute_batch(
            "CREATE TABLE virus_md5 (md5_hash TEXT NOT NULL);
             CREATE TABLE virus_sha1 (sha1_hash TEXT NOT NULL);
             CREATE TABLE virus_sha256 (sha256_hash TEXT NOT NULL);",
        )
        .expect("create signatures schema");
    for hash in md5 {
        connection
            .execute("INSERT INTO virus_md5 (md5_hash) VALUES (?1)", [hash])
            .expect("insert md5");
    }
    for hash in sha1 {
        connection
            .execute("INSERT INTO virus_sha1 (sha1_hash) VALUES (?1)", [hash])
            .expect("insert sha1");
    }
    for hash in sha256 {
        connection
            .execute("INSERT INTO virus_sha256 (sha256_hash) VALUES (?1)", [hash])
            .expect("insert sha256");
    }
    path.to_path_buf()
}

pub fn make_core(app_data_dir: &Path, signatures: Option<&Path>) -> Core {
    let candidates = signatures
        .map(|path| vec![path.to_path_buf()])
        .unwrap_or_default();
    Core::new(app_data_dir, candidates).expect("create core")
}

pub fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
