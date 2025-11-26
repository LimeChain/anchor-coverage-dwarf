use std::{
    env::current_dir,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

pub trait StripCurrentDir {
    fn strip_current_dir(&self) -> &Self;
}

impl StripCurrentDir for Path {
    fn strip_current_dir(&self) -> &Self {
        let Ok(current_dir) = current_dir() else {
            return self;
        };
        self.strip_prefix(current_dir).unwrap_or(self)
    }
}

pub fn find_files_with_extension(dirs: &[PathBuf], extension: &str) -> Vec<PathBuf> {
    let mut so_files = Vec::new();

    for dir in dirs {
        if dir.is_dir()
            && let Ok(entries) = std::fs::read_dir(dir)
        {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().is_some_and(|ext| ext == extension) {
                    so_files.push(path);
                }
            }
        }
    }

    so_files
}

pub fn compute_hash(slice: &[u8]) -> String {
    hex::encode(Sha256::digest(slice).as_slice())
}
