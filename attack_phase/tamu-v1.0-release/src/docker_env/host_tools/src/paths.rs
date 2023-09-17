use std::path::{Path, PathBuf};

pub fn package_path(path: impl AsRef<Path>) -> PathBuf {
    let mut ret = PathBuf::from("/package_dir");
    ret.push(path);
    ret
}
