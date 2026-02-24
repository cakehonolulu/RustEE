use crate::testing::GoldenState;
use std::{
    fs,
    path::{Path, PathBuf},
};

pub struct GoldenStore {
    root: PathBuf,
}

impl GoldenStore {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().join("tests").join("golden"),
        }
    }

    fn path(&self, family: &str, name: &str) -> PathBuf {
        self.root
            .join(family.to_lowercase())
            .join(format!("{name}.json"))
    }

    pub fn load(&self, family: &str, name: &str) -> Option<GoldenState> {
        let text = fs::read_to_string(self.path(family, name)).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn save(&self, family: &str, name: &str, state: &GoldenState) -> std::io::Result<()> {
        let p = self.path(family, name);
        fs::create_dir_all(p.parent().unwrap())?;
        fs::write(&p, serde_json::to_string_pretty(state).unwrap())
    }

    pub fn exists(&self, family: &str, name: &str) -> bool {
        self.path(family, name).exists()
    }
}
