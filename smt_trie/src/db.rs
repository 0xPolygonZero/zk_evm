use std::collections::HashMap;

use serde::{Serialize, Deserialize};

use crate::smt::{Key, Node};

pub trait Db: Default {
    fn get_node(&self, key: &Key) -> Option<&Node>;
    fn set_node(&mut self, key: Key, value: Node);
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryDb {
    pub db: HashMap<Key, Node>,
}

impl Db for MemoryDb {
    fn get_node(&self, key: &Key) -> Option<&Node> {
        self.db.get(key)
    }

    fn set_node(&mut self, key: Key, value: Node) {
        self.db.insert(key, value);
    }
}
