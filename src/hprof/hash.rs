//! Fast hashing: a stateless FxHash-style hasher for every `u64`-keyed map.
//!
//! A type alias of the same name shadows `std::collections::HashMap`, so a module that writes
//! `use super::hash::HashMap;` needs no signature or call-site change. Lookups on id keys are about an
//! order of magnitude cheaper than the default SipHash, and the iteration order is fixed within a build,
//! which removes the `RandomState` drift that would otherwise reorder observable output between runs.

use std::collections::HashMap as StdMap;
use std::hash::BuildHasherDefault;

#[derive(Default)]
pub(crate) struct FxHasher {
    hash: u64,
}

const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

impl FxHasher {
    #[inline]
    fn add(&mut self, i: u64) {
        self.hash = (self.hash.rotate_left(5) ^ i).wrapping_mul(SEED);
    }
}

impl std::hash::Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            self.add(u64::from_le_bytes(buf));
        }
    }
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i);
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }
    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

/// The Fx-hashed HashMap: same name and generics as std's, different default `BuildHasher`.
pub(crate) type HashMap<K, V, S = BuildHasherDefault<FxHasher>> = StdMap<K, V, S>;

/// Builds an Fx-hashed map. The alias's default parameter does not reach `HashMap::new()`.
#[allow(clippy::new_without_default)]
pub(crate) fn new_map<K, V>() -> HashMap<K, V> {
    StdMap::with_hasher(BuildHasherDefault::default())
}
