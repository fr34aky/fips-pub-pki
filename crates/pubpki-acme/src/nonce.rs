//! Replay protection (RFC 8555 §6.5): every POST carries a nonce the
//! server issued and consumes once. In memory; a restart costs a client
//! one `badNonce` retry, which every client does.

use base64::Engine;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct NoncePool {
    live: HashMap<String, u64>,
    ttl: u64,
    cap: usize,
}

impl NoncePool {
    pub fn new(ttl: u64, cap: usize) -> Self {
        Self {
            live: HashMap::new(),
            ttl,
            cap: cap.max(1),
        }
    }

    /// A fresh nonce from `random`, valid `ttl` seconds from `now`.
    /// Expired nonces are dropped; past `cap`, the oldest go first.
    pub fn issue(&mut self, now: u64, random: [u8; 16]) -> String {
        self.live.retain(|_, issued| *issued + self.ttl > now);
        while self.live.len() >= self.cap {
            let oldest = self
                .live
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(n, _)| n.clone());
            match oldest {
                Some(n) => {
                    self.live.remove(&n);
                }
                None => break,
            }
        }
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
        self.live.insert(nonce.clone(), now);
        nonce
    }

    /// Single use: `true` once for a live nonce, never again.
    pub fn consume(&mut self, nonce: &str, now: u64) -> bool {
        match self.live.remove(nonce) {
            Some(issued) => issued + self.ttl > now,
            None => false,
        }
    }

    pub fn len(&self) -> usize {
        self.live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_use_ttl_and_cap() {
        let mut pool = NoncePool::new(100, 3);
        let a = pool.issue(1000, [1; 16]);
        let b = pool.issue(1001, [2; 16]);
        assert_ne!(a, b);
        assert!(pool.consume(&a, 1050));
        assert!(!pool.consume(&a, 1050), "once");
        assert!(!pool.consume("made-up", 1050));
        assert!(!pool.consume(&b, 1200), "expired");
        let c = pool.issue(1300, [3; 16]);
        let d = pool.issue(1301, [4; 16]);
        let e = pool.issue(1302, [5; 16]);
        let f = pool.issue(1303, [6; 16]);
        assert_eq!(pool.len(), 3);
        assert!(!pool.consume(&c, 1310), "the oldest went past the cap");
        assert!(pool.consume(&d, 1310) && pool.consume(&e, 1310) && pool.consume(&f, 1310));
        assert!(pool.is_empty());
    }
}
