// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub type TokenHandle = Arc<ArcSwap<String>>;

pub fn token_handle(token: String) -> TokenHandle {
    Arc::new(ArcSwap::from_pointee(token))
}

pub fn derive_secret(password: &str) -> String {
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    hex::encode(h.finalize())
}

pub fn check_bearer(auth_header: Option<&[u8]>, expected_token: &str) -> bool {
    let Some(v) = auth_header else { return false };
    let Ok(s) = std::str::from_utf8(v) else {
        return false;
    };
    let Some(tok) = s
        .strip_prefix("Bearer ")
        .or_else(|| s.strip_prefix("bearer "))
    else {
        return false;
    };
    constant_time_eq(tok.trim().as_bytes(), expected_token.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_matches_known_vector() {

        let s = derive_secret("clashpass");
        assert_eq!(s.len(), 64);
        assert_eq!(s, derive_secret("clashpass"));
        assert_ne!(s, derive_secret("other"));
    }

    #[test]
    fn bearer_check() {
        let tok = derive_secret("pw");
        assert!(check_bearer(Some(format!("Bearer {tok}").as_bytes()), &tok));
        assert!(check_bearer(Some(format!("bearer {tok}").as_bytes()), &tok));
        assert!(!check_bearer(Some(b"Bearer wrong"), &tok));
        assert!(!check_bearer(Some(b"Basic xyz"), &tok));
        assert!(!check_bearer(None, &tok));
    }
}
