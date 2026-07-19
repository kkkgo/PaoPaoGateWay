// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

#[inline]
pub fn fmix64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    h
}

#[inline]
pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[inline]
pub fn fxhash(bytes: &[u8]) -> u64 {
    const K: u64 = 0x51_7c_c1_b7_27_22_0a_95;
    let mut h = 0u64;
    let mut chunks = bytes.chunks_exact(8);
    for c in &mut chunks {
        let w = u64::from_le_bytes(c.try_into().unwrap());
        h = (h.rotate_left(5) ^ w).wrapping_mul(K);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut buf = [0u8; 8];
        buf[..rem.len()].copy_from_slice(rem);
        let w = u64::from_le_bytes(buf);
        h = (h.rotate_left(5) ^ w).wrapping_mul(K);
    }
    h
}

#[inline]
pub fn djb2(bytes: &[u8]) -> u64 {
    let mut h = 5381u64;
    for &b in bytes {
        h = (h << 5).wrapping_add(h) ^ b as u64;
    }
    h
}

#[inline]
pub fn wyhash_lite(bytes: &[u8]) -> u64 {
    const S0: u64 = 0xa0761d6478bd642f;
    const S1: u64 = 0xe7037ed1a0b428db;
    let mut seed = S0 ^ mum(S0, S1);
    let mut chunks = bytes.chunks_exact(8);
    for c in &mut chunks {
        let w = u64::from_le_bytes(c.try_into().unwrap());
        seed = mum(seed ^ S1, w ^ S0);
    }
    let rem = chunks.remainder();
    let mut buf = [0u8; 8];
    buf[..rem.len()].copy_from_slice(rem);
    let w = u64::from_le_bytes(buf);
    seed = mum(seed ^ S1, w ^ S0 ^ (bytes.len() as u64).rotate_left(32));
    mum(seed ^ S0, S1)
}

#[inline]
fn mum(a: u64, b: u64) -> u64 {
    let r = (a as u128).wrapping_mul(b as u128);
    (r as u64) ^ ((r >> 64) as u64)
}

#[inline]
fn mum128(a: u64, b: u64) -> (u64, u64) {
    let r = (a as u128).wrapping_mul(b as u128);
    (r as u64, (r >> 64) as u64)
}

#[inline]
fn read64(p: &[u8]) -> u64 {
    u64::from_le_bytes(p[..8].try_into().unwrap())
}
#[inline]
fn read32(p: &[u8]) -> u64 {
    u64::from(u32::from_le_bytes(p[..4].try_into().unwrap()))
}

const RAPID_SECRET: [u64; 8] = [
    0x2d358dccaa6c78a5,
    0x8bb84b93962eacc9,
    0x4b33a62ed433d4a3,
    0x4d5a2da51de1aa47,
    0xa0761d6478bd642f,
    0xe7037ed1a0b428db,
    0x90ed1765281c388c,
    0xaaaaaaaaaaaaaaaa,
];

pub const RAPIDHASH_SEED: u64 = 2162917476049;

#[inline]
pub fn rapidhash(key: &[u8], mut seed: u64) -> u64 {
    let s = &RAPID_SECRET;
    let len = key.len();
    seed ^= mum(seed ^ s[2], s[1]);
    let (mut a, mut b) = (0u64, 0u64);
    let mut i = len;
    if len <= 16 {
        if len >= 4 {
            seed ^= len as u64;
            if len >= 8 {
                a = read64(key);
                b = read64(&key[len - 8..]);
            } else {
                a = read32(key);
                b = read32(&key[len - 4..]);
            }
        } else if len > 0 {
            a = ((key[0] as u64) << 45) | (key[len - 1] as u64);
            b = key[len >> 1] as u64;
        }
    } else {
        let mut p = 0usize;
        if len > 112 {
            let (mut s1, mut s2, mut s3, mut s4, mut s5, mut s6) =
                (seed, seed, seed, seed, seed, seed);
            loop {
                seed = mum(read64(&key[p..]) ^ s[0], read64(&key[p + 8..]) ^ seed);
                s1 = mum(read64(&key[p + 16..]) ^ s[1], read64(&key[p + 24..]) ^ s1);
                s2 = mum(read64(&key[p + 32..]) ^ s[2], read64(&key[p + 40..]) ^ s2);
                s3 = mum(read64(&key[p + 48..]) ^ s[3], read64(&key[p + 56..]) ^ s3);
                s4 = mum(read64(&key[p + 64..]) ^ s[4], read64(&key[p + 72..]) ^ s4);
                s5 = mum(read64(&key[p + 80..]) ^ s[5], read64(&key[p + 88..]) ^ s5);
                s6 = mum(read64(&key[p + 96..]) ^ s[6], read64(&key[p + 104..]) ^ s6);
                p += 112;
                i -= 112;
                if i <= 112 {
                    break;
                }
            }
            seed ^= s1;
            s2 ^= s3;
            s4 ^= s5;
            seed ^= s6;
            s2 ^= s4;
            seed ^= s2;
        }
        if i > 16 {
            seed = mum(read64(&key[p..]) ^ s[2], read64(&key[p + 8..]) ^ seed);
            if i > 32 {
                seed = mum(read64(&key[p + 16..]) ^ s[2], read64(&key[p + 24..]) ^ seed);
                if i > 48 {
                    seed = mum(read64(&key[p + 32..]) ^ s[1], read64(&key[p + 40..]) ^ seed);
                    if i > 64 {
                        seed = mum(read64(&key[p + 48..]) ^ s[1], read64(&key[p + 56..]) ^ seed);
                        if i > 80 {
                            seed =
                                mum(read64(&key[p + 64..]) ^ s[2], read64(&key[p + 72..]) ^ seed);
                            if i > 96 {
                                seed = mum(
                                    read64(&key[p + 80..]) ^ s[1],
                                    read64(&key[p + 88..]) ^ seed,
                                );
                            }
                        }
                    }
                }
            }
        }
        a = read64(&key[p + i - 16..]) ^ (i as u64);
        b = read64(&key[p + i - 8..]);
    }
    a ^= s[1];
    b ^= seed;
    let (a2, b2) = mum128(a, b);
    mum(a2 ^ s[7], b2 ^ s[1] ^ (i as u64))
}

#[inline]
pub fn fastrange(h: u64, n: u32) -> u32 {
    (((h as u128).wrapping_mul(n as u128)) >> 64) as u32
}

#[inline]
pub fn probe_step(h: u64, n: u32) -> u32 {
    if n <= 1 {
        return 1;
    }
    1 + fastrange(fmix64(h ^ 0x9e3779b97f4a7c15), n - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_input_same_output() {
        for f in [fnv1a, fxhash, djb2, wyhash_lite] {
            assert_eq!(f(b"google.com"), f(b"google.com"));
            assert_ne!(f(b"google.com"), f(b"facebook.com"));
        }

        assert_eq!(
            rapidhash(b"google.com", RAPIDHASH_SEED),
            rapidhash(b"google.com", RAPIDHASH_SEED)
        );
        assert_ne!(
            rapidhash(b"google.com", RAPIDHASH_SEED),
            rapidhash(b"facebook.com", RAPIDHASH_SEED)
        );
        assert_ne!(rapidhash(b"google.com", 0), rapidhash(b"google.com", 1));
    }

    #[test]
    fn rapidhash_matches_c_reference() {

        let refs: &[(&[u8], u64)] = &[
            (b"google.com", 0x459b_11a5_4d9a_0a40),
            (b"gstatic.com", 0x6945_240c_9fc0_a510),
            (b"www.google.com", 0x6d93_4651_8cf8_3511),
            (b"events.data.microsoft.com", 0x4b91_7a00_9fb5_307c),
            (b"a", 0x599f_47df_33a2_e1eb),
            (b"abcd", 0xf8f4_4f4a_65e2_6132),
            (b"abcdefg", 0x2760_e841_11b2_9a0d),
            (b"login.microsoftonline.com", 0x8aae_b2c8_9386_2ad1),
        ];
        for (k, h) in refs {
            assert_eq!(
                rapidhash(k, 0),
                *h,
                "rapidhash port mismatch for {:?}",
                std::str::from_utf8(k)
            );
        }
    }

    #[test]
    fn fastrange_in_bounds() {
        for n in [1u32, 2, 3, 100, 65536, 16_777_212, u32::MAX] {
            for h in [0u64, 1, u64::MAX, 0x1234_5678_9abc_def0] {
                assert!(fastrange(h, n) < n, "fastrange({h:#x},{n}) out of range");
            }
        }
    }

    #[test]
    fn fastrange_covers_low_and_high() {

        assert_eq!(fastrange(0, 1000), 0);
        assert_eq!(fastrange(u64::MAX, 1000), 999);
    }

    #[test]
    fn probe_step_in_range() {
        for n in [2u32, 3, 100, 65536] {
            for h in [0u64, 7, u64::MAX] {
                let s = probe_step(h, n);
                assert!((1..n).contains(&s), "step {s} out of [1,{n})");
            }
        }
    }

    #[test]
    fn fmix64_avalanche_changes_bits() {

        let a = fmix64(0);
        let b = fmix64(1);
        assert!(
            (a ^ b).count_ones() >= 16,
            "weak avalanche: {a:#x} vs {b:#x}"
        );
    }
}
