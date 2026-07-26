// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::io;
use std::os::fd::{AsRawFd, RawFd};

const SIOCETHTOOL: u32 = 0x8946;
const ETHTOOL_GLINKSETTINGS: u32 = 0x0000_004c;
const ETHTOOL_SLINKSETTINGS: u32 = 0x0000_004d;
const AUTONEG_ENABLE: u8 = 1;

const MAX_NWORDS: usize = 8;

const NON_SPEED_BITS: &[u32] = &[
    6,
    7,
    8,
    9,
    10,
    11,
    13,
    14,
    16,
    20,
    49,
    50,
    51,
    74,
];

const MODE_NAMES: &[(u32, &str)] = &[
    (0, "10baseT/Half"),
    (1, "10baseT/Full"),
    (2, "100baseT/Half"),
    (3, "100baseT/Full"),
    (4, "1000baseT/Half"),
    (5, "1000baseT/Full"),
    (12, "10000baseT/Full"),
    (15, "2500baseX/Full"),
    (41, "1000baseX/Full"),
    (47, "2500baseT/Full"),
    (48, "5000baseT/Full"),
    (67, "100baseT1/Full"),
    (68, "1000baseT1/Full"),
    (90, "100baseFX/Half"),
    (91, "100baseFX/Full"),
    (92, "10baseT1L/Full"),
];

#[repr(C)]
#[derive(Clone, Copy)]
struct LinkSettings {
    cmd: u32,
    speed: u32,
    duplex: u8,
    port: u8,
    phy_address: u8,
    autoneg: u8,
    mdio_support: u8,
    eth_tp_mdix: u8,
    eth_tp_mdix_ctrl: u8,
    link_mode_masks_nwords: i8,
    transceiver: u8,
    master_slave_cfg: u8,
    master_slave_state: u8,
    rate_matching: u8,
    reserved: [u32; 7],
    masks: [u32; 3 * MAX_NWORDS],
}

const _: () = assert!(std::mem::offset_of!(LinkSettings, masks) == 48);

impl LinkSettings {
    fn zeroed() -> Self {

        unsafe { std::mem::zeroed() }
    }

    fn nwords(&self) -> usize {
        self.link_mode_masks_nwords.max(0) as usize
    }

    fn supported(&self) -> &[u32] {
        &self.masks[..self.nwords()]
    }

    fn advertising(&self) -> &[u32] {
        let n = self.nwords();
        &self.masks[n..2 * n]
    }

    fn set_advertising(&mut self, adv: &[u32]) {
        let n = self.nwords().min(adv.len());
        let base = self.nwords();
        self.masks[base..base + n].copy_from_slice(&adv[..n]);
    }
}

#[repr(C)]
struct IfReq {
    name: [u8; 16],
    data: *mut libc::c_void,
    _pad: [u8; 16],
}

impl IfReq {
    fn new(ifname: &str, data: *mut libc::c_void) -> io::Result<Self> {
        let b = ifname.as_bytes();
        if b.is_empty() || b.len() >= 16 || b.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bad interface name",
            ));
        }
        let mut name = [0u8; 16];
        name[..b.len()].copy_from_slice(b);
        Ok(Self {
            name,
            data,
            _pad: [0u8; 16],
        })
    }
}

fn ethtool_ioctl(fd: RawFd, ifname: &str, ls: &mut LinkSettings) -> io::Result<()> {
    let mut req = IfReq::new(ifname, (ls as *mut LinkSettings).cast())?;
    let rc = unsafe { libc::ioctl(fd, SIOCETHTOOL as _, &raw mut req) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn get_link_settings(fd: RawFd, ifname: &str) -> io::Result<LinkSettings> {
    let mut probe = LinkSettings::zeroed();
    probe.cmd = ETHTOOL_GLINKSETTINGS;
    ethtool_ioctl(fd, ifname, &mut probe)?;

    let n = probe.link_mode_masks_nwords;
    if n >= 0 {
        return Err(io::Error::other(format!(
            "GLINKSETTINGS handshake returned nwords={n} (expected negative)"
        )));
    }
    let nwords = n.unsigned_abs() as usize;
    if nwords > MAX_NWORDS {
        return Err(io::Error::other(format!(
            "kernel link_mode nwords={nwords} exceeds supported max {MAX_NWORDS}"
        )));
    }

    let mut ls = LinkSettings::zeroed();
    ls.cmd = ETHTOOL_GLINKSETTINGS;
    ls.link_mode_masks_nwords = nwords as i8;
    ethtool_ioctl(fd, ifname, &mut ls)?;
    if ls.link_mode_masks_nwords != nwords as i8 {
        return Err(io::Error::other(format!(
            "GLINKSETTINGS nwords mismatch: asked {nwords}, got {}",
            ls.link_mode_masks_nwords
        )));
    }
    Ok(ls)
}

fn speed_mask_word(i: usize) -> u32 {
    let mut m = u32::MAX;
    for &b in NON_SPEED_BITS {
        if b as usize / 32 == i {
            m &= !(1u32 << (b % 32));
        }
    }
    m
}

fn desired_advertising(supported: &[u32], advertising: &[u32]) -> Option<Vec<u32>> {
    let mut out = advertising.to_vec();
    let mut changed = false;
    for (i, (w, sup)) in out.iter_mut().zip(supported).enumerate() {
        let missing = sup & speed_mask_word(i) & !*w;
        if missing != 0 {
            *w |= missing;
            changed = true;
        }
    }
    changed.then_some(out)
}

fn has_speed_bits(mask: &[u32]) -> bool {
    mask.iter()
        .enumerate()
        .any(|(i, w)| w & speed_mask_word(i) != 0)
}

fn mask_hex(mask: &[u32]) -> String {
    let hi = mask.iter().rposition(|w| *w != 0).unwrap_or(0);
    let mut s = String::from("0x");
    for w in mask[..=hi].iter().rev() {
        s.push_str(&format!("{w:08x}"));
    }
    s
}

fn mode_names(mask: &[u32]) -> String {
    let mut names = Vec::new();
    for (i, w) in mask.iter().enumerate() {
        for b in 0..32u32 {
            if w & (1 << b) == 0 {
                continue;
            }
            let bit = i as u32 * 32 + b;
            if NON_SPEED_BITS.contains(&bit) {
                continue;
            }
            match MODE_NAMES.iter().find(|(n, _)| *n == bit) {
                Some((_, name)) => names.push((*name).to_string()),
                None => names.push(format!("bit{bit}")),
            }
        }
    }
    if names.is_empty() {
        "-".into()
    } else {
        names.join(",")
    }
}

fn physical_ifaces() -> Vec<String> {
    let Ok(rd) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut out: Vec<String> = rd
        .flatten()
        .filter(|e| {
            let p = e.path();
            p.join("device").exists()
                && !p.join("wireless").exists()
                && !p.join("phy80211").exists()
        })
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n != "lo")
        .collect();
    out.sort();
    out
}

pub fn tune_link_modes() {
    let ifaces = physical_ifaces();
    if ifaces.is_empty() {
        tracing::debug!("no physical NIC found; skip link-mode tune");
        return;
    }
    let sock = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                ?e,
                "open socket for SIOCETHTOOL failed; skip link-mode tune"
            );
            return;
        }
    };
    for iface in ifaces {
        tune_iface(sock.as_raw_fd(), &iface);
    }
}

fn tune_iface(fd: RawFd, iface: &str) {
    let ls = match get_link_settings(fd, iface) {
        Ok(ls) => ls,
        Err(e) => {

            tracing::debug!(iface, err = %e, "GLINKSETTINGS unavailable; skip");
            return;
        }
    };
    if !has_speed_bits(ls.supported()) {
        tracing::debug!(iface, "NIC reports no link modes (virtual?); skip");
        return;
    }
    if ls.autoneg != AUTONEG_ENABLE {
        tracing::info!(
            iface,
            supported = %mask_hex(ls.supported()),
            "autoneg is off (speed forced by operator); leaving link modes alone"
        );
        return;
    }

    let Some(want) = desired_advertising(ls.supported(), ls.advertising()) else {
        tracing::info!(
            iface,
            advertising = %mask_hex(ls.advertising()),
            modes = %mode_names(ls.advertising()),
            "NIC already advertises every supported speed; skip"
        );
        return;
    };

    let added: Vec<u32> = want
        .iter()
        .zip(ls.advertising())
        .map(|(w, a)| w & !a)
        .collect();
    tracing::info!(
        iface,
        from = %mask_hex(ls.advertising()),
        to = %mask_hex(&want),
        added = %mode_names(&added),
        "NIC advertises fewer speeds than it supports; re-advertising full capability"
    );

    let mut set = ls;
    set.cmd = ETHTOOL_SLINKSETTINGS;
    set.autoneg = AUTONEG_ENABLE;
    set.set_advertising(&want);
    if let Err(e) = ethtool_ioctl(fd, iface, &mut set) {
        tracing::warn!(iface, err = %e, "SLINKSETTINGS failed; link modes unchanged");
        return;
    }

    match get_link_settings(fd, iface) {
        Ok(now) => {
            let adv = mask_hex(now.advertising());
            if desired_advertising(now.supported(), now.advertising()).is_some() {
                tracing::warn!(
                    iface,
                    advertising = %adv,
                    supported = %mask_hex(now.supported()),
                    "driver accepted the request but advertising is still narrower than supported"
                );
            } else {
                tracing::info!(
                    iface,
                    advertising = %adv,
                    modes = %mode_names(now.advertising()),
                    "NIC advertising updated (link will renegotiate)"
                );
            }
        }
        Err(e) => tracing::warn!(iface, err = %e, "re-read after SLINKSETTINGS failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_settings_header_matches_uapi_layout() {
        assert_eq!(std::mem::offset_of!(LinkSettings, cmd), 0);
        assert_eq!(std::mem::offset_of!(LinkSettings, speed), 4);
        assert_eq!(std::mem::offset_of!(LinkSettings, duplex), 8);
        assert_eq!(
            std::mem::offset_of!(LinkSettings, link_mode_masks_nwords),
            15
        );
        assert_eq!(std::mem::offset_of!(LinkSettings, reserved), 20);
        assert_eq!(std::mem::offset_of!(LinkSettings, masks), 48);
    }

    #[test]
    fn ifreq_is_full_kernel_size() {
        assert_eq!(std::mem::size_of::<IfReq>(), 40);
        let r = IfReq::new("eth0", std::ptr::null_mut()).unwrap();
        assert_eq!(&r.name[..5], b"eth0\0");
        assert!(IfReq::new("", std::ptr::null_mut()).is_err());
        assert!(IfReq::new("0123456789abcdef", std::ptr::null_mut()).is_err());
    }

    #[test]
    fn speed_mask_excludes_feature_bits() {
        let w0 = speed_mask_word(0);
        for b in [6u32, 7, 8, 9, 10, 11, 13, 14, 16, 20] {
            assert_eq!(w0 & (1 << b), 0, "bit {b} must not count as a speed bit");
        }
        for b in [0u32, 1, 2, 3, 4, 5, 12, 15] {
            assert_ne!(w0 & (1 << b), 0, "bit {b} must count as a speed bit");
        }

        assert_eq!(speed_mask_word(1) & (1 << (49 - 32)), 0);
        assert_eq!(speed_mask_word(2) & (1 << (74 - 64)), 0);
        assert_ne!(speed_mask_word(1) & (1 << (47 - 32)), 0);
    }

    #[test]
    fn widens_advertising_to_supported_speeds() {

        let sup = [0b0010_0000_1010_1111u32, 1 << (47 - 32)];
        let adv = [0b0010_0000_1010_1111u32, 0];
        let want = desired_advertising(&sup, &adv).expect("must widen");
        assert_eq!(want[1], 1 << (47 - 32));
        assert_eq!(want[0], adv[0], "word0 must be untouched");
        assert_eq!(mode_names(&[0, 1 << (47 - 32)]), "2500baseT/Full");
    }

    #[test]
    fn matching_advertising_is_left_alone() {
        let sup = [0b0010_0000_1010_1111u32, 1 << (47 - 32)];
        assert!(desired_advertising(&sup, &sup).is_none());
    }

    #[test]
    fn never_clears_pause_or_extra_bits() {

        let sup = [0b0000_0000_0010_1111u32, 0];
        let adv = [(1 << 13) | (1 << 14) | 0b0000_0000_0000_1111u32, 0];
        let want = desired_advertising(&sup, &adv).expect("1000baseT/Full missing");
        assert_ne!(want[0] & (1 << 13), 0);
        assert_ne!(want[0] & (1 << 14), 0);
        assert_ne!(want[0] & (1 << 5), 0);
    }

    #[test]
    fn supported_without_speed_bits_is_ignored() {
        assert!(!has_speed_bits(&[0, 0]));
        assert!(!has_speed_bits(&[1 << 6 | 1 << 13, 0]));
        assert!(has_speed_bits(&[1 << 5, 0]));
    }

    #[test]
    fn hex_matches_ethtool_notation() {

        assert_eq!(mask_hex(&[0x2f, 0x8000]), "0x000080000000002f");
        assert_eq!(mask_hex(&[0, 0]), "0x00000000");
    }

    #[test]
    fn query_local_ifaces_never_panics() {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind udp");
        for iface in physical_ifaces() {
            if let Ok(ls) = get_link_settings(sock.as_raw_fd(), &iface) {
                assert!(ls.nwords() <= MAX_NWORDS);
                let _ = mask_hex(ls.supported());
                let _ = mode_names(ls.advertising());
            }
        }
    }
}
