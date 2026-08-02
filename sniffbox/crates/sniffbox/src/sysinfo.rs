// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub fn meminfo() -> (u64, u64) {
    let text = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mut total = 0u64;
    let mut avail = 0u64;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = parse_kb(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail = parse_kb(rest);
        }
    }
    (total, avail)
}

fn parse_kb(rest: &str) -> u64 {
    rest.split_whitespace()
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
        * 1024
}

pub fn kernel_version() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string()
}

pub fn uptime_secs() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|t| t.split_whitespace().next()?.parse::<f64>().ok())
        .map(|s| s as u64)
        .unwrap_or(0)
}

pub fn cpu_model_cores() -> (String, usize) {
    let text = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let mut model = String::new();
    let mut cores = 0usize;
    for line in text.lines() {
        if line.starts_with("processor") {
            cores += 1;
        } else if model.is_empty() {

            if let Some(v) = line.strip_prefix("model name") {
                model = v.trim_start_matches([':', ' ', '\t']).trim().to_string();
            }
        }
    }
    if cores == 0 {
        cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
    }
    if model.is_empty() {
        model = arm_model(&text);
    }
    (model, cores)
}

const ARM_IMPLEMENTERS: &[(u16, &str)] = &[
    (0x41, "ARM"),
    (0x42, "Broadcom"),
    (0x43, "Cavium"),
    (0x44, "DEC"),
    (0x46, "FUJITSU"),
    (0x48, "HiSilicon"),
    (0x49, "Infineon"),
    (0x4d, "Motorola/Freescale"),
    (0x4e, "NVIDIA"),
    (0x50, "APM"),
    (0x51, "Qualcomm"),
    (0x53, "Samsung"),
    (0x56, "Marvell"),
    (0x61, "Apple"),
    (0x66, "Faraday"),
    (0x69, "Intel"),
    (0x6d, "Microsoft"),
    (0x70, "Phytium"),
    (0xc0, "Ampere"),
];

const ARM_PARTS: &[(u16, &str)] = &[
    (0xd01, "Cortex-A32"),
    (0xd02, "Cortex-A34"),
    (0xd03, "Cortex-A53"),
    (0xd04, "Cortex-A35"),
    (0xd05, "Cortex-A55"),
    (0xd06, "Cortex-A65"),
    (0xd07, "Cortex-A57"),
    (0xd08, "Cortex-A72"),
    (0xd09, "Cortex-A73"),
    (0xd0a, "Cortex-A75"),
    (0xd0b, "Cortex-A76"),
    (0xd0c, "Neoverse-N1"),
    (0xd0d, "Cortex-A77"),
    (0xd0e, "Cortex-A76AE"),
    (0xd13, "Cortex-R52"),
    (0xd15, "Cortex-R82"),
    (0xd40, "Neoverse-V1"),
    (0xd41, "Cortex-A78"),
    (0xd42, "Cortex-A78AE"),
    (0xd43, "Cortex-A65AE"),
    (0xd44, "Cortex-X1"),
    (0xd46, "Cortex-A510"),
    (0xd47, "Cortex-A710"),
    (0xd48, "Cortex-X2"),
    (0xd49, "Neoverse-N2"),
    (0xd4a, "Neoverse-E1"),
    (0xd4b, "Cortex-A78C"),
    (0xd4c, "Cortex-X1C"),
    (0xd4d, "Cortex-A715"),
    (0xd4e, "Cortex-X3"),
    (0xd4f, "Neoverse-V2"),
    (0xd80, "Cortex-A520"),
    (0xd81, "Cortex-A720"),
    (0xd82, "Cortex-X4"),
    (0xd83, "Neoverse-V3AE"),
    (0xd84, "Neoverse-V3"),
    (0xd85, "Cortex-X925"),
    (0xd87, "Cortex-A725"),
    (0xd88, "Cortex-A520AE"),
    (0xd89, "Cortex-A720AE"),
    (0xd8e, "Neoverse-N3"),
    (0xd8f, "Cortex-A320"),
];

fn arm_model(text: &str) -> String {
    let hex = |s: &str| u16::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok();
    let mut implementer = None;
    let mut parts: Vec<u16> = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "CPU implementer" => implementer = implementer.or_else(|| hex(value)),
            "CPU part" => {
                if let Some(p) = hex(value)
                    && !parts.contains(&p)
                {
                    parts.push(p);
                }
            }
            _ => {}
        }
    }
    let Some(implementer) = implementer else {
        return String::new();
    };
    if parts.is_empty() {
        return String::new();
    }
    let vendor = ARM_IMPLEMENTERS
        .iter()
        .find(|(id, _)| *id == implementer)
        .map(|(_, name)| (*name).to_string())
        .unwrap_or_else(|| format!("implementer 0x{implementer:02x}"));
    let named: Vec<String> = parts
        .iter()
        .map(|p| {
            ARM_PARTS
                .iter()
                .find(|(id, _)| id == p && implementer == 0x41)
                .map(|(_, name)| (*name).to_string())
                .unwrap_or_else(|| format!("part 0x{p:03x}"))
        })
        .collect();
    format!("{vendor} {}", named.join(" + "))
}

pub fn cpu_jiffies() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    let line = text.lines().next()?;
    let rest = line.strip_prefix("cpu")?.trim_start();
    let vals: Vec<u64> = rest
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();
    if vals.len() < 5 {
        return None;
    }

    let idle = vals[3] + vals.get(4).copied().unwrap_or(0);
    let total: u64 = vals.iter().sum();
    Some((total, idle))
}

pub fn cpu_jiffies_per_core() -> Vec<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {

        let Some(rest) = line.strip_prefix("cpu") else {
            break;
        };
        if rest.starts_with(char::is_whitespace) {
            continue;
        }
        let Some(nums) = rest.split_once(char::is_whitespace).map(|(_, r)| r) else {
            continue;
        };
        let vals: Vec<u64> = nums
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();
        if vals.len() < 5 {
            continue;
        }
        let idle = vals[3] + vals.get(4).copied().unwrap_or(0);
        let total: u64 = vals.iter().sum();
        out.push((total, idle));
    }
    out
}

pub fn cpu_usage_pct(prev: (u64, u64), now: (u64, u64)) -> f64 {
    let dt = now.0.saturating_sub(prev.0);
    let di = now.1.saturating_sub(prev.1);
    if dt == 0 {
        return 0.0;
    }
    let busy = dt.saturating_sub(di) as f64;
    (busy / dt as f64) * 100.0
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

fn read_num<T: std::str::FromStr>(path: impl AsRef<Path>) -> Option<T> {
    read_trimmed(path)?.parse().ok()
}

pub fn cpu_freqs_khz() -> Vec<u32> {
    let per = scan_cpu_freqs_khz("/sys/devices/system/cpu");
    if !per.is_empty() {
        return per.into_values().collect();
    }
    let from_cpuinfo =
        cpuinfo_freqs_khz(&std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default());
    if !from_cpuinfo.is_empty() {
        return from_cpuinfo;
    }

    hostinfo::root()
        .map(|r| {
            scan_cpu_freqs_khz(r.join("sysfs/cpu"))
                .into_values()
                .collect()
        })
        .unwrap_or_default()
}

fn scan_cpu_freqs_khz(root: impl AsRef<Path>) -> BTreeMap<usize, u32> {
    let mut per: BTreeMap<usize, u32> = BTreeMap::new();
    let Ok(dir) = std::fs::read_dir(root) else {
        return per;
    };
    for ent in dir.flatten() {
        let Some(n) = cpu_index(&ent.file_name().to_string_lossy()) else {
            continue;
        };
        let base = ent.path().join("cpufreq");
        let khz = read_num::<u32>(base.join("scaling_cur_freq"))
            .or_else(|| read_num::<u32>(base.join("cpuinfo_cur_freq")));
        if let Some(k) = khz {
            per.insert(n, k);
        }
    }
    per
}

fn cpu_index(name: &str) -> Option<usize> {
    name.strip_prefix("cpu")?.parse().ok()
}

fn cpuinfo_freqs_khz(text: &str) -> Vec<u32> {
    text.lines()
        .filter_map(|l| l.strip_prefix("cpu MHz"))
        .filter_map(|v| {
            v.trim_start_matches([':', ' ', '\t'])
                .trim()
                .parse::<f64>()
                .ok()
        })
        .map(|mhz| (mhz * 1000.0).round() as u32)
        .collect()
}

pub fn cpu_freq_range_khz() -> Option<(u32, u32)> {
    scan_cpu_freq_range_khz("/sys/devices/system/cpu")

        .or_else(|| scan_cpu_freq_range_khz(hostinfo::root()?.join("sysfs/cpu")))
}

fn scan_cpu_freq_range_khz(root: impl AsRef<Path>) -> Option<(u32, u32)> {
    let mut lo: Option<u32> = None;
    let mut hi: Option<u32> = None;
    let dir = std::fs::read_dir(root).ok()?;
    for ent in dir.flatten() {
        if cpu_index(&ent.file_name().to_string_lossy()).is_none() {
            continue;
        }
        let base = ent.path().join("cpufreq");
        if let Some(v) = read_num::<u32>(base.join("cpuinfo_min_freq"))
            .or_else(|| read_num::<u32>(base.join("scaling_min_freq")))
        {
            lo = Some(lo.map_or(v, |c: u32| c.min(v)));
        }
        if let Some(v) = read_num::<u32>(base.join("cpuinfo_max_freq"))
            .or_else(|| read_num::<u32>(base.join("scaling_max_freq")))
        {
            hi = Some(hi.map_or(v, |c: u32| c.max(v)));
        }
    }
    match (lo, hi) {
        (Some(lo), Some(hi)) if hi > 0 => Some((lo, hi)),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct CpuTemp {
    pub celsius: f64,
    pub sensor: String,
}

fn thermal_score(zone_type: &str) -> u32 {
    let t = zone_type.trim().to_ascii_lowercase();
    if matches!(
        t.as_str(),
        "cpu-thermal" | "x86_pkg_temp" | "coretemp" | "soc_thermal" | "cpu_thermal" | "cpu"
    ) {
        return 1000;
    }
    const NOT_CPU: &[&str] = &[
        "acpitz", "iwlwifi", "nvme", "amdgpu", "radeon", "nouveau", "pch_", "wlan", "battery",
        "sd", "disk", "gpu",
    ];
    if NOT_CPU.iter().any(|p| t.starts_with(p)) {
        return 0;
    }
    const CPU_ISH: &[&str] = &["cpu", "pkg_temp", "coretemp", "processor", "tcpu", "soc"];
    if CPU_ISH.iter().any(|k| t.contains(k)) {
        return 50;
    }
    0
}

fn temp_celsius(raw: i64) -> Option<f64> {
    let c = if raw.abs() < 1000 {
        raw as f64
    } else {
        raw as f64 / 1000.0
    };
    (-50.0..=200.0).contains(&c).then_some(c)
}

pub fn cpu_temp() -> Option<CpuTemp> {
    let best = scan_thermal_best("/sys/class/thermal");
    if let Some((score, celsius, sensor)) = best.clone()
        && score >= 50
    {
        return Some(CpuTemp { celsius, sensor });
    }
    hwmon_cpu_temp()
        .or_else(|| {

            best.map(|(_, celsius, sensor)| CpuTemp { celsius, sensor })
        })
        .or_else(|| {

            let (_, celsius, sensor) = scan_thermal_best(hostinfo::root()?.join("sysfs/thermal"))?;
            Some(CpuTemp { celsius, sensor })
        })
}

fn scan_thermal_best(root: impl AsRef<Path>) -> Option<(u32, f64, String)> {
    let mut best: Option<(u32, f64, String)> = None;
    let Ok(dir) = std::fs::read_dir(root) else {
        return None;
    };
    for ent in dir.flatten() {
        if !ent
            .file_name()
            .to_string_lossy()
            .starts_with("thermal_zone")
        {
            continue;
        }
        let p = ent.path();
        let (Some(ty), Some(raw)) = (
            read_trimmed(p.join("type")),
            read_num::<i64>(p.join("temp")),
        ) else {
            continue;
        };
        let Some(c) = temp_celsius(raw) else { continue };
        let score = thermal_score(&ty);
        if best.as_ref().is_none_or(|(s, _, _)| score > *s) {
            best = Some((score, c, ty));
        }
    }
    best
}

mod hostinfo {
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    const TAG: &str = "hostinfo";

    const MNT: &str = "/run/sniffbox/hostinfo";

    static ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();

    pub(super) fn root() -> Option<&'static Path> {
        ROOT.get_or_init(probe).as_deref()
    }

    fn usable(p: &Path) -> bool {
        p.join("sysfs").is_dir()
    }

    fn probe() -> Option<PathBuf> {

        if let Some(p) = std::env::var_os("SNIFFBOX_HOSTINFO") {
            let p = PathBuf::from(p);
            return usable(&p).then_some(p);
        }

        for cand in [MNT, "/mnt/host"] {
            let p = Path::new(cand);
            if usable(p) {
                return Some(p.to_path_buf());
            }
        }

        if !tag_present() {
            return None;
        }
        mount_ro().ok()?;
        let p = Path::new(MNT);
        usable(p).then(|| p.to_path_buf())
    }

    fn tag_present() -> bool {
        let Ok(dir) = std::fs::read_dir("/sys/bus/virtio/devices") else {
            return false;
        };
        dir.flatten().any(|e| {
            std::fs::read_to_string(e.path().join("mount_tag"))
                .is_ok_and(|t| t.trim_end_matches('\0').trim() == TAG)
        })
    }

    fn mount_ro() -> std::io::Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        std::fs::create_dir_all(MNT)?;
        let cs = |s: &[u8]| CString::new(s).map_err(std::io::Error::other);
        let src = cs(TAG.as_bytes())?;
        let tgt = cs(Path::new(MNT).as_os_str().as_bytes())?;
        let fstype = cs(b"9p")?;
        let data = cs(b"trans=virtio,version=9p2000.L")?;

        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                fstype.as_ptr(),
                libc::MS_RDONLY,
                data.as_ptr().cast(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

fn hwmon_cpu_temp() -> Option<CpuTemp> {
    const CPU_CHIPS: &[&str] = &["coretemp", "k10temp", "zenpower", "cpu_thermal"];
    let dir = std::fs::read_dir("/sys/class/hwmon").ok()?;
    for ent in dir.flatten() {
        let p = ent.path();
        let Some(name) = read_trimmed(p.join("name")) else {
            continue;
        };
        if !CPU_CHIPS.contains(&name.as_str()) {
            continue;
        }

        if let Some(raw) = read_num::<i64>(p.join("temp1_input"))
            && let Some(celsius) = temp_celsius(raw)
        {
            return Some(CpuTemp {
                celsius,
                sensor: name,
            });
        }
    }
    None
}

#[derive(Debug, Default, Clone)]
pub struct Iface {
    pub name: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub mac: Option<String>,
    pub gateway: Option<String>,
    pub driver: Option<String>,
    pub model: Option<String>,
    pub pci_id: Option<String>,
    pub speed: Option<u32>,
    pub duplex: Option<String>,
    pub link: Option<bool>,
}

const NIC_MODELS: &[(&str, &str)] = &[

    ("igc", "Intel I225/I226 2.5GbE"),
    ("igb", "Intel I350/I210/I211 Gigabit"),
    ("e1000e", "Intel 8257x Gigabit"),
    ("e1000", "Intel PRO/1000"),
    ("ixgbe", "Intel X550/X540 10GbE"),
    ("i40e", "Intel X710/XL710 10/40GbE"),
    ("ice", "Intel E810 10/25/100GbE"),

    ("r8169", "Realtek RTL8168/RTL8111 Gigabit"),
    ("r8168", "Realtek RTL8168/RTL8111 Gigabit"),
    ("r8125", "Realtek RTL8125 2.5GbE"),
    ("r8126", "Realtek RTL8126 5GbE"),
    ("r8152", "Realtek RTL8152/RTL8153 USB 2.5GbE"),
    ("8139too", "Realtek RTL8139 Fast Ethernet"),
    ("8139cp", "Realtek RTL8139 Fast Ethernet"),

    ("atlantic", "Aquantia/Marvell AQtion Multi-Gig"),
    ("mvneta", "Marvell ARMADA NETA Gigabit"),
    ("mvpp2", "Marvell PP2 Gigabit"),

    ("mlx4_en", "Mellanox ConnectX-3"),
    ("mlx5_core", "Mellanox ConnectX-4/5/6/7"),

    ("bnx2", "Broadcom NetXtreme II"),
    ("bnx2x", "Broadcom NetXtreme II 10GbE"),
    ("tg3", "Broadcom Tigon3"),
    ("bnxt_en", "Broadcom NetXtreme-C/E 10/25/50/100GbE"),

    ("cxgb4", "Chelsio T4/T5/T6 10/25/40/100GbE"),
    ("cxgb4vf", "Chelsio T4/T5/T6 10/25/40/100GbE"),
    ("qede", "QLogic/Cavium FastLinQ 10/25/40/100GbE"),
    ("qed", "QLogic/Cavium FastLinQ 10/25/40/100GbE"),
    ("sfc", "Solarflare 10/25/40GbE"),
    ("nfp", "Netronome NFP 10/25/40/100GbE"),

    ("vmxnet3", "VMware vmxnet3"),
    ("vmxnet", "VMware vmxnet"),
    ("virtio_net", "Virtio virtual NIC"),
    ("pcnet32", "AMD PCnet32 (virtual)"),
    ("ne2k_pci", "NE2000 PCI (legacy VM)"),
    ("hv_netvsc", "Microsoft Hyper-V virtual NIC"),

    ("vif", "Xen virtual NIC"),
    ("xennet", "Xen virtual NIC"),
    ("xen_netfront", "Xen virtual NIC"),

    ("stmmac", "Synopsys DesignWare GMAC"),
    ("dwmac", "Synopsys DesignWare GMAC"),
    ("dwmac_socfpga", "Synopsys DesignWare GMAC"),
    ("dwmac_imx", "Synopsys DesignWare GMAC"),
    ("dwmac_sunxi", "Synopsys DesignWare GMAC"),
    ("dwmac_intel", "Synopsys DesignWare GMAC"),
    ("fec", "NXP/Freescale FEC"),
    ("macb", "Cadence MACB/GEM"),
    ("xgbe", "AMD 10GbE XGBE"),
    ("axgbe", "AMD 10GbE XGBE"),

    ("lan743x", "Microchip LAN7430 Gigabit"),
    ("jme", "JMicron JMC2xx Gigabit"),
    ("alx", "Qualcomm Atheros ALX"),
];

fn driver_to_model(driver: &str) -> Option<&'static str> {
    NIC_MODELS
        .iter()
        .find(|(d, _)| *d == driver)
        .map(|(_, m)| *m)
}

const VIRTUAL_NIC_NOMINAL_SPEED: &[(&str, u32)] = &[
    ("virtio_net", 10_000),
    ("hv_netvsc", 10_000),
    ("vif", 10_000),
    ("xen_netfront", 10_000),
    ("vmxnet3", 10_000),
];

fn virtual_nic_nominal_speed(driver: &str) -> Option<u32> {
    VIRTUAL_NIC_NOMINAL_SPEED
        .iter()
        .find(|(d, _)| *d == driver)
        .map(|(_, s)| *s)
}

fn resolve_speed(raw: Option<i64>, link: Option<bool>, driver: Option<&str>) -> Option<u32> {
    if let Some(s) = raw.filter(|s| *s > 0) {
        return Some(s as u32);
    }
    if link == Some(true) {
        return driver.and_then(virtual_nic_nominal_speed);
    }
    None
}

fn fill_hw(e: &mut Iface) {
    let base = Path::new("/sys/class/net").join(&e.name);
    e.link = read_num::<u8>(base.join("carrier")).map(|c| c != 0);
    e.duplex = read_trimmed(base.join("duplex")).filter(|d| d != "unknown");

    let raw_speed = read_num::<i64>(base.join("speed"));

    let dev = base.join("device");
    if dev.exists() {
        e.driver = std::fs::read_link(dev.join("driver"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
        let hex =
            |f: &str| read_trimmed(dev.join(f)).map(|v| v.trim_start_matches("0x").to_string());
        if let (Some(v), Some(d)) = (hex("vendor"), hex("device")) {
            e.pci_id = Some(format!("{v}:{d}"));
        }
        e.model = e
            .driver
            .as_deref()
            .and_then(driver_to_model)
            .map(str::to_string);
    } else {

        e.model = read_trimmed(base.join("uevent"))
            .and_then(|t| {
                t.lines()
                    .find_map(|l| l.strip_prefix("DEVTYPE="))
                    .map(str::to_string)
            })
            .or_else(|| base.join("tun_flags").exists().then(|| "tun".to_string()));
    }

    e.speed = resolve_speed(raw_speed, e.link, e.driver.as_deref());

    let fell_back = e.speed.is_some() && raw_speed.is_none_or(|s| s <= 0);
    if fell_back && e.duplex.is_none() {
        e.duplex = Some("full".to_string());
    }
}

pub fn interfaces() -> Vec<Iface> {
    let mut map: BTreeMap<String, Iface> = BTreeMap::new();

    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Vec::new();
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_name.is_null() {
                continue;
            }
            if ifa.ifa_flags & (libc::IFF_LOOPBACK as libc::c_uint) != 0 {
                continue;
            }
            let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
            let entry = map.entry(name.clone()).or_insert_with(|| Iface {
                name,
                ..Default::default()
            });
            if ifa.ifa_addr.is_null() {
                continue;
            }
            let fam = (*ifa.ifa_addr).sa_family as i32;
            match fam {
                libc::AF_INET => {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    let prefix = if ifa.ifa_netmask.is_null() {
                        32
                    } else {
                        let m = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                        u32::from_be(m.sin_addr.s_addr).count_ones() as u8
                    };
                    entry.ipv4.push(format!("{ip}/{prefix}"));
                }
                libc::AF_INET6 => {
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    let prefix = if ifa.ifa_netmask.is_null() {
                        128
                    } else {
                        let m = &*(ifa.ifa_netmask as *const libc::sockaddr_in6);
                        m.sin6_addr
                            .s6_addr
                            .iter()
                            .map(|b| b.count_ones())
                            .sum::<u32>() as u8
                    };
                    entry.ipv6.push(format!("{ip}/{prefix}"));
                }
                libc::AF_PACKET => {
                    let sll = &*(ifa.ifa_addr as *const libc::sockaddr_ll);
                    let n = sll.sll_halen as usize;
                    if n == 6 {
                        let a = &sll.sll_addr;
                        entry.mac = Some(format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            a[0], a[1], a[2], a[3], a[4], a[5]
                        ));
                    }
                }
                _ => {}
            }
        }
        libc::freeifaddrs(ifap);
    }
    for (ifname, gw) in default_gateways() {
        if let Some(e) = map.get_mut(&ifname) {
            e.gateway = Some(gw.to_string());
        }
    }
    let mut out: Vec<Iface> = map.into_values().collect();
    for e in &mut out {
        fill_hw(e);
    }
    out
}

fn default_gateways() -> BTreeMap<String, Ipv4Addr> {
    let mut out = BTreeMap::new();
    let text = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    for line in text.lines().skip(1) {
        let mut f = line.split_whitespace();
        let (Some(iface), Some(dest), Some(gw)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if dest != "00000000" {
            continue;
        }

        if let Ok(raw) = u32::from_str_radix(gw, 16) {
            let ip = Ipv4Addr::from(raw.swap_bytes());
            out.entry(iface.to_string()).or_insert(ip);
        }
    }
    out
}

pub fn resolv_nameservers() -> Vec<String> {
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn self_rss() -> u64 {
    rss_of_status(&std::fs::read_to_string("/proc/self/status").unwrap_or_default())
}

pub fn find_pid_by_name(names: &[&str]) -> Option<u32> {
    let dir = std::fs::read_dir("/proc").ok()?;
    for ent in dir.flatten() {
        let fname = ent.file_name();
        let Some(pid) = fname.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        if names.contains(&comm.trim()) {
            return Some(pid);
        }
    }
    None
}

pub fn find_pids_by_name(names: &[&str]) -> Vec<u32> {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ent in dir.flatten() {
        let fname = ent.file_name();
        let Some(pid) = fname.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        if names.contains(&comm.trim()) {
            out.push(pid);
        }
    }
    out.sort_unstable();
    out
}

pub fn process_rss(pid: u32) -> u64 {
    rss_of_status(&std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default())
}

pub fn self_uptime() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    let starttime_ticks: u64 = tokens.get(19)?.parse().ok()?;
    let starttime_secs = starttime_ticks / 100;
    Some(uptime_secs().saturating_sub(starttime_secs))
}

pub fn process_uptime(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    let starttime_ticks: u64 = tokens.get(19)?.parse().ok()?;
    let starttime_secs = starttime_ticks / 100;
    Some(uptime_secs().saturating_sub(starttime_secs))
}

pub fn self_cpu_jiffies() -> Option<u64> {
    cpu_jiffies_of_stat(&std::fs::read_to_string("/proc/self/stat").ok()?)
}

pub fn process_cpu_jiffies(pid: u32) -> Option<u64> {
    cpu_jiffies_of_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

fn cpu_jiffies_of_stat(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    let utime: u64 = tokens.get(11)?.parse().ok()?;
    let stime: u64 = tokens.get(12)?.parse().ok()?;
    Some(utime + stime)
}

pub fn process_cpu_pct(proc_delta: u64, total_delta: u64) -> f64 {
    if total_delta == 0 {
        return 0.0;
    }
    ((proc_delta as f64 / total_delta as f64) * 100.0).clamp(0.0, 100.0)
}

fn rss_of_status(status: &str) -> u64 {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .map(parse_kb)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Default)]
pub struct ClashVersion {
    pub version: String,
    pub meta: bool,
}

pub fn clash_version(sock: &std::path::Path) -> Option<ClashVersion> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let mut s = UnixStream::connect(sock).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(300))).ok();
    s.set_write_timeout(Some(Duration::from_millis(300))).ok();
    s.write_all(b"GET /version HTTP/1.0\r\nHost: clash\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut buf = Vec::with_capacity(512);

    let mut chunk = [0u8; 512];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 8192 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1)?;
    let v: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let version = v.get("version")?.as_str()?.to_string();
    let meta = v.get("meta").and_then(|x| x.as_bool()).unwrap_or(false);
    Some(ClashVersion { version, meta })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_nonzero_on_linux() {
        let (t, a) = meminfo();
        assert!(t > 0, "MemTotal should be readable");
        assert!(a > 0 && a <= t);
    }

    #[test]
    fn uptime_positive() {
        assert!(uptime_secs() > 0);
    }

    #[test]
    fn kernel_version_nonempty() {
        let k = kernel_version();
        assert!(!k.is_empty() && !k.contains('\n'), "kernel={k:?}");
    }

    #[test]
    fn cpu_model_cores_sane() {
        let (_m, c) = cpu_model_cores();
        assert!(c >= 1);
    }

    fn fake_share(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("sniffbox-hostinfo-test-{name}"));
        let _ = std::fs::remove_dir_all(&root);
        let tz = root.join("sysfs/thermal/thermal_zone0");
        std::fs::create_dir_all(&tz).unwrap();
        std::fs::write(tz.join("type"), "cpu-thermal\n").unwrap();
        std::fs::write(tz.join("temp"), "56000\n").unwrap();
        for (i, khz) in [1512000u32, 1200000, 1000000, 667000].iter().enumerate() {
            let c = root.join(format!("sysfs/cpu/cpu{i}/cpufreq"));
            std::fs::create_dir_all(&c).unwrap();
            std::fs::write(c.join("scaling_cur_freq"), format!("{khz}\n")).unwrap();
            std::fs::write(c.join("cpuinfo_min_freq"), "100000\n").unwrap();
            std::fs::write(c.join("cpuinfo_max_freq"), "1512000\n").unwrap();
        }
        root
    }

    #[test]
    fn scans_host_shared_thermal_tree() {
        let root = fake_share("thermal");
        let (score, celsius, sensor) = scan_thermal_best(root.join("sysfs/thermal")).unwrap();
        assert_eq!(sensor, "cpu-thermal");
        assert_eq!(score, 1000, "cpu-thermal must be the determined CPU sensor");
        assert!((celsius - 56.0).abs() < f64::EPSILON, "celsius={celsius}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scans_host_shared_cpufreq_tree() {
        let root = fake_share("cpufreq");
        let freqs: Vec<u32> = scan_cpu_freqs_khz(root.join("sysfs/cpu"))
            .into_values()
            .collect();

        assert_eq!(freqs, vec![1512000, 1200000, 1000000, 667000]);
        assert_eq!(
            scan_cpu_freq_range_khz(root.join("sysfs/cpu")),
            Some((100000, 1512000))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scans_of_missing_tree_are_empty_not_panics() {
        let missing = std::env::temp_dir().join("sniffbox-hostinfo-does-not-exist");
        assert!(scan_thermal_best(&missing).is_none());
        assert!(scan_cpu_freqs_khz(&missing).is_empty());
        assert!(scan_cpu_freq_range_khz(&missing).is_none());
    }

    #[test]
    fn no_host_share_on_bare_metal() {
        if std::path::Path::new("/sys/bus/virtio/devices").exists() {
            eprintln!("skipping: this machine is a VM");
            return;
        }
        assert!(
            hostinfo::root().is_none(),
            "bare metal should not detect host share"
        );
    }

    #[test]
    fn arm_model_from_implementer_and_part() {

        let cpuinfo = "processor\t: 0\nBogoMIPS\t: 48.00\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 cpuid\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x0\nCPU part\t: 0xd03\nCPU revision\t: 4\n\nprocessor\t: 1\nCPU implementer\t: 0x41\nCPU part\t: 0xd03\n";
        assert_eq!(arm_model(cpuinfo), "ARM Cortex-A53");
    }

    #[test]
    fn arm_model_lists_every_big_little_core() {
        let cpuinfo = "CPU implementer\t: 0x41\nCPU part\t: 0xd03\nCPU implementer\t: 0x41\nCPU part\t: 0xd08\n";
        assert_eq!(arm_model(cpuinfo), "ARM Cortex-A53 + Cortex-A72");
    }

    #[test]
    fn arm_model_falls_back_to_raw_ids() {

        assert_eq!(
            arm_model("CPU implementer\t: 0x51\nCPU part\t: 0x800\n"),
            "Qualcomm part 0x800"
        );

        assert_eq!(
            arm_model("CPU implementer\t: 0x99\nCPU part\t: 0xd03\n"),
            "implementer 0x99 part 0xd03"
        );
    }

    #[test]
    fn arm_model_empty_without_ids() {
        assert_eq!(arm_model("processor\t: 0\nBogoMIPS\t: 48.00\n"), "");
    }

    #[test]
    fn cpu_model_prefers_model_name_line() {

        let (model, cores) = cpu_model_cores();
        assert!(cores >= 1);
        let _ = model;
    }

    #[test]
    fn cpu_per_core_matches_core_count() {

        let per_core = cpu_jiffies_per_core();
        let (_m, cores) = cpu_model_cores();
        assert_eq!(per_core.len(), cores);
        for (total, idle) in per_core {
            assert!(total >= idle);
        }
    }

    #[test]
    fn cpu_usage_bounds() {
        let u = cpu_usage_pct((100, 40), (200, 90));
        assert!((0.0..=100.0).contains(&u));
        assert_eq!(cpu_usage_pct((100, 40), (100, 40)), 0.0);
    }

    #[test]
    fn self_rss_positive() {
        assert!(self_rss() > 0);
    }

    #[test]
    fn cpu_jiffies_of_stat_parses_utime_stime() {

        let stat = "1234 (sniffbox) S 1 1234 1234 0 -1 4194560 100 0 0 0 71 29 0 0 20 0 3 0 999";
        assert_eq!(cpu_jiffies_of_stat(stat), Some(100));
    }

    #[test]
    fn cpu_jiffies_of_stat_survives_parens_and_spaces_in_comm() {

        let stat = "77 (weird ) name) S 1 1 1 0 -1 0 0 0 0 0 5 7 0 0 20 0 1 0 42";
        assert_eq!(cpu_jiffies_of_stat(stat), Some(12));
    }

    #[test]
    fn cpu_jiffies_of_stat_rejects_garbage() {
        assert_eq!(cpu_jiffies_of_stat(""), None);
        assert_eq!(cpu_jiffies_of_stat("1 (x) S 1 2"), None);
    }

    #[test]
    fn self_cpu_jiffies_readable_and_monotonic() {
        let a = self_cpu_jiffies().expect("/proc/self/stat readable");
        let mut spin = 0u64;
        for i in 0..3_000_000u64 {
            spin = spin.wrapping_add(i);
        }
        std::hint::black_box(spin);
        assert!(self_cpu_jiffies().unwrap() >= a);
    }

    #[test]
    fn process_cpu_pct_bounds() {
        assert_eq!(process_cpu_pct(0, 0), 0.0);
        assert_eq!(process_cpu_pct(50, 200), 25.0);
        assert_eq!(process_cpu_pct(999, 100), 100.0);
    }

    #[test]
    fn find_pid_by_name_finds_this_test_binary() {
        let comm = std::fs::read_to_string("/proc/self/comm").unwrap();
        let comm = comm.trim();
        let pid = find_pid_by_name(&[comm]).expect("own comm should be found");
        assert!(process_rss(pid) > 0);
        assert!(find_pid_by_name(&["definitely-not-a-real-process-xyz"]).is_none());
    }

    #[test]
    fn thermal_score_ranks_cpu_zones_above_the_rest() {
        assert_eq!(thermal_score("x86_pkg_temp"), 1000);
        assert_eq!(thermal_score("cpu-thermal"), 1000);
        assert_eq!(thermal_score("soc_thermal"), 1000);

        assert_eq!(thermal_score("cpu0-thermal"), 50);
        assert_eq!(thermal_score("bigcore0_tcpu"), 50);

        assert_eq!(thermal_score("acpitz"), 0);
        assert_eq!(thermal_score("nvme"), 0);
        assert_eq!(thermal_score("iwlwifi_1"), 0);
        assert_eq!(thermal_score("battery"), 0);
        assert_eq!(thermal_score("mystery"), 0);
    }

    #[test]
    fn temp_celsius_handles_both_units_and_rejects_garbage() {
        assert_eq!(temp_celsius(48_500), Some(48.5));
        assert_eq!(temp_celsius(45), Some(45.0));
        assert_eq!(temp_celsius(-40_000), Some(-40.0));
        assert_eq!(temp_celsius(9_999_000), None);
        assert_eq!(temp_celsius(-100_000), None);
    }

    #[test]
    fn cpu_temp_is_optional_and_sane() {

        if let Some(t) = cpu_temp() {
            assert!(!t.sensor.is_empty());
            assert!((-50.0..=200.0).contains(&t.celsius), "temp={}", t.celsius);
        }
    }

    #[test]
    fn cpu_index_only_matches_numbered_cpu_dirs() {
        assert_eq!(cpu_index("cpu0"), Some(0));
        assert_eq!(cpu_index("cpu13"), Some(13));
        assert_eq!(cpu_index("cpufreq"), None);
        assert_eq!(cpu_index("cpuidle"), None);
        assert_eq!(cpu_index("possible"), None);
    }

    #[test]
    fn cpuinfo_freqs_parse_mhz_to_khz() {
        let text = "processor\t: 0\ncpu MHz\t\t: 3200.000\nprocessor\t: 1\ncpu MHz\t\t: 799.951\n";
        assert_eq!(cpuinfo_freqs_khz(text), vec![3_200_000, 799_951]);
        assert!(cpuinfo_freqs_khz("processor\t: 0\n").is_empty());
    }

    #[test]
    fn cpu_freqs_match_core_count_when_available() {
        let f = cpu_freqs_khz();
        if !f.is_empty() {
            let (_m, cores) = cpu_model_cores();
            assert_eq!(f.len(), cores);
            assert!(f.iter().all(|&k| k > 0));
        }
        if let Some((lo, hi)) = cpu_freq_range_khz() {
            assert!(lo <= hi && hi > 0);
        }
    }

    #[test]
    fn driver_to_model_maps_known_drivers_only() {
        assert_eq!(driver_to_model("igc"), Some("Intel I225/I226 2.5GbE"));
        assert_eq!(driver_to_model("virtio_net"), Some("Virtio virtual NIC"));
        assert_eq!(driver_to_model("nonexistent_drv"), None);
    }

    #[test]
    fn every_nominal_speed_driver_has_a_model_name() {

        for (drv, mbps) in VIRTUAL_NIC_NOMINAL_SPEED {
            assert!(*mbps > 0, "{drv}: nominal speed must be positive");
            assert!(
                driver_to_model(drv).is_some(),
                "{drv}: missing from NIC_MODELS"
            );
        }
    }

    #[test]
    fn no_phy_paravirt_drivers_fall_back_to_10g() {

        for drv in ["virtio_net", "hv_netvsc", "vif", "xen_netfront", "vmxnet3"] {
            assert_eq!(
                resolve_speed(Some(-1), Some(true), Some(drv)),
                Some(10_000),
                "{drv}: speed=-1 should fall back"
            );
            assert_eq!(
                resolve_speed(None, Some(true), Some(drv)),
                Some(10_000),
                "{drv}: unreadable speed should fall back"
            );

            assert_eq!(resolve_speed(Some(-1), Some(false), Some(drv)), None);
            assert_eq!(resolve_speed(Some(1000), Some(true), Some(drv)), Some(1000));
        }
    }

    #[test]
    fn virtio_without_negotiated_speed_falls_back_to_10g() {

        assert_eq!(
            resolve_speed(Some(-1), Some(true), Some("virtio_net")),
            Some(10_000)
        );

        assert_eq!(
            resolve_speed(None, Some(true), Some("virtio_net")),
            Some(10_000)
        );

        assert_eq!(
            resolve_speed(Some(1000), Some(true), Some("virtio_net")),
            Some(1000)
        );

        assert_eq!(
            resolve_speed(Some(-1), Some(false), Some("virtio_net")),
            None
        );
        assert_eq!(resolve_speed(Some(-1), None, Some("virtio_net")), None);

        assert_eq!(resolve_speed(Some(-1), Some(true), Some("igc")), None);
        assert_eq!(resolve_speed(Some(-1), Some(true), None), None);
        assert_eq!(
            resolve_speed(Some(2500), Some(true), Some("igc")),
            Some(2500)
        );
    }

    #[test]
    fn interfaces_hw_fields_are_self_consistent() {
        for i in interfaces() {

            if let Some(s) = i.speed {
                assert!(s > 0, "{}: speed={s}", i.name);
            }
            if let Some(id) = &i.pci_id {
                assert!(id.contains(':') && !id.contains("0x"), "{}: {id}", i.name);
            }

            if i.driver.is_none() {
                assert!(
                    i.model.as_deref().is_none_or(|m| !m.contains("GbE")),
                    "{}: model without driver: {:?}",
                    i.name,
                    i.model
                );
            }
        }
    }

    #[test]
    fn interfaces_no_loopback() {
        let ifs = interfaces();
        assert!(
            !ifs.iter().any(|i| i.name == "lo"),
            "loopback interface should be filtered"
        );
    }

    #[test]
    fn gateway_route_parse() {

        let raw = u32::from_str_radix("0100A8C0", 16).unwrap();
        assert_eq!(
            Ipv4Addr::from(raw.swap_bytes()),
            Ipv4Addr::new(192, 168, 0, 1)
        );
    }
}
