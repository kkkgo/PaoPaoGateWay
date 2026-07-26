#!/bin/bash

# PaoPaoGateway KVM VM manager (serial console).
# Usage: /root/ppgwVM-arm64.sh [start|stop|restart|status|console|bridge|enable|disable|help]
# Without arguments it opens a menu.

# Arrays hold QEMU's arguments, so this needs bash. Called as "sh ppgwVM-arm64.sh" it
# would otherwise die somewhere further down with a syntax error.
[ -n "$BASH_VERSION" ] || exec bash "$0" "$@"

ISO=${PPGW_ISO:-/root/ppgw-arm64.iso}
BRIDGE=${PPGW_BRIDGE:-br0}
TAP=${PPGW_TAP:-tap1}
PORT=${PPGW_PORT:-4445}
# every core the host has, PPGW_CPUS to pin it to fewer
CPUS=${PPGW_CPUS:-$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null)}
case $CPUS in ''|0|*[!0-9]*) CPUS=4 ;; esac
RAM=${PPGW_RAM:-1024}
MACHINE=${PPGW_MACHINE:-virt,gic-version=max,its=on}
PIDFILE=${PPGW_PIDFILE:-/run/ppgw-vm.pid}
SERVICE=/etc/systemd/system/ppgw-vm.service
# left behind by a bridge that would not come up: the script that puts the old
# configuration back runs detached, with nowhere to print
FAILMARK=/run/ppgw-bridge-failed
# the guest address last seen, so it can be confirmed cheaply next time
GUESTIP=/run/ppgw-guest-ip
RESTORE_SH=/run/ppgw-restore.sh
# What "uninstall" offers to remove again. iproute2 is what check_deps installs
# and is deliberately not here: it is Priority: important, half the system calls
# it, and removing it is how a box loses its network for good.
PKGS_REMOVABLE="qemu-system-arm qemu-utils qemu-efi-aarch64 bridge-utils netcat-openbsd"
SELF=$(readlink -f "$0")
NAME=${PPGW_NAME:-PaoPaoGateway}
# pci gets MSI-X and multiple queues, mmio is the old single-queue transport
NIC=${PPGW_NIC:-pci}
# one queue per vCPU lets the guest spread packet work across cores
QUEUES=${PPGW_QUEUES:-auto}
# virtio-net advertises no link speed unless told to (QEMU defaults to -1), so
# the guest's /sys/class/net/eth0/speed reads back empty. auto = whatever the
# bridge's own uplink negotiated; a number = that many Mbit/s; off = stay quiet.
NIC_SPEED=${PPGW_NIC_SPEED:-auto}
NIC_DUPLEX=${PPGW_NIC_DUPLEX:-full}
# QEMU's virt machine models no thermal sensor and no cpufreq, so the host's
# readings are sampled into a directory and shared into the guest over 9p
HOSTINFO=${PPGW_HOSTINFO:-on}
HOSTINFO_DIR=${PPGW_HOSTINFO_DIR:-/run/ppgw-hostinfo}
HOSTINFO_INTERVAL=${PPGW_HOSTINFO_INTERVAL:-5}
HOSTINFO_TAG=${PPGW_HOSTINFO_TAG:-hostinfo}
SAMPLERPID=${PPGW_SAMPLERPID:-/run/ppgw-sampler.pid}
# The default mirror times out often enough on these boxes to fail an install.
# Before installing anything, both mirrors are timed and the faster one wins.
MIRROR_TEST=${PPGW_MIRROR_TEST:-on}
MIRROR_SECS=${PPGW_MIRROR_SECS:-6}
USTC_HOST=mirrors.ustc.edu.cn
USTC_LIST=${PPGW_USTC_LIST:-/etc/apt/sources.list.d/ppgw-ustc.list}
# apt keeps its package lists per source list; a private directory means this
# script never prunes or replaces what the system's own apt-get update fetched
USTC_LISTDIR=${PPGW_USTC_LISTDIR:-/var/lib/ppgw-apt-lists}
# The uplink's MAC, which is what the guest's own identity is derived from. The
# hostname used to do this job, but every Armbian box is called "armbian" until
# somebody changes it, so two of them handed their guests the same MAC.
uplink_mac() {
    local d n m
    # whatever carries the default route, bridge included: the bridge wears the
    # uplink's MAC, so the answer does not change when the bridge is built
    d=$(ip route show default 2>/dev/null | sed -n 's/.*[[:space:]]dev[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' | head -1)
    for n in "$d" /sys/class/net/*; do
        n=$(basename "$n")
        case $n in lo|''|tap*|tun*|veth*|docker*|virbr*|wg*|zt*|sit0|ip6tnl0) continue ;; esac
        m=$(cat "/sys/class/net/$n/address" 2>/dev/null)
        case $m in ''|00:00:00:00:00:00) continue ;; esac
        echo "$m"
        return 0
    done
    return 1
}

# stable MAC, QEMU's default one clashes with every other default QEMU guest
FINGERPRINT=$(printf '%s-%s' "$(uplink_mac || hostname)" "$TAP" | md5sum)
MAC=${PPGW_MAC:-52:54:00:$(echo "$FINGERPRINT" | sed 's/\(..\)\(..\)\(..\).*/\1:\2:\3/')}
# a stable machine UUID and serial so the guest reports the same identity every boot
UUID=${PPGW_UUID:-$(echo "$FINGERPRINT" | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\).*/\1-\2-\3-\4-\5/')}
SERIAL=${PPGW_SERIAL:-PPGW-$(echo "$FINGERPRINT" | cut -c1-8 | tr 'a-z' 'A-Z')}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok() { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}$*${NC}"; }
err() { echo -e "${RED}$*${NC}" >&2; }

# Straight from the terminal, not from stdin: apt and debconf drain whatever is
# on stdin during an install, and a script piped in from curl has none to begin
# with. read -p writes its prompt to stderr, so this is safe inside $( ).
# somebody is there to answer: a terminal on stdin, or one we can open ourselves.
# A detached or systemd-run copy has neither, and must never stop to ask.
interactive() { [ -t 0 ] || [ -c /dev/tty ]; }

ask() {
    local a
    if [ -c /dev/tty ]; then
        read -r -p "$1${2:+ [$2]}: " a </dev/tty
    else
        read -r -p "$1${2:+ [$2]}: " a
    fi
    echo "${a:-$2}"
}

yesno() {
    local a p
    p="$1 [$([ "$2" = y ] && echo Y/n || echo y/N)]: "
    if [ -c /dev/tty ]; then
        read -r -p "$p" a </dev/tty
    else
        read -r -p "$p" a
    fi
    a=${a:-$2}
    case $a in [Yy]*) return 0 ;; *) return 1 ;; esac
}

find_bios() {
    for f in /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
             /usr/share/AAVMF/AAVMF_CODE.no-secboot.fd \
             /usr/share/AAVMF/AAVMF_CODE.fd \
             /usr/share/qemu/edk2-aarch64-code.fd; do
        [ -f "$f" ] && { echo "$f"; return 0; }
    done
    return 1
}

os_field() { sed -n "s/^$1=//p" /etc/os-release 2>/dev/null | tr -d '"' | head -1; }

# what this distro is called on the USTC mirror
# -> USTC_BASE, USTC_SUITE, USTC_COMP, USTC_SEC, USTC_SECSUITE
ustc_repo() {
    local id arch
    id=$(os_field ID)
    # Armbian, Mint, Zorin and friends only name their base in ID_LIKE
    case $id in
        debian|raspbian|ubuntu) ;;
        *) case " $(os_field ID_LIKE) " in
               *" ubuntu "*) id=ubuntu ;;
               *" debian "*) id=debian ;;
           esac ;;
    esac
    # a derivative's own codename is not a suite on the mirror, its base's is
    USTC_SUITE=$(os_field UBUNTU_CODENAME)
    [ -n "$USTC_SUITE" ] || USTC_SUITE=$(os_field VERSION_CODENAME)
    [ -n "$USTC_SUITE" ] || USTC_SUITE=$(lsb_release -cs 2>/dev/null)
    [ -n "$USTC_SUITE" ] || return 1
    arch=$(dpkg --print-architecture 2>/dev/null)
    case $id in
        debian|raspbian)
            USTC_BASE="https://$USTC_HOST/debian"
            USTC_SEC="https://$USTC_HOST/debian-security"
            USTC_COMP="main contrib non-free"
            # bookworm split the firmware out into a component of its own
            case $USTC_SUITE in
                bookworm|trixie|forky|sid) USTC_COMP="$USTC_COMP non-free-firmware" ;;
            esac
            case $USTC_SUITE in
                stretch|buster) USTC_SECSUITE="$USTC_SUITE/updates" ;;
                *) USTC_SECSUITE="$USTC_SUITE-security" ;;
            esac
            ;;
        ubuntu)
            # only x86 lives under /ubuntu, every other port is under /ubuntu-ports
            case $arch in
                amd64|i386) USTC_BASE="https://$USTC_HOST/ubuntu" ;;
                *) USTC_BASE="https://$USTC_HOST/ubuntu-ports" ;;
            esac
            USTC_SEC=$USTC_BASE
            USTC_SECSUITE="$USTC_SUITE-security"
            USTC_COMP="main restricted universe multiverse"
            ;;
        *) return 1 ;;
    esac
    # unstable has no -updates and no security suite
    case $USTC_SUITE in sid|unstable) USTC_SEC="" ;; esac
    return 0
}

# -> "URL SUITE" of the mirror apt fetches the base system from
current_repo() {
    local pairs pick f
    pairs=$( {
        # "deb [arch=...] URI SUITE components..."
        grep -rhs '^[[:space:]]*deb[[:space:]]' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null \
            | sed 's/\[[^]]*\]//' | awk 'NF>2 {print $2, $3}'
        # deb822 puts the same two fields on lines of their own, one repo per file
        for f in /etc/apt/sources.list.d/*.sources; do
            [ -f "$f" ] || continue
            awk '/^[[:space:]]*URIs:/ && !u {u=$2} /^[[:space:]]*Suites:/ && !s {s=$2} END {if (u && s) print u, s}' "$f"
        done
    } 2>/dev/null | grep '^http' | grep -v "$USTC_HOST" )
    [ -n "$pairs" ] || return 1
    # the distro's own archive, not whichever third-party repo happens to sort first
    pick=$(echo "$pairs" | grep -E '/(debian|ubuntu|ubuntu-ports|raspbian)/? ' | head -1)
    [ -n "$pick" ] || pick=$(echo "$pairs" | head -1)
    set -- $pick
    echo "${1%/} $2"
}

# -> "BYTES MS", what a mirror delivered of a real index and how long it took.
# A mirror that answers quickly and then trickles is exactly what times an
# install out, so this measures the transfer rather than the handshake. Where
# both finish the file inside the window the byte counts are identical, and the
# times are then the only thing that tells them apart.
fetch_sample() {
    local n t0 t1
    t0=$(date +%s%N)
    # curl prints the write-out even when the transfer is cut short by --max-time
    n=$(curl -sfL --max-time "$MIRROR_SECS" -o /dev/null -w '%{size_download}' "$1" 2>/dev/null)
    t1=$(date +%s%N)
    case $n in ''|0|*[!0-9]*) return 1 ;; esac
    echo "$n $(( (t1 - t0) / 1000000 ))"
}

# milliseconds to fetch a URL, nothing at all if it never answered
fetch_ms() {
    local url=$1 t0 t1 best= ms i
    # two goes, the quicker one counts; a mirror that fails once is not worth
    # waiting on a second time
    for i in 1 2; do
        t0=$(date +%s%N)
        if command -v curl >/dev/null; then
            curl -sfL --max-time 8 -o /dev/null "$url" 2>/dev/null || break
        else
            wget -q -T 8 -O /dev/null "$url" 2>/dev/null || break
        fi
        t1=$(date +%s%N)
        ms=$(( (t1 - t0) / 1000000 ))
        [ -z "$best" ] || [ "$ms" -lt "$best" ] && best=$ms
    done
    [ -n "$best" ] || return 1
    echo "$best"
}

write_ustc_list() {
    {
        echo "# added by ppgwVM-arm64.sh: $USTC_HOST answered faster than $1"
        echo "deb $USTC_BASE $USTC_SUITE $USTC_COMP"
        if [ -n "$USTC_SEC" ]; then
            echo "deb $USTC_BASE $USTC_SUITE-updates $USTC_COMP"
            echo "deb $USTC_SEC $USTC_SECSUITE $USTC_COMP"
        fi
    } >"$USTC_LIST" || return 1
}

# Time the configured mirror against USTC and, if USTC wins, add it as a source
# and point this install at it. -> APT_ARGS, empty when nothing changed.
use_faster_mirror() {
    APT_ARGS=()
    [ "$MIRROR_TEST" = on ] || return 0
    command -v curl >/dev/null || command -v wget >/dev/null || return 0
    if grep -rqs "$USTC_HOST" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
        echo "Already on $USTC_HOST."
        return 0
    fi
    ustc_repo || return 0
    local cur uri suite arch now fast switch=""
    cur=$(current_repo) || return 0
    set -- $cur
    uri=$1
    suite=$2
    arch=$(dpkg --print-architecture 2>/dev/null)

    echo "Timing mirrors (a slow one is what makes these installs fail)..."
    if [ -n "$arch" ] && command -v curl >/dev/null; then
        local nowb nowms fastb fastms
        now=$(fetch_sample "$uri/dists/$suite/main/binary-$arch/Packages.gz")
        fast=$(fetch_sample "$USTC_BASE/dists/$USTC_SUITE/main/binary-$arch/Packages.gz")
        if [ -n "$now" ] && [ -n "$fast" ]; then
            set -- $now;  nowb=$1;  nowms=$2
            set -- $fast; fastb=$1; fastms=$2
            echo "  $uri: $((nowb / 1024)) KB in ${nowms} ms"
            echo "  $USTC_BASE: $((fastb / 1024)) KB in ${fastms} ms"
            if [ "$nowb" = "$fastb" ]; then
                # both served the whole index, so the quicker one is the faster one
                [ $((fastms * 4)) -lt $((nowms * 3)) ] && switch=yes || switch=no
            else
                # 25% more data inside the same window is worth switching for
                [ $((fastb * 4)) -gt $((nowb * 5)) ] && switch=yes || switch=no
            fi
        fi
    fi
    if [ -z "$switch" ]; then
        # no curl, or one of them would not serve an index: fall back to latency
        now=$(fetch_ms "$uri/dists/$suite/Release")
        fast=$(fetch_ms "$USTC_BASE/dists/$USTC_SUITE/Release")
        echo "  $uri: ${now:-no answer}${now:+ ms}"
        echo "  $USTC_BASE: ${fast:-no answer}${fast:+ ms}"
        [ -n "$fast" ] || return 0
        if [ -n "$now" ]; then
            [ $((fast * 4)) -lt $((now * 3)) ] && switch=yes || switch=no
        else
            switch=yes
        fi
    fi
    [ "$switch" = "yes" ] || return 0

    write_ustc_list "$uri" || { warn "Cannot write $USTC_LIST."; return 0; }
    ok "Added $USTC_LIST, installing from $USTC_HOST."
    mkdir -p "$USTC_LISTDIR/partial"
    APT_ARGS=(-o "Dir::Etc::SourceList=$USTC_LIST"
              -o "Dir::Etc::SourceParts=-"
              -o "Dir::State::Lists=$USTC_LISTDIR")
}

# install whatever is missing, one apt-get call
check_deps() {
    local miss_cmd=() miss_pkg=()
    command -v qemu-system-aarch64 >/dev/null || { miss_cmd+=(qemu-system-aarch64); miss_pkg+=(qemu-system-arm); }
    command -v qemu-img >/dev/null || { miss_cmd+=(qemu-img); miss_pkg+=(qemu-utils); }
    command -v nc >/dev/null || { miss_cmd+=(nc); miss_pkg+=(netcat-openbsd); }
    command -v brctl >/dev/null || { miss_cmd+=(brctl); miss_pkg+=(bridge-utils); }
    command -v ip >/dev/null || { miss_cmd+=(ip); miss_pkg+=(iproute2); }
    find_bios >/dev/null || { miss_cmd+=(QEMU_EFI.fd); miss_pkg+=(qemu-efi-aarch64); }

    [ ${#miss_pkg[@]} -eq 0 ] && return 0

    warn "Missing: ${miss_cmd[*]}"
    echo "Packages: ${miss_pkg[*]}"
    if ! command -v apt-get >/dev/null; then
        err "No apt-get here, install them by hand."
        return 1
    fi
    if [ "$(id -u)" != "0" ]; then
        err "Run as root to install: apt-get install -y ${miss_pkg[*]}"
        return 1
    fi
    echo "Installing..."
    use_faster_mirror
    apt-get "${APT_ARGS[@]}" update -qq
    if ! apt-get "${APT_ARGS[@]}" install -y "${miss_pkg[@]}"; then
        if [ ${#APT_ARGS[@]} -gt 0 ]; then
            warn "$USTC_HOST could not serve them, falling back to the configured mirror."
            apt-get update -qq
            apt-get install -y "${miss_pkg[@]}" || { err "Install failed."; return 1; }
        else
            err "Install failed."
            return 1
        fi
    fi
    ok "Packages installed."
}

# ---------------------------------------------------------------- host bridge

# physical interfaces that could carry the bridge
list_uplinks() {
    local d n
    for d in /sys/class/net/*/; do
        n=$(basename "$d")
        case $n in lo|tap*|tun*|docker*|veth*|virbr*|br-*|wg*|zt*|dummy*) continue ;; esac
        # a bridge, a bond member's master or any purely virtual device has no
        # device link back to a real bus
        [ -e "$d/device" ] || continue
        [ -d "$d/bridge" ] && continue
        [ -d "$d/wireless" ] && continue
        echo "$n"
    done
}

default_iface() {
    ip route show default 2>/dev/null | sed -n 's/.*[[:space:]]dev[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' | head -1
}

iface_cidr() { ip -4 -o addr show dev "$1" 2>/dev/null | awk '{print $4; exit}'; }
iface_gw() { ip route show default 2>/dev/null | sed -n "s/.*via[[:space:]]\{1,\}\([^[:space:]]*\).*dev[[:space:]]\{1,\}$1\([[:space:]].*\)\?$/\1/p" | head -1; }
# systemd-resolved's stub is no use to anyone but this host, so where resolv.conf
# only points at 127.0.0.53 the real servers have to come from resolved itself
host_dns() {
    local d
    d=$(awk '$1=="nameserver" && $2 !~ /^127\./ {print $2}' /etc/resolv.conf 2>/dev/null | head -2)
    if [ -z "$d" ] && command -v resolvectl >/dev/null; then
        d=$(resolvectl dns 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$' | grep -v '^127\.' | head -2)
    fi
    [ -n "$d" ] || return 1
    echo $d
}

# Is the uplink's address handed out or set by hand? -> dhcp|static
# The kernel flags a leased address "dynamic" whoever asked for it, which beats
# guessing from whichever backend's config file happens to mention the interface.
iface_mode() {
    local ifc=$1 p m f
    case " $(ip -4 -o addr show dev "$ifc" 2>/dev/null) " in
        *" dynamic "*) echo dhcp; return 0 ;;
    esac
    if command -v nmcli >/dev/null; then
        p=$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null | awk -F: -v d="$ifc" '$2 == d {print $1; exit}')
        if [ -n "$p" ]; then
            m=$(nmcli -g ipv4.method connection show "$p" 2>/dev/null)
            [ "$m" = "manual" ] && { echo static; return 0; }
            [ "$m" = "auto" ] && { echo dhcp; return 0; }
        fi
    fi
    grep -rqs "iface[[:space:]]\{1,\}$ifc[[:space:]]\{1,\}inet[[:space:]]\{1,\}static" \
        /etc/network/interfaces /etc/network/interfaces.d/ 2>/dev/null && { echo static; return 0; }
    for f in /etc/netplan/*.yaml /etc/systemd/network/*.network; do
        [ -f "$f" ] || continue
        grep -q "$ifc" "$f" || continue
        grep -qE '^[[:space:]]*(dhcp4:[[:space:]]*(true|yes)|DHCP=(yes|ipv4|both))' "$f" && { echo dhcp; return 0; }
        grep -qE '^[[:space:]]*(addresses:|Address=)' "$f" && { echo static; return 0; }
    done
    # an address nothing claims to have leased is one somebody set
    [ -n "$(iface_cidr "$ifc")" ] && { echo static; return 0; }
    echo dhcp
}

valid_ip() {
    local ip=$1 o
    local IFS=.
    set -- $ip
    [ $# -eq 4 ] || return 1
    for o in "$@"; do
        case $o in ''|*[!0-9]*) return 1 ;; esac
        [ "$o" -gt 255 ] && return 1
    done
    return 0
}

valid_cidr() {
    local a=${1%/*} p=${1##*/}
    [ "$1" != "$a" ] || return 1
    case $p in ''|*[!0-9]*) return 1 ;; esac
    [ "$p" -ge 1 ] && [ "$p" -le 32 ] || return 1
    valid_ip "$a"
}

# whoever owns this host's network config, in the order they take precedence
net_backend() {
    if command -v nmcli >/dev/null && systemctl is-active --quiet NetworkManager 2>/dev/null; then
        echo nm; return 0
    fi
    if command -v netplan >/dev/null && ls /etc/netplan/*.yaml >/dev/null 2>&1; then
        echo netplan; return 0
    fi
    if systemctl is-active --quiet systemd-networkd 2>/dev/null; then
        echo networkd; return 0
    fi
    [ -f /etc/network/interfaces ] && { echo ifupdown; return 0; }
    return 1
}

# comment out every stanza that configures $1, so only the bridge claims it
comment_out_iface() {
    awk -v ifc="$1" '
        $0 ~ "^[[:space:]]*(auto|allow-hotplug)[[:space:]]+" ifc "([[:space:]]|$)" { print "#ppgw# " $0; next }
        $0 ~ "^[[:space:]]*iface[[:space:]]+" ifc "[[:space:]]" { skip = 1; print "#ppgw# " $0; next }
        skip && /^[[:space:]]+[^[:space:]]/ { print "#ppgw# " $0; next }
        { skip = 0; print }
    ' "$2"
}

bridge_ifupdown() {
    local f=/etc/network/interfaces.d/ppgw-$BRIDGE t
    mkdir -p /etc/network/interfaces.d
    for t in /etc/network/interfaces /etc/network/interfaces.d/*; do
        [ -f "$t" ] || continue
        [ "$t" = "$f" ] && continue
        case $t in *.ppgw.bak) continue ;; esac
        grep -q "[[:space:]]$BR_UP\([[:space:]]\|$\)" "$t" || continue
        cp -a "$t" "$t.ppgw.bak"
        comment_out_iface "$BR_UP" "$t.ppgw.bak" >"$t" || return 1
        echo "  $t (was $t.ppgw.bak)"
    done
    {
        echo "# written by ppgwVM-arm64.sh"
        echo "auto $BR_UP"
        echo "iface $BR_UP inet manual"
        echo ""
        echo "auto $BRIDGE"
        if [ "$BR_MODE" = dhcp ]; then
            echo "iface $BRIDGE inet dhcp"
        else
            echo "iface $BRIDGE inet static"
            echo "    address $BR_ADDR"
            echo "    gateway $BR_GW"
            [ -n "$BR_DNS" ] && echo "    dns-nameservers $BR_DNS"
        fi
        echo "    bridge_ports $BR_UP"
        # the uplink's MAC, so DHCP keeps handing out the same lease
        [ -n "$BR_MAC" ] && echo "    bridge_hw $BR_MAC"
        echo "    bridge_stp off"
        echo "    bridge_fd 0"
        echo "    bridge_maxwait 5"
    } >"$f" || return 1
    grep -qs '^source' /etc/network/interfaces || printf '\nsource /etc/network/interfaces.d/*\n' >>/etc/network/interfaces
    echo "  $f"
}

bridge_netplan() {
    local f=/etc/netplan/99-ppgw-$BRIDGE.yaml
    {
        echo "# written by ppgwVM-arm64.sh"
        echo "network:"
        echo "  version: 2"
        echo "  ethernets:"
        echo "    $BR_UP:"
        echo "      dhcp4: false"
        echo "      dhcp6: false"
        echo "  bridges:"
        echo "    $BRIDGE:"
        echo "      interfaces: [$BR_UP]"
        # keeping the uplink's MAC keeps the DHCP lease, and the address with it
        [ -n "$BR_MAC" ] && echo "      macaddress: $BR_MAC"
        echo "      parameters:"
        echo "        stp: false"
        echo "        forward-delay: 0"
        if [ "$BR_MODE" = dhcp ]; then
            echo "      dhcp4: true"
        else
            echo "      dhcp4: false"
            echo "      addresses: [$BR_ADDR]"
            echo "      routes:"
            echo "        - to: default"
            echo "          via: $BR_GW"
            [ -n "$BR_DNS" ] && {
                echo "      nameservers:"
                echo "        addresses: [${BR_DNS// /, }]"
            }
        fi
    } >"$f" || return 1
    # netplan refuses to read a world-readable file since 0.106
    chmod 600 "$f"
    netplan generate >/dev/null 2>&1 || warn "netplan generate complained, check $f"
    echo "  $f"
}

bridge_networkd() {
    local d=/etc/systemd/network s
    mkdir -p "$d"
    {
        printf '# written by ppgwVM-arm64.sh\n[NetDev]\nName=%s\nKind=bridge\n' "$BRIDGE"
        # same MAC as the uplink, or DHCP treats the bridge as a new host
        [ -n "$BR_MAC" ] && printf 'MACAddress=%s\n' "$BR_MAC"
    } >"$d/10-ppgw-$BRIDGE.netdev" || return 1
    # lower numbers win, so this beats any 80-*.network the distro ships
    printf '# written by ppgwVM-arm64.sh\n[Match]\nName=%s\n\n[Network]\nBridge=%s\n' \
        "$BR_UP" "$BRIDGE" >"$d/20-ppgw-$BR_UP.network" || return 1
    {
        printf '# written by ppgwVM-arm64.sh\n[Match]\nName=%s\n\n[Network]\n' "$BRIDGE"
        if [ "$BR_MODE" = dhcp ]; then
            printf 'DHCP=ipv4\n'
        else
            printf 'Address=%s\nGateway=%s\n' "$BR_ADDR" "$BR_GW"
            for s in $BR_DNS; do printf 'DNS=%s\n' "$s"; done
        fi
    } >"$d/30-ppgw-$BRIDGE.network" || return 1
    echo "  $d/10-ppgw-$BRIDGE.netdev"
    echo "  $d/20-ppgw-$BR_UP.network"
    echo "  $d/30-ppgw-$BRIDGE.network"
}

# NetworkManager keeps its own database, so this goes through nmcli. The
# profiles are created but not brought up: activating them here would cut the
# session off halfway through.
bridge_nm() {
    local slave=$BRIDGE-slave-$BR_UP uuid ifn id
    nmcli connection delete "$BRIDGE" >/dev/null 2>&1
    nmcli connection delete "$slave" >/dev/null 2>&1
    # autoconnect off while it is built: NetworkManager activates a bridge the
    # moment the profile lands, and a half-configured one comes up on a MAC of
    # its own invention
    nmcli connection add type bridge ifname "$BRIDGE" con-name "$BRIDGE" \
        bridge.stp no connection.autoconnect no >/dev/null || return 1
    # that invented MAC is what makes the DHCP server hand out a new lease, and
    # the host come back on a different address
    [ -n "$BR_MAC" ] && nmcli connection modify "$BRIDGE" bridge.mac-address "$BR_MAC" >/dev/null
    if [ "$BR_MODE" = dhcp ]; then
        nmcli connection modify "$BRIDGE" ipv4.method auto ipv6.method auto || return 1
    else
        nmcli connection modify "$BRIDGE" \
            ipv4.method manual ipv4.addresses "$BR_ADDR" ipv4.gateway "$BR_GW" \
            ${BR_DNS:+ipv4.dns "$BR_DNS"} ipv6.method auto || return 1
    fi
    # a priority above the default 0 keeps the uplink's old profile from racing
    # this one for the interface at boot
    nmcli connection add type ethernet ifname "$BR_UP" master "$BRIDGE" \
        con-name "$slave" connection.autoconnect yes \
        connection.autoconnect-priority 10 >/dev/null || return 1
    # fully built now, so it may come up on its own from here on
    nmcli connection modify "$BRIDGE" connection.autoconnect yes >/dev/null
    # the uplink's old profile would grab it first and leave the bridge empty
    for uuid in $(nmcli -t -f UUID connection show 2>/dev/null); do
        id=$(nmcli -g connection.id connection show "$uuid" 2>/dev/null)
        [ "$id" = "$BRIDGE" ] || [ "$id" = "$slave" ] && continue
        ifn=$(nmcli -g connection.interface-name connection show "$uuid" 2>/dev/null)
        [ "$ifn" = "$BR_UP" ] || continue
        nmcli connection modify "$uuid" connection.autoconnect no >/dev/null 2>&1 \
            && echo "  autoconnect off: $id"
        # by UUID, not by name: profiles are called things like "有线连接 1"
        NM_OLD="$NM_OLD $uuid"
    done
    echo "  nmcli profiles: $BRIDGE, $slave"
}

# The steps that put the new configuration on the air, written out as a script
# of their own: run detached it outlives the session the link is about to drop,
# and it can put the old address back if the bridge never comes up, which is the
# difference between a blip and a box nobody can reach. -> APPLY_SH
write_apply_script() {
    local c
    APPLY_SH=/run/ppgw-bridge-up.sh
    {
        echo "#!/bin/sh"
        echo "sleep 1"
        case $1 in
            nm)
                for c in $NM_OLD; do
                    echo "nmcli -w 10 connection down uuid $c >/dev/null 2>&1"
                done
                # anything NetworkManager brought up by itself is not carrying
                # the settings written above
                echo "nmcli -w 10 connection down '$BRIDGE' >/dev/null 2>&1"
                # -w 0: a bridge with no port yet has no carrier, so waiting for
                # it to finish DHCP here would block until the port is in, which
                # is the very next line
                echo "nmcli -w 0 connection up '$BRIDGE'"
                echo "nmcli -w 20 connection up '$BRIDGE-slave-$BR_UP'"
                ;;
            netplan)
                echo "netplan apply >/dev/null 2>&1"
                ;;
            networkd)
                echo "networkctl reload >/dev/null 2>&1"
                echo "systemctl restart systemd-networkd >/dev/null 2>&1"
                ;;
            ifupdown)
                echo "ifdown '$BR_UP' >/dev/null 2>&1"
                echo "ifup '$BRIDGE' >/dev/null 2>&1"
                ;;
        esac
        # DHCP can take a while, so give it one before calling this a failure
        echo "i=0"
        echo "while [ \$i -lt 25 ]; do"
        echo "    if ip -4 -o addr show dev $BRIDGE 2>/dev/null | grep -q inet; then"
        # bash, not sh: this script is run through whichever /bin/sh is around,
        # and the one it calls is full of arrays
        [ "$2" = "start" ] && echo "        NOCONSOLE=1 bash '$SELF' start"
        echo "        exit 0"
        echo "    fi"
        echo "    i=\$((i + 1)); sleep 1"
        echo "done"
        # Rescue: hand the uplink its old address back so the box stays reachable,
        # and leave it configured the way it was, or the next reboot drops it
        # straight back into whatever just failed.
        echo "printf '$BRIDGE did not come up (%s), $BR_UP was put back as it was. See $APPLY_SH.log\\n' \"\$(date '+%F %T')\" >$FAILMARK"
        if [ "$1" = "nm" ] && [ -n "$NM_OLD" ]; then
            echo "nmcli -w 10 connection down '$BRIDGE' >/dev/null 2>&1"
            echo "nmcli connection modify '$BRIDGE' connection.autoconnect no >/dev/null 2>&1"
            echo "nmcli connection modify '$BRIDGE-slave-$BR_UP' connection.autoconnect no >/dev/null 2>&1"
            for c in $NM_OLD; do
                echo "nmcli connection modify $c connection.autoconnect yes >/dev/null 2>&1"
                echo "nmcli -w 20 connection up uuid $c >/dev/null 2>&1"
            done
        elif [ -n "$BR_OLD_CIDR" ]; then
            echo "ip link set $BR_UP nomaster 2>/dev/null"
            echo "ip addr add $BR_OLD_CIDR dev $BR_UP 2>/dev/null"
            echo "ip link set $BR_UP up"
            [ -n "$BR_OLD_GW" ] && echo "ip route add default via $BR_OLD_GW dev $BR_UP 2>/dev/null"
        fi
        echo "exit 1"
    } >"$APPLY_SH"
    chmod +x "$APPLY_SH"
}

# Offered when the bridge the VM needs is not there. Everything is asked up
# front, before anything is written, because the answers decide whether this
# host keeps the address the caller is connected on.
setup_bridge() {
    if [ -f "$FAILMARK" ]; then
        warn "$(cat "$FAILMARK")"
        rm -f "$FAILMARK"
    fi
    if ip link show "$BRIDGE" >/dev/null 2>&1; then
        # NetworkManager creates the device the moment the profile is added, so
        # a bridge with nothing in it is one that was configured but never applied
        warn "$BRIDGE exists but has no interface in it."
    else
        err "Bridge not found: $BRIDGE"
        echo "Bridges here:"
        ip -br link show type bridge 2>/dev/null | sed 's/^/  /' | grep . || echo "  none"
    fi
    if ! interactive; then
        echo "Pick one: PPGW_BRIDGE=<name> $SELF start"
        return 1
    fi
    if [ "$(id -u)" != "0" ]; then
        echo "Run as root to have $BRIDGE created, or pick one: PPGW_BRIDGE=<name> $SELF start"
        return 1
    fi
    echo ""
    yesno "Set $BRIDGE up on this host?" y || {
        echo "Pick an existing one: PPGW_BRIDGE=<name> $SELF start"
        return 1
    }

    local backend ups n def
    backend=$(net_backend) || {
        err "No network backend found (NetworkManager, netplan, systemd-networkd, ifupdown)."
        return 1
    }
    ups=$(list_uplinks)
    [ -n "$ups" ] || { err "No physical interface to put into $BRIDGE."; return 1; }
    def=$(default_iface)
    n=$(echo "$ups" | wc -l)
    if [ "$n" = "1" ]; then
        BR_UP=$ups
    else
        echo ""
        echo "Interfaces:"
        ip -br addr show 2>/dev/null | grep -E "^($(echo "$ups" | tr '\n' '|' | sed 's/|$//')) " | sed 's/^/  /'
        BR_UP=$(ask "Which one goes into $BRIDGE" "${def:-$(echo "$ups" | head -1)}")
    fi
    ip link show "$BR_UP" >/dev/null 2>&1 || { err "No such interface: $BR_UP"; return 1; }
    BR_MAC=$(cat "/sys/class/net/$BR_UP/address" 2>/dev/null)

    # on a second run the uplink may already sit in a half-configured bridge, so
    # whatever is holding the address now is what the answers default to
    local from=$BR_UP mode
    [ -n "$(iface_cidr "$from")" ] || from=$BRIDGE
    BR_OLD_CIDR=$(iface_cidr "$from")
    BR_OLD_GW=$(iface_gw "$from")
    mode=$(iface_mode "$from")

    echo ""
    echo "Backend: $backend, uplink: $BR_UP (${BR_OLD_CIDR:-no address}, $mode)"
    echo "$BRIDGE takes the address over from $BR_UP, keeping ${BR_UP}'s MAC so a DHCP"
    echo "server hands back the same lease."
    echo ""
    BR_ADDR=""; BR_GW=""; BR_DNS=""
    # whatever this host is on now is what it keeps unless it is told otherwise
    if [ "$mode" = "static" ]; then
        if yesno "$BR_UP is set up statically. Keep it static on $BRIDGE?" y; then
            BR_MODE=static
        else
            BR_MODE=dhcp
        fi
    elif yesno "Keep DHCP on $BRIDGE? (no = static address)" y; then
        BR_MODE=dhcp
    else
        BR_MODE=static
    fi
    if [ "$BR_MODE" = "static" ]; then
        while :; do
            BR_ADDR=$(ask "Address/prefix" "$BR_OLD_CIDR")
            valid_cidr "$BR_ADDR" && break
            err "Wanted something like 192.168.1.2/24, got: $BR_ADDR"
        done
        while :; do
            BR_GW=$(ask "Gateway" "$BR_OLD_GW")
            valid_ip "$BR_GW" && break
            err "Not an IPv4 address: $BR_GW"
        done
        # a router that hands out addresses almost always resolves as well
        BR_DNS=$(ask "DNS servers (space separated)" "$(host_dns || echo "$BR_GW")")
        set -- $BR_DNS
        BR_DNS="$*"
    fi

    echo ""
    echo "About to configure: $BRIDGE <- $BR_UP, $BR_MODE${BR_ADDR:+ $BR_ADDR gw $BR_GW}${BR_DNS:+ dns $BR_DNS}"
    warn "Moving the address onto $BRIDGE blinks the link for a few seconds, which"
    if [ "$BR_MODE" = "static" ]; then
        warn "drops this session. It comes back on $BR_ADDR."
    else
        warn "drops this session. $BRIDGE asks for the lease with ${BR_UP}'s own MAC,"
        warn "so it comes back on ${BR_OLD_CIDR:-the same address}."
    fi
    yesno "Write it and bring it up now?" y || { echo "Nothing was changed."; return 1; }

    NM_OLD=""
    case $backend in
        nm)       bridge_nm ;;
        netplan)  bridge_netplan ;;
        networkd) bridge_networkd ;;
        ifupdown) bridge_ifupdown ;;
    esac || { err "Could not write the $backend config."; return 1; }
    ok "$backend config for $BRIDGE written."

    # Over SSH the session is the first thing the link takes with it, so the
    # switch and the VM start are handed to a detached copy that survives it.
    if [ -n "$SSH_CONNECTION" ]; then
        write_apply_script "$backend" start
        warn "Applying now. The link goes quiet for a few seconds."
        # Through sh, not as a program: /run is mounted noexec on plenty of
        # distros. Ignoring HUP and sleeping before the exit matter too: sshd
        # tears the session down the moment this script ends, and it took the
        # detaching child with it before setsid had run.
        if command -v setsid >/dev/null; then
            ( trap '' HUP; setsid sh "$APPLY_SH" </dev/null >"$APPLY_SH.log" 2>&1 & )
        else
            ( trap '' HUP; nohup sh "$APPLY_SH" </dev/null >"$APPLY_SH.log" 2>&1 & )
        fi
        # The address and the MAC both stay put, so this session usually rides
        # out the gap; the pidfile is local, so waiting works even while the
        # link is down. If the session did die, the detached copy has the VM
        # covered anyway and there is nobody left here to show a console to.
        local i
        for i in $(seq 1 45); do
            is_running && break
            sleep 1
        done
        if is_running; then
            ok "$BRIDGE is up: $(iface_cidr "$BRIDGE") via $(bridge_uplink "$BRIDGE")"
            show_status
            echo ""
            do_console
            exit 0
        fi
        [ -f "$FAILMARK" ] && { err "$(cat "$FAILMARK")"; rm -f "$FAILMARK"; }
        err "$BRIDGE did not come up in time, see $APPLY_SH.log"
        exit 1
    fi
    # At the console nothing is about to be cut off, so this runs in the open and
    # the caller carries on into the VM start itself
    write_apply_script "$backend"
    echo "Applying..."
    sh "$APPLY_SH" 2>&1 | tee "$APPLY_SH.log"
    if [ -n "$(iface_cidr "$BRIDGE")" ]; then
        ok "$BRIDGE is up: $(iface_cidr "$BRIDGE") via $(bridge_uplink "$BRIDGE")"
        return 0
    fi
    err "$BRIDGE never got an address, ${BR_UP}'s own configuration was put back."
    return 1
}

# A bridge with nothing but the guest's tap in it goes nowhere. NetworkManager
# creates the device as soon as the profile is added, so this is what a
# configured-but-not-yet-applied bridge looks like.
bridge_uplink() {
    local p n
    for p in /sys/class/net/"$1"/brif/*; do
        [ -e "$p" ] || continue
        n=$(basename "$p")
        case $n in "$TAP"|tap*|tun*) continue ;; esac
        echo "$n"
        return 0
    done
    return 1
}

do_bridge() {
    if ip link show "$BRIDGE" >/dev/null 2>&1 && bridge_uplink "$BRIDGE" >/dev/null; then
        ok "$BRIDGE is already there."
        ip -br addr show "$BRIDGE" | sed 's/^/  /'
        echo "Members:"
        ls /sys/class/net/"$BRIDGE"/brif 2>/dev/null | sed 's/^/  /' | grep . || echo "  none"
        return 0
    fi
    # the bridge exists to carry the guest, so having built it, get on with that
    setup_bridge && do_start
}

check_env() {
    check_deps || return 1
    BIOS=$(find_bios) || { err "No aarch64 UEFI firmware found."; return 1; }
    MACHINE_VER=$(qemu-system-aarch64 --version 2>/dev/null | sed -n '1s/.*version \([0-9.]*\).*/\1/p')
    MACHINE_VER=${MACHINE_VER:-unknown}
    if [ ! -f "$ISO" ]; then
        err "ISO not found: $ISO"
        echo "Copy the image there, or run: PPGW_ISO=/path/to.iso $SELF start"
        return 1
    fi
    if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
        setup_bridge || return 1
    fi
    if ! bridge_uplink "$BRIDGE" >/dev/null; then
        warn "$BRIDGE has no interface in it, so the guest reaches nothing but this host."
        warn "Put one in with: $SELF bridge"
    fi
    if [ ! -w /dev/kvm ]; then
        warn "No /dev/kvm, running without KVM (slow)."
        ACCEL=""
        # -cpu host needs KVM, TCG cannot do it
        CPU=${PPGW_CPU:-max}
    else
        ACCEL="-enable-kvm"
        # host passes the physical CPU's features straight through to the guest
        CPU=${PPGW_CPU:-host}
    fi
}

is_running() {
    [ -f "$PIDFILE" ] || return 1
    local pid
    pid=$(cat "$PIDFILE" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        return 0
    fi
    rm -f "$PIDFILE"
    return 1
}

port_busy() {
    ss -tln 2>/dev/null | grep -q ":$PORT "
}

neigh_addr() {
    ip neigh show 2>/dev/null | awk -v m="${1,,}" -v pat="$2" 'tolower($5) == m && $1 ~ pat {print $1; exit}'
}

# The guest's own address, as far as this host can tell. Its ARP entry lives on
# the bridge rather than on the tap, and only appears once the guest has had
# reason to ARP for this host, which it mostly has not. So: try the neighbour
# table, then the address it had last time (pinging a known address resolves
# ARP, and the entry that comes back says whether it is still this guest), then
# a broadcast ping in case anything answers. Failing all that, the link-local is
# derived from the MAC and is always there, which at least proves it is alive.
guest_addr() {
    local mac=$1 a bc
    a=$(neigh_addr "$mac" '^[0-9]+\.')
    if [ -z "$a" ] && [ -s "$GUESTIP" ]; then
        ping -c1 -W1 "$(cat "$GUESTIP")" >/dev/null 2>&1
        a=$(neigh_addr "$mac" '^[0-9]+\.')
    fi
    if [ -z "$a" ]; then
        bc=$(ip -4 -o addr show dev "$BRIDGE" 2>/dev/null | sed -n 's/.*brd \([0-9.]*\).*/\1/p' | head -1)
        [ -n "$bc" ] && ping -b -w1 "$bc" >/dev/null 2>&1
        a=$(neigh_addr "$mac" '^[0-9]+\.')
    fi
    if [ -n "$a" ]; then
        echo "$a" >"$GUESTIP" 2>/dev/null
        echo "$a"
        return 0
    fi
    a=$(neigh_addr "$mac" ':') || return 1
    [ -n "$a" ] || return 1
    echo "$a (link-local, IPv4 not seen)"
}

show_status() {
    echo "======================================"
    echo "        PaoPaoGateway VM"
    echo "======================================"
    if is_running; then
        # read these back off the running QEMU rather than guessing from the env:
        # a VM started before a setting changed still runs with the old one
        local pid cmd nq rmac
        pid=$(cat "$PIDFILE")
        cmd=$(tr '\0' '\n' <"/proc/$pid/cmdline" 2>/dev/null)
        rmac=$(echo "$cmd" | sed -n 's/.*,mac=\([^,]*\).*/\1/p' | head -1)
        nq=$(echo "$cmd" | sed -n 's/.*,queues=\([0-9]*\).*/\1/p' | head -1)
        echo -e "Status:   ${GREEN}running${NC}, PID $pid"
        echo "CPU:      ${CPU:-${PPGW_CPU:-host}} x $CPUS, up $(ps -p "$pid" -o etime= 2>/dev/null | tr -d ' '), \
${RAM} MB ($(ps -p "$pid" -o rss= 2>/dev/null | awk '{printf "%d", $1/1024}') MB used)"
        echo "Network:  $TAP on $BRIDGE, ${rmac:-$MAC}, $(guest_addr "${rmac:-$MAC}" || echo "address not seen yet")"
        [ -n "$rmac" ] && [ "$rmac" != "$MAC" ] && \
            warn "          restart to pick up the current MAC, $MAC"
        echo "NIC:      virtio-net-$NIC, ${nq:-1} queue(s), vhost on, link ${NIC_SPEED} ${NIC_DUPLEX}"
        echo "Console:  $PORT (telnet 127.0.0.1)"
        echo "ISO:      $ISO"
    else
        echo -e "Status:   ${RED}stopped${NC}"
    fi
    if [ -f "$SERVICE" ] && [ "$(systemctl is-enabled ppgw-vm 2>/dev/null)" = "enabled" ]; then
        echo -e "Startup:  ${GREEN}enabled${NC}, starts at boot"
    else
        echo -e "Startup:  ${YELLOW}disabled${NC}, does not start at boot"
    fi
    echo "======================================"
}

cpu_khz() {
    cat "/sys/devices/system/cpu/cpu0/cpufreq/$1" 2>/dev/null
}

# best effort names for the SoC, /proc/cpuinfo on arm64 carries no model string
cpu_vendor() {
    tr -d '\0' </proc/device-tree/compatible 2>/dev/null | cut -d, -f1 | head -c 32
    :
}

cpu_model() {
    tr -d '\0' </proc/device-tree/model 2>/dev/null | head -c 32
    :
}

# A copy of the readings laid out exactly like the kernel lays out sysfs, so the
# guest can overlay it onto its own /sys and every tool that reads
# /sys/class/thermal or .../cpufreq works unmodified. Files are rewritten in
# place, never replaced, or the guest's mounts would still see the old inode.
write_hostinfo_sysfs() {
    local sd=$HOSTINFO_DIR/sysfs zone type t c name f n=0
    mkdir -p "$sd/thermal" "$sd/cpu" || return 1

    for zone in /sys/class/thermal/thermal_zone*/; do
        [ -r "$zone/temp" ] || continue
        t=$(cat "$zone/temp" 2>/dev/null) || continue
        type=$(cat "$zone/type" 2>/dev/null || echo "cpu-thermal")
        mkdir -p "$sd/thermal/thermal_zone$n"
        printf '%s\n' "$type" >"$sd/thermal/thermal_zone$n/type"
        printf '%s\n' "$t" >"$sd/thermal/thermal_zone$n/temp"
        n=$((n + 1))
    done

    for c in /sys/devices/system/cpu/cpu[0-9]*/; do
        [ -d "$c/cpufreq" ] || continue
        name=$(basename "$c")
        mkdir -p "$sd/cpu/$name/cpufreq"
        for f in scaling_cur_freq cpuinfo_cur_freq cpuinfo_min_freq cpuinfo_max_freq \
                 scaling_min_freq scaling_max_freq scaling_governor; do
            [ -r "$c/cpufreq/$f" ] || continue
            printf '%s\n' "$(cat "$c/cpufreq/$f" 2>/dev/null)" >"$sd/cpu/$name/cpufreq/$f"
        done
    done
}

# one pass over the host's sensors, written where the guest can read it
write_hostinfo() {
    local d=$HOSTINFO_DIR t zone type cur max min gov n
    mkdir -p "$d" || return 1

    # every thermal zone, named after what the kernel calls it
    n=0
    for zone in /sys/class/thermal/thermal_zone*/; do
        [ -r "$zone/temp" ] || continue
        t=$(cat "$zone/temp" 2>/dev/null) || continue
        type=$(cat "$zone/type" 2>/dev/null || echo "zone$n")
        printf '%s\n' "$t" >"$d/temp_$type"
        [ $n -eq 0 ] && printf '%s\n' "$t" >"$d/temp"
        n=$((n + 1))
    done

    cur=$(cpu_khz scaling_cur_freq)
    max=$(cpu_khz cpuinfo_max_freq)
    min=$(cpu_khz cpuinfo_min_freq)
    gov=$(cpu_khz scaling_governor)
    [ -n "$cur" ] && printf '%s\n' "$cur" >"$d/cpu_cur_freq"
    [ -n "$max" ] && printf '%s\n' "$max" >"$d/cpu_max_freq"
    [ -n "$min" ] && printf '%s\n' "$min" >"$d/cpu_min_freq"
    [ -n "$gov" ] && printf '%s\n' "$gov" >"$d/cpu_governor"

    # per-core, the little cores may sit at a different point than cpu0
    for c in /sys/devices/system/cpu/cpu[0-9]*/; do
        [ -r "$c/cpufreq/scaling_cur_freq" ] || continue
        printf '%s\n' "$(cat "$c/cpufreq/scaling_cur_freq")" >"$d/$(basename "$c")_cur_freq"
    done

    write_hostinfo_sysfs

    # one file with everything, so the guest needs a single read
    {
        printf 'temp_mc=%s\n' "${t:-}"
        [ -n "$t" ] && printf 'temp_c=%s\n' "$((t / 1000)).$(( (t % 1000) / 100 ))"
        printf 'cpu_cur_khz=%s\n' "${cur:-}"
        printf 'cpu_max_khz=%s\n' "${max:-}"
        printf 'cpu_governor=%s\n' "${gov:-}"
        printf 'host_loadavg=%s\n' "$(cut -d' ' -f1-3 /proc/loadavg)"
        printf 'host_uptime=%s\n' "$(cut -d. -f1 /proc/uptime)"
        printf 'sampled_at=%s\n' "$(date +%s)"
    # unique per process: the sampler and a manual `hostinfo` run write this
    # at the same time, and a shared name means one mv steals the other's file
    } >"$d/metrics.$$.tmp" && mv -f "$d/metrics.$$.tmp" "$d/metrics"
}

# refreshes the shared directory for as long as the VM is up
sampler_loop() {
    echo $$ >"$SAMPLERPID"
    trap 'rm -f "$SAMPLERPID"; exit 0' TERM INT
    local seen=0 waited=0
    while :; do
        write_hostinfo
        # never outlive the VM: once it has been up and is gone, so are we.
        # this is what keeps a lost pidfile from orphaning the sampler.
        if is_running; then
            seen=1
        elif [ "$seen" = "1" ] || [ "$waited" -gt 60 ]; then
            break
        fi
        waited=$((waited + HOSTINFO_INTERVAL))
        # backgrounded so a TERM is acted on now instead of one interval later
        sleep "$HOSTINFO_INTERVAL" &
        wait $!
    done
    rm -f "$SAMPLERPID"
}

sampler_running() {
    [ -f "$SAMPLERPID" ] || return 1
    local p
    p=$(cat "$SAMPLERPID" 2>/dev/null)
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null && return 0
    rm -f "$SAMPLERPID"
    return 1
}

start_sampler() {
    [ "$HOSTINFO" = "on" ] || return 0
    sampler_running && return 0
    write_hostinfo || { warn "Cannot write $HOSTINFO_DIR, host sensors will not be shared."; return 1; }
    # through bash by name, not as a program: the file is not always +x, and it
    # is bash all the way down
    setsid bash "$SELF" _sampler </dev/null >/dev/null 2>&1 &
    sleep 1
}

stop_sampler() {
    local p
    if sampler_running; then
        p=$(cat "$SAMPLERPID")
        kill "$p" 2>/dev/null
        for _ in $(seq 1 10); do
            kill -0 "$p" 2>/dev/null || break
            sleep 0.3
        done
        kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null
    fi
    rm -f "$SAMPLERPID"
}

# how many queue pairs the NIC gets; virtio-mmio can only ever do one
resolve_queues() {
    if [ "$NIC" != "pci" ]; then
        NQ=1
        return 0
    fi
    case $QUEUES in
        auto) NQ=$CPUS ;;
        ''|*[!0-9]*) err "PPGW_QUEUES must be a number or 'auto': $QUEUES"; return 1 ;;
        *) NQ=$QUEUES ;;
    esac
    [ "$NQ" -lt 1 ] && NQ=1
    # QEMU caps a virtio-net device at 8 queue pairs
    [ "$NQ" -gt 8 ] && NQ=8
    return 0
}

# What the bridge's uplink negotiated. The guest's virtio link has no physical
# speed of its own, so the uplink is the honest number to show. Taps are skipped:
# they always claim 10 Gbit/s.
uplink_speed() {
    local l n s
    for l in /sys/class/net/"$BRIDGE"/lower_*; do
        [ -e "$l" ] || continue
        n=$(basename "$l" | sed 's/^lower_//')
        [ "$n" = "$TAP" ] && continue
        s=$(cat "/sys/class/net/$n/speed" 2>/dev/null) || continue
        case $s in ''|*[!0-9]*) continue ;; esac
        [ "$s" -gt 0 ] && { echo "$s"; return 0; }
    done
    return 1
}

# -> LINK, the ",speed=...,duplex=..." to hang off the NIC (may be empty)
resolve_link() {
    LINK=""
    case $NIC_SPEED in
        off|none|no) return 0 ;;
        auto) SPEED=$(uplink_speed) || SPEED=1000 ;;
        ''|*[!0-9]*) err "PPGW_NIC_SPEED must be a number, 'auto' or 'off': $NIC_SPEED"; return 1 ;;
        *) SPEED=$NIC_SPEED ;;
    esac
    case $NIC_DUPLEX in
        full|half) ;;
        *) err "PPGW_NIC_DUPLEX must be 'full' or 'half': $NIC_DUPLEX"; return 1 ;;
    esac
    LINK=",speed=$SPEED,duplex=$NIC_DUPLEX"
}

create_tap() {
    ip link set "$TAP" down 2>/dev/null
    ip tuntap del dev "$TAP" mode tap 2>/dev/null
    if [ "$NQ" -gt 1 ]; then
        # a multi-queue NIC needs a tap opened with as many queues
        if ! ip tuntap add dev "$TAP" mode tap user root multi_queue 2>/dev/null; then
            warn "Kernel refused a multi-queue tap, falling back to one queue."
            NQ=1
            ip tuntap add dev "$TAP" mode tap user root || return 1
        fi
    else
        ip tuntap add dev "$TAP" mode tap user root || return 1
    fi
    ip link set "$TAP" master "$BRIDGE" || return 1
    ip link set "$TAP" up
}

remove_tap() {
    ip link set "$TAP" down 2>/dev/null
    # a tap created with multi_queue only goes away if the flag matches
    ip tuntap del dev "$TAP" mode tap multi_queue 2>/dev/null
    ip tuntap del dev "$TAP" mode tap 2>/dev/null
}

do_start() {
    if is_running; then
        warn "Already running (PID $(cat "$PIDFILE"))."
        return 0
    fi
    check_env || return 1
    if port_busy; then
        err "Port $PORT is taken, another VM is using it."
        echo "Pick another: PPGW_PORT=<port> $SELF start"
        return 1
    fi
    resolve_queues || return 1
    resolve_link || return 1
    start_sampler
    create_tap || { err "Cannot set up $TAP on $BRIDGE."; return 1; }

    local args=()
    [ -n "$ACCEL" ] && args+=("$ACCEL")
    args+=(-cpu "$CPU")
    # spelling out the topology gives the guest a sane view instead of 4 sockets
    args+=(-smp "$CPUS,sockets=1,cores=$CPUS,threads=1")
    args+=(-m "$RAM")
    args+=(-machine "$MACHINE")
    args+=(-bios "$BIOS")
    # naming the process makes it findable in ps/top next to other QEMU guests
    args+=(-name "$NAME,process=ppgw-vm")
    args+=(-uuid "$UUID")
    # so the guest's dmidecode / /sys/class/dmi reports something meaningful
    args+=(-smbios "type=1,manufacturer=PaoPao,product=$NAME,version=$(uname -m),serial=$SERIAL,uuid=$UUID")
    args+=(-smbios "type=2,manufacturer=PaoPao,product=$NAME,version=qemu-$MACHINE_VER")
    args+=(-smbios "type=3,manufacturer=PaoPao")
    # the guest has no cpufreq of its own, so at least report the real numbers
    # through DMI, where dmidecode -t processor can pick them up
    local maxmhz curmhz
    maxmhz=$(cpu_khz cpuinfo_max_freq)
    curmhz=$(cpu_khz scaling_cur_freq)
    if [ -n "$maxmhz" ]; then
        args+=(-smbios "type=4,manufacturer=$(cpu_vendor),version=$(cpu_model),max-speed=$((maxmhz / 1000)),current-speed=$(( ${curmhz:-$maxmhz} / 1000 ))")
    fi
    # format=raw skips QEMU's probe of the image on every start
    args+=(-drive "file=$ISO,media=cdrom,readonly=on,format=raw")

    if [ "$NIC" = "pci" ]; then
        # vectors = one per rx and tx queue, plus config and control
        local vectors=$((NQ * 2 + 2))
        args+=(-netdev "tap,id=net0,ifname=$TAP,script=no,downscript=no,vhost=on,queues=$NQ")
        # romfile= drops the PXE option ROM, which we do not boot from anyway
        args+=(-device "virtio-net-pci,netdev=net0,mac=$MAC,mq=on,vectors=$vectors,romfile=$LINK")
        # entropy from the host, the guest has no hardware RNG of its own
        args+=(-device virtio-rng-pci)
        # lets the host see the guest's real memory use and reclaim what is idle
        args+=(-device virtio-balloon-pci)
    else
        args+=(-netdev "tap,id=net0,ifname=$TAP,script=no,downscript=no,vhost=on")
        args+=(-device "virtio-net-device,netdev=net0,mac=$MAC$LINK")
        args+=(-device virtio-rng-device)
        args+=(-device virtio-balloon-device)
    fi

    # share the sampled sensor readings in, read-only
    if [ "$HOSTINFO" = "on" ] && [ -d "$HOSTINFO_DIR" ]; then
        args+=(-fsdev "local,id=hostinfo,path=$HOSTINFO_DIR,security_model=none,readonly=on")
        if [ "$NIC" = "pci" ]; then
            args+=(-device "virtio-9p-pci,fsdev=hostinfo,mount_tag=$HOSTINFO_TAG")
        else
            args+=(-device "virtio-9p-device,fsdev=hostinfo,mount_tag=$HOSTINFO_TAG")
        fi
    fi

    args+=(-rtc base=utc)
    args+=(-display none)
    args+=(-serial "telnet:localhost:$PORT,server,nowait")
    args+=(-pidfile "$PIDFILE")
    args+=(-daemonize)

    echo "Starting VM..."
    qemu-system-aarch64 "${args[@]}" || { err "QEMU failed to start."; remove_tap; stop_sampler; return 1; }

    sleep 2
    if ! is_running; then
        err "VM did not come up."
        remove_tap
        stop_sampler
        return 1
    fi
    ok "VM started."
    show_status
    if [ -t 0 ] && [ -z "$NOCONSOLE" ]; then
        echo ""
        do_console
    fi
}

do_stop() {
    if ! is_running; then
        echo "Not running."
        remove_tap
        stop_sampler
        return 0
    fi
    local pid
    pid=$(cat "$PIDFILE")
    echo "Stopping VM..."
    kill -INT "$pid" 2>/dev/null
    for _ in $(seq 1 10); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
    rm -f "$PIDFILE"
    remove_tap
    stop_sampler
    ok "VM stopped."
}

do_restart() {
    do_stop
    sleep 1
    do_start
}

# QEMU hands the serial port to one client at a time, and an nc left behind by a
# dropped SSH session goes on holding it: the next terminal to ask for the
# console just sits there looking dead. The newcomer wins, every time.
free_console() {
    local vm p pids what
    vm=$(cat "$PIDFILE" 2>/dev/null)
    pids=$(ss -tnp 2>/dev/null | grep "127.0.0.1:$PORT" | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u)
    for p in $pids; do
        # not us, and never the VM, which is the server side of that socket
        [ "$p" = "$$" ] && continue
        [ -n "$vm" ] && [ "$p" = "$vm" ] && continue
        # while it is still there to ask
        what=$(cat "/proc/$p/comm" 2>/dev/null)
        kill "$p" 2>/dev/null || continue
        warn "Took the console off ${what:-PID} $p."
        for _ in 1 2 3 4 5; do
            kill -0 "$p" 2>/dev/null || break
            sleep 0.2
        done
        kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null
    done
}

do_console() {
    if ! is_running; then
        err "VM is not running. Start it first: $SELF start"
        return 1
    fi
    command -v nc >/dev/null || { err "nc missing, install netcat-openbsd."; return 1; }
    free_console
    echo "Console on $PORT, Ctrl+C to detach."
    nc 127.0.0.1 "$PORT"
}

do_enable() {
    [ "$(id -u)" = "0" ] || { err "Run as root."; return 1; }
    cat >"$SERVICE" <<EOF
[Unit]
Description=PaoPaoGateway VM
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=$PIDFILE
Environment=NOCONSOLE=1
Environment=PPGW_ISO=$ISO
Environment=PPGW_BRIDGE=$BRIDGE
Environment=PPGW_TAP=$TAP
Environment=PPGW_PORT=$PORT
Environment=PPGW_RAM=$RAM
Environment=PPGW_NIC=$NIC
Environment=PPGW_NIC_SPEED=$NIC_SPEED
Environment=PPGW_NIC_DUPLEX=$NIC_DUPLEX
Environment=PPGW_QUEUES=$QUEUES
Environment=PPGW_NAME=$NAME
Environment=PPGW_HOSTINFO=$HOSTINFO
Environment=PPGW_HOSTINFO_INTERVAL=$HOSTINFO_INTERVAL
${PPGW_CPU:+Environment=PPGW_CPU=$PPGW_CPU}
${PPGW_CPUS:+Environment=PPGW_CPUS=$PPGW_CPUS}
ExecStart=$SELF start
ExecStop=$SELF stop
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ppgw-vm >/dev/null 2>&1 || { err "Enable failed."; return 1; }
    ok "ppgw will start at boot (ppgw-vm.service)."
}

do_disable() {
    [ "$(id -u)" = "0" ] || { err "Run as root."; return 1; }
    systemctl disable ppgw-vm >/dev/null 2>&1
    rm -f "$SERVICE"
    systemctl daemon-reload
    ok "ppgw will not start at boot."
}

uninstall_packages() {
    command -v apt-get >/dev/null || { warn "No apt-get here, leaving packages alone."; return 0; }
    local present="" p
    for p in $PKGS_REMOVABLE; do
        dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "^install ok installed" && present="$present $p"
    done
    if [ -z "$present" ]; then
        echo "None of those packages are installed."
    else
        echo "Installed: $present"
        apt-get remove -s $present 2>/dev/null | grep -E "^Remv|to remove" | sed 's/^/  /'
        if [ "$ASSUME_YES" = "1" ] || yesno "Remove them?" n; then
            apt-get remove -y $present || { err "apt-get remove failed."; return 1; }
            ok "Packages removed."
        else
            echo "Left the packages alone."
        fi
    fi
    [ -f "$USTC_LIST" ] && { rm -f "$USTC_LIST"; ok "Removed $USTC_LIST."; }
    [ -d "$USTC_LISTDIR" ] && { rm -rf "$USTC_LISTDIR"; ok "Removed $USTC_LISTDIR."; }
    return 0
}

# Every command that hands the address back to the uplink, written out as its
# own script for the same reason the bridge is built that way: the session does
# not survive the move.
write_restore_script() {
    local backend=$1 up=$2 cidr=$3 gw=$4 uuid id ifn f
    {
        echo "#!/bin/sh"
        echo "sleep 1"
        case $backend in
            nm)
                # whatever profile owned the uplink before the bridge took over
                for uuid in $(nmcli -t -f UUID connection show 2>/dev/null); do
                    id=$(nmcli -g connection.id connection show "$uuid" 2>/dev/null)
                    case $id in "$BRIDGE"|"$BRIDGE"-slave-*) continue ;; esac
                    ifn=$(nmcli -g connection.interface-name connection show "$uuid" 2>/dev/null)
                    [ "$ifn" = "$up" ] || continue
                    echo "nmcli connection modify $uuid connection.autoconnect yes >/dev/null 2>&1"
                    echo "RESTORED=$uuid"
                done
                echo "nmcli -w 10 connection down '$BRIDGE' >/dev/null 2>&1"
                echo "nmcli connection delete '$BRIDGE-slave-$up' >/dev/null 2>&1"
                echo "nmcli connection delete '$BRIDGE' >/dev/null 2>&1"
                # nothing claimed it, so give the uplink a plain DHCP profile
                echo 'if [ -z "$RESTORED" ]; then'
                echo "    nmcli connection add type ethernet ifname $up con-name ppgw-restored-$up \\"
                echo "        connection.autoconnect yes ipv4.method auto ipv6.method auto >/dev/null 2>&1"
                echo "    RESTORED=ppgw-restored-$up"
                echo "fi"
                echo 'nmcli -w 20 connection up "$RESTORED" >/dev/null 2>&1'
                ;;
            netplan)
                echo "rm -f /etc/netplan/99-ppgw-$BRIDGE.yaml"
                echo "netplan apply >/dev/null 2>&1"
                ;;
            networkd)
                echo "rm -f /etc/systemd/network/10-ppgw-$BRIDGE.netdev"
                echo "rm -f /etc/systemd/network/20-ppgw-$up.network"
                echo "rm -f /etc/systemd/network/30-ppgw-$BRIDGE.network"
                echo "networkctl reload >/dev/null 2>&1"
                echo "systemctl restart systemd-networkd >/dev/null 2>&1"
                ;;
            ifupdown)
                echo "ifdown '$BRIDGE' >/dev/null 2>&1"
                echo "rm -f /etc/network/interfaces.d/ppgw-$BRIDGE"
                # whatever was commented out when the bridge was written
                for f in /etc/network/interfaces /etc/network/interfaces.d/*; do
                    [ -f "$f.ppgw.bak" ] || continue
                    echo "cp -a '$f.ppgw.bak' '$f' && rm -f '$f.ppgw.bak'"
                done
                echo "ifup '$up' >/dev/null 2>&1"
                ;;
        esac
        echo "ip link set $BRIDGE down 2>/dev/null"
        echo "ip link del $BRIDGE 2>/dev/null"
        echo "i=0"
        echo "while [ \$i -lt 30 ]; do"
        echo "    ip -4 -o addr show dev $up 2>/dev/null | grep -q inet && exit 0"
        echo "    i=\$((i + 1)); sleep 1"
        echo "done"
        # last resort, so the box is reachable even if the backend did nothing
        if [ -n "$cidr" ]; then
            echo "ip addr add $cidr dev $up 2>/dev/null"
            echo "ip link set $up up"
            [ -n "$gw" ] && echo "ip route add default via $gw dev $up 2>/dev/null"
        fi
        echo "exit 1"
    } >"$RESTORE_SH"
    chmod +x "$RESTORE_SH"
}

restore_network() {
    ip link show "$BRIDGE" >/dev/null 2>&1 || { echo "No $BRIDGE here, nothing to put back."; return 0; }
    local backend up cidr gw i
    backend=$(net_backend) || { err "No network backend found, not touching the network."; return 1; }
    up=$(bridge_uplink "$BRIDGE")
    if [ -z "$up" ]; then
        # built but never given its uplink: just take the bridge away
        case $backend in
            nm)       nmcli connection delete "$BRIDGE" >/dev/null 2>&1 ;;
            netplan)  rm -f "/etc/netplan/99-ppgw-$BRIDGE.yaml"; netplan apply >/dev/null 2>&1 ;;
            networkd) rm -f /etc/systemd/network/[123]0-ppgw-*; systemctl restart systemd-networkd >/dev/null 2>&1 ;;
            ifupdown) rm -f "/etc/network/interfaces.d/ppgw-$BRIDGE" ;;
        esac
        ip link del "$BRIDGE" 2>/dev/null
        ok "$BRIDGE removed (it had no uplink to hand anything back to)."
        return 0
    fi

    cidr=$(iface_cidr "$BRIDGE")
    gw=$(iface_gw "$BRIDGE")
    echo ""
    echo "Restore: $up leaves $BRIDGE and takes ${cidr:-its address} back ($backend)."
    warn "The link goes quiet for a few seconds while it moves."
    if [ "$ASSUME_YES" != "1" ]; then
        yesno "Put the network back?" y || { echo "Left the network alone."; return 1; }
    fi

    write_restore_script "$backend" "$up" "$cidr" "$gw"
    if [ -n "$SSH_CONNECTION" ]; then
        if command -v setsid >/dev/null; then
            ( trap '' HUP; setsid sh "$RESTORE_SH" </dev/null >"$RESTORE_SH.log" 2>&1 & )
        else
            ( trap '' HUP; nohup sh "$RESTORE_SH" </dev/null >"$RESTORE_SH.log" 2>&1 & )
        fi
        for i in $(seq 1 45); do
            [ -n "$(iface_cidr "$up")" ] && ! ip link show "$BRIDGE" >/dev/null 2>&1 && break
            sleep 1
        done
    else
        sh "$RESTORE_SH" 2>&1 | tee "$RESTORE_SH.log"
    fi

    if [ -n "$(iface_cidr "$up")" ]; then
        rm -f "$RESTORE_SH" "$RESTORE_SH.log"
        ok "$up is back on $(iface_cidr "$up")."
        ip link show "$BRIDGE" >/dev/null 2>&1 && warn "$BRIDGE is still there, remove it by hand: ip link del $BRIDGE"
        return 0
    fi
    err "$up has no address, see $RESTORE_SH.log"
    return 1
}

# Undoes what this script sets up: the VM and its service always, the packages
# and the bridge if asked. Written for testing the install path over and over,
# so it aims to leave the box as it was found rather than merely working.
# Usage: uninstall [--packages] [--keep-network] [--yes]
do_uninstall() {
    [ "$(id -u)" = "0" ] || { err "Run as root."; return 1; }
    local do_pkgs=0 do_net=1 a
    ASSUME_YES=0
    for a in "$@"; do
        case $a in
            --packages) do_pkgs=1 ;;
            --keep-network) do_net=0 ;;
            --yes|-y) ASSUME_YES=1 ;;
            *) err "uninstall: unknown option $a"; return 1 ;;
        esac
    done
    # no flags at all: offer the lot, each step asks for itself below
    [ $# -eq 0 ] && interactive && do_pkgs=1

    echo ""
    echo "Removing the VM side..."
    do_stop
    rm -rf "$HOSTINFO_DIR"
    rm -f "$FAILMARK" "$GUESTIP" /run/ppgw-bridge-up.sh /run/ppgw-bridge-up.sh.log
    if [ -f "$SERVICE" ]; then
        do_disable
    else
        echo "No boot service installed."
    fi

    [ "$do_pkgs" = "1" ] && uninstall_packages
    [ "$do_net" = "1" ] && restore_network

    echo ""
    ok "Uninstalled."
    echo "Left alone: the ISO and this script."
}

# Who reads this, and why it is laid out the way it is. sniffbox looks for the
# 9p tag in the guest and mounts the share itself, read-only, so nothing has to
# be typed at the console any more.
guest_hint() {
    echo "The guest picks this up on its own: sniffbox looks for a virtio-9p"
    echo "device tagged '$HOSTINFO_TAG' (in the guest, /sys/bus/virtio/devices/*/"
    echo "mount_tag), mounts it read-only under /run/sniffbox, and reads"
    echo "sysfs/thermal and sysfs/cpu out of it. That is where the guest's CPU"
    echo "temperature and frequency come from: QEMU's virt machine models no"
    echo "thermal sensor and no cpufreq, so without this the guest has neither."
    echo ""
    echo "Turn it off with PPGW_HOSTINFO=off and the guest simply shows nothing"
    echo "for those two, which costs one sampler process here every ${HOSTINFO_INTERVAL}s."
}

do_hostinfo() {
    if [ "$HOSTINFO" != "on" ]; then
        warn "Host sensor sharing is off (PPGW_HOSTINFO=$HOSTINFO)."
        return 0
    fi
    write_hostinfo || { err "Cannot sample host sensors."; return 1; }
    echo "Sampled from this host into $HOSTINFO_DIR:"
    sed 's/^/  /' "$HOSTINFO_DIR/metrics"
    echo ""
    # the sysfs-shaped copy is the part the guest actually reads
    echo "Shared as tag '$HOSTINFO_TAG':"
    echo "  sysfs/thermal: $(ls "$HOSTINFO_DIR/sysfs/thermal" 2>/dev/null | tr '\n' ' ')"
    echo "  sysfs/cpu:     $(ls "$HOSTINFO_DIR/sysfs/cpu" 2>/dev/null | tr '\n' ' ')"
    echo ""
    if sampler_running; then
        echo -e "Sampler:  ${GREEN}running${NC} (PID $(cat "$SAMPLERPID"), every ${HOSTINFO_INTERVAL}s)"
    else
        echo -e "Sampler:  ${RED}stopped${NC}"
    fi
    if is_running; then
        echo -e "9p share: $(tr '\0' '\n' <"/proc/$(cat "$PIDFILE")/cmdline" 2>/dev/null | grep -q "mount_tag=$HOSTINFO_TAG" && echo "${GREEN}attached to the running VM${NC}" || echo "${RED}not on the running VM, restart it${NC}")"
    fi
    echo ""
    guest_hint
}

show_help() {
    echo "PaoPaoGateway VM manager"
    echo ""
    echo "Usage: $SELF [command]"
    echo ""
    echo "Commands:"
    echo "  start     start the VM, then open the console"
    echo "  stop      stop the VM"
    echo "  restart   stop and start again"
    echo "  status    show state, PID, console port"
    echo "  console   open the serial console"
    echo "  bridge    create $BRIDGE on this host (asked before anything changes)"
    echo "  enable    add ppgw to startup, so it comes up at boot"
    echo "  disable   take it back out of startup"
    echo "  uninstall undo all of it: VM, service, $BRIDGE, and the packages"
    echo "            [--packages] [--keep-network] [--yes]"
    echo "  help      this text"
    echo ""
    echo "  hostinfo  diagnostic only: prints what is being sampled and whether"
    echo "            the 9p share is on the running VM. 'start' already does the"
    echo "            sampling, so nothing needs this to work."
    echo ""
    echo "Settings (environment):"
    echo "  PPGW_ISO=$ISO"
    echo "  PPGW_BRIDGE=$BRIDGE  PPGW_TAP=$TAP  PPGW_PORT=$PORT"
    echo "  PPGW_MAC=$MAC"
    echo "  PPGW_CPUS=$CPUS (every host core unless set)  PPGW_RAM=$RAM"
    echo "  PPGW_CPU=${PPGW_CPU:-host with KVM, max without}"
    echo "  PPGW_MACHINE=$MACHINE"
    echo "  PPGW_NIC=$NIC  PPGW_QUEUES=$QUEUES"
    echo "  PPGW_NIC_SPEED=$NIC_SPEED  PPGW_NIC_DUPLEX=$NIC_DUPLEX"
    echo "  PPGW_NAME=$NAME  PPGW_SERIAL=$SERIAL"
    echo "  PPGW_HOSTINFO=$HOSTINFO  PPGW_HOSTINFO_INTERVAL=${HOSTINFO_INTERVAL}s"
    echo "  PPGW_HOSTINFO_TAG=$HOSTINFO_TAG  PPGW_HOSTINFO_DIR=$HOSTINFO_DIR"
    echo "  PPGW_MIRROR_TEST=$MIRROR_TEST (off = never time mirrors, use apt as configured)"
    echo ""
    echo "Missing packages are installed with apt-get. The configured mirror is"
    echo "timed against $USTC_HOST first; if USTC is at least 25% faster it is"
    echo "added as $USTC_LIST and used for the install."
    echo ""
    echo "No command opens the menu."
}

show_menu() {
    show_status
    echo "  1) start"
    echo "  2) stop"
    echo "  3) restart"
    echo "  4) console"
    echo "  5) Enable startup"
    echo "  6) Disable startup"
    echo "  7) uninstall"
    echo "  0) quit"
}

if [ $# -eq 0 ]; then
    while true; do
        show_menu
        read -r -p "Choice [0-7]: " choice
        case $choice in
            1) do_start ;;
            2) do_stop ;;
            3) do_restart ;;
            4) do_console ;;
            5) do_enable ;;
            6) do_disable ;;
            7) do_uninstall ;;
            0) exit 0 ;;
            *) err "Unknown choice." ;;
        esac
        echo ""
        read -r -p "Press enter to continue..."
    done
else
    case $1 in
        start) do_start ;;
        stop) do_stop ;;
        restart) do_restart ;;
        status) show_status ;;
        console) do_console ;;
        hostinfo) do_hostinfo ;;
        bridge) do_bridge ;;
        _sampler) sampler_loop ;;
        enable) do_enable ;;
        disable) do_disable ;;
        uninstall) shift; do_uninstall "$@" ;;
        help|--help|-h) show_help ;;
        *) err "Unknown command: $1"; show_help; exit 1 ;;
    esac
fi
