#!/bin/sh
log() {
    log_msg=$1
    log_type=$2
    if [ "$log_type" = "warn" ]; then
        echo -e "\033[31m[PaoPaoGW $(date +%H%M%S)]\033[0m ""$log_msg" >/dev/tty0
        return 0
    fi
    if [ "$log_type" = "succ" ]; then
        echo -e "\033[32m[PaoPaoGW $(date +%H%M%S)]\033[0m ""$log_msg" >/dev/tty0
        return 0
    fi
    echo -e "[PaoPaoGW $(date +%H%M%S)] ""$1" >/dev/tty0
}
if [ -f /etc/kill_netrec ]; then
    if ps | grep -v "grep" | grep "/usr/bin/ppgw" | grep "wsPort"; then
        safe_kill "/usr/bin/ppgw"
        if [ -f /etc/kill_netrec ]; then
            rm /etc/kill_netrec
        fi
        log "NET REC SHUTDOWN." warn
    fi
    exit 0
fi
getsha256() {
    echo -n "$1" | sha256sum | cut -d" " -f1
}
safe_kill() {
    target_path="$1"
        if [ -z "$target_path" ]; then return 1; fi
    pids=$(pgrep -f "$target_path" | grep -v "$$")
    if [ -z "$pids" ]; then
        return 0
    fi
    kill "$pids" 2>/dev/null
    for pid in $pids; do
        if kill -0 "$pid" 2>/dev/null; then
            sleep 1
            break
        fi
    done
    for pid in $pids; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null
        fi
    done
    still_alive=0
    for pid in $pids; do
        if kill -0 "$pid" 2>/dev/null; then
            still_alive=1
            break
        fi
    done

    if [ "$still_alive" -eq 0 ]; then
        log "$target_path Killed." warn
    fi
}
home="/etc/config/clash/clash-dashboard/rec_data"
reckey=""
if ps | grep -v "grep" | grep "d /etc/config/clash"; then
    if ps | grep -v "grep" | grep "wsPort"; then
        echo "PPGW REC RUNNING."
        exit 0
    fi
else
    exit 0
fi
if [ -f /tmp/ppgw.ini ]; then
    . /tmp/ppgw.ini 2>/dev/tty0
fi
if [ -z "$max_rec" ]; then
    max_rec="5000"
fi
if [ "$net_rec" = "yes" ]; then
    echo "LOAD NET REC..."
else
    exit 0
fi
if [ -f /etc/load_netrec ]; then
    exit 0
fi
touch /etc/load_netrec
rm -rf "$home"/*
mkdir -p "$home"/
rec_stamp=$(date +%s)$(cat /dev/urandom | tr -cd 'a-zA-Z0-9' | head -c 64)
echo "{\"reckey\": \"$rec_stamp\"}" >/etc/config/clash/clash-dashboard/reckey.json
reckey=$(getsha256 "$rec_stamp""$(getsha256 "$clash_web_password")")
mkdir -p "$home"/"$reckey"
if [ -f /usr/bin/sing-box ]; then
    export backipws="ws://127.0.0.1:82/connections?token=paopaogateway"
fi
if echo $net_cleanday | grep -qEo "^[1-9]$|^1[0-9]$|^2[0-9]$|^3[01]$"; then
    export net_cleanday="$net_cleanday"
else
    export net_cleanday=""
fi
reload_touch="$home/${reckey}/data_clean.json"
fresh_touch="$home/${reckey}/data.json"
cat >"$fresh_touch" <<'EOF'
[
  {
    "domain": "clean-start.paopao.gateway",
    "download": 0,
    "upload": 0,
    "total": 0,
    "clientIPs": [
      "127.0.0.1"
    ],
    "lastUpdate": "1970-01-01T00:00:00.2722102Z"
  }
]
EOF
if [ -z "$clash_web_port" ]; then
    clash_web_port="80"
fi
if [ -z "$clash_web_password" ]; then
    clash_web_password="clashpass"
fi
/usr/bin/ppgw -wsPort="$clash_web_port" -secret="$(getsha256 "$clash_web_password")" -net_rec_num="$max_rec" -reckey="$reckey" >/dev/tty0 2>&1 &
echo "{\"clean\": \"ok\"}" >"$reload_touch"
inotifywait -e delete -e access -e close_nowrite "$reload_touch"
sleep 1
touch /etc/kill_netrec
if ps | grep -v "grep" | grep "/usr/bin/ppgw" | grep "wsPort"; then
    safe_kill "/usr/bin/ppgw"
    if [ -f /etc/kill_netrec ]; then
        rm /etc/kill_netrec
    fi
    log "NET REC SHUTDOWN." warn
fi
if [ -f /etc/load_netrec ]; then
    rm /etc/load_netrec
fi
if [ -f /etc/kill_netrec ]; then
    rm /etc/kill_netrec
fi
rm -rf "$home"/
/usr/bin/net_rec.sh &
