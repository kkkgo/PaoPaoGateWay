#!/bin/sh
IPREX4='([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'

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

net_ready() {
    while ! ip addr show dev eth0 | grep -q 'inet '; do
        log "Waiting for eth0 to be ready." warn
        sleep 1
    done
    export eth0ip=$(ip a | grep eth0 | grep inet | grep -Eo "$IPREX4" | head -1)
    eth0mac=$(ip link show dev eth0 | grep -Eo "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}" | head -1)
    log "eth0 ready: IP: [""$eth0ip""] MAC: [""$eth0mac""]" succ
}

fast_node_sel() {
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini
    fi
    if [ -z "$clash_web_port" ]; then
        clash_web_port="80"
    fi
    if [ -z "$clash_web_password" ]; then
        clash_web_password="clashpass"
    fi
    if [ -z "$test_node_url" ]; then
        test_node_url="http://www.google.com"
    fi
    if [ -z "$ext_node" ]; then
        ext_node="Traffic|Expire| GB|Days|Date"
    fi
    ppgw -apiurl="http://127.0.0.1:""$clash_web_port" -secret="$clash_web_password" -test_node_url="$test_node_url" -ext_node="$ext_node" >/dev/tty0
}
start_clash() {
    if [ -f /tmp/clash.yaml ]; then
        if [ -f /tmp/ppgw.ini ]; then
            . /tmp/ppgw.ini
        fi
        if [ -z "$test_node_url" ]; then
            test_node_url="http://www.google.com"
        fi
        sed "s|http://www.google.com|$test_node_url|g" /etc/config/clash/clash-dashboard/index_base.html >/etc/config/clash/clash-dashboard/index.html
        /usr/bin/clash -d /etc/config/clash -f /tmp/clash.yaml >/dev/tty0 2>&1 &
    else
        log "The clash.yaml generation failed." warn
    fi
}
gen_hash() {
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini
        str="ppgw""$fake_cidr""$dns_ip""$dns_port""$openport""$sleeptime""$clash_web_port""$clash_web_password""$mode""$udp_enable""$socks5_ip""$socks5_port""$yamlfile""$suburl""$subtime""$fast_node""$test_node_url""$ext_node"
        echo "$str" | md5sum | grep -Eo "[a-z0-9]{32}" | head -1
    else
        echo "INI does not exist"
    fi
}

gen_yaml_hash() {
    calcfile=$1
    if [ -f "$calcfile" ]; then
        ppgw -yamlhashFile "$calcfile"
    else
        echo "$calcfile"" does not exist"
    fi
}

get_conf() {
    net_ready
    sleep 1
    down_url=$1
    down_type=$2
    down_sdns=$3
    if [ "$down_type" = "ini" ]; then
        file_down="/tmp/ppgw.ini.down"
    fi
    if [ "$down_type" = "yaml" ]; then
        file_down="/tmp/ppgw.yaml.down"
    fi
    file_down_tmp="$file_down"".tmp"
    if [ -f "$file_down_tmp" ]; then
        rm "$file_down_tmp"
    fi
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini
    fi
    if [ "$down_sdns" = "yes" ]; then
        rawURL=$(ppgw -server "$dns_ip" -port "$dns_port" -rawURL "$down_url")
    else
        rawURL=$(ppgw -rawURL "$down_url")
    fi
    line_count=$(echo "$rawURL" | wc -l)
    if [ "$line_count" -eq 1 ]; then
        wget --header="User-Agent: ClashforWindows/0.20.23" --timeout=10 --tries=1 --no-check-certificate "$down_url" -O "$file_down_tmp" >/dev/tty0 2>&1
    else
        rawDomain=$(echo "$rawURL" | head -1)
        rawSch=$(echo "$rawURL" | sed -n "2p")
        rawIP=$(echo "$rawURL" | sed -n "3p")
        rawReq=$(echo "$rawURL" | tail -1)
        down_url="$rawSch"":""//""$rawIP""$rawReq"
        wget --header="Host: ""$rawDomain" --header="User-Agent: ClashforWindows/0.20.23" --timeout=10 --no-check-certificate "$down_url" -O "$file_down_tmp" >/dev/tty0 2>&1
    fi
    if [ "$down_type" = "ini" ]; then
        if head -1 "$file_down_tmp" | grep -q "#paopao-gateway"; then
            cp "$file_down_tmp" "$file_down"
            sed 's/\r$//' "$file_down" | grep -E "^[_a-zA-Z0-9]+=" >"/tmp/ppgw.ini"
            log "[Succ] Get ""$down_url" succ
            return 0
        fi
    fi
    if [ "$down_type" = "yaml" ]; then
        if grep -q "proxies:" "$file_down_tmp"; then
            cp "$file_down_tmp" "$file_down"
            sed 's/\r$//' "$file_down" | grep -v "\- RULE-SET" >"/tmp/paopao_custom.yaml"
            log "[Succ] Get ""$down_url" succ
            return 0
        fi
    fi
    log "[Fail] Get ""$down_url" warn
    return 1
}

try_conf() {
    net_ready
    export gw=$(ip route show | grep "default via" | head -1 | grep -Eo "$IPREX4" | head -1)
    dns1=$(grep nameserver /etc/resolv.conf | grep -Eo "$IPREX4" | head -1)
    dns2=$(grep nameserver /etc/resolv.conf | grep -Eo "$IPREX4" | tail -1)
    confport=7889
    conf=$1
    down_type=$2
    paopao="paopao.dns"
    log "Try to get new ""$conf"
    if [ -n "$try_succ_host" ]; then
        get_conf "http://""$try_succ_host":"$try_succ_confport""/""$conf" "$down_type"
    else
        try_host=$paopao
        try_confport=$confport
        get_conf "http://""$try_host":"$try_confport""/""$conf" "$down_type"
    fi
    if [ "$?" = "1" ]; then
        try_host=$gw
        get_conf "http://""$try_host":"$try_confport""/""$conf" "$down_type"
    fi
    if [ "$?" = "1" ]; then
        try_host=$dns1
        get_conf "http://""$try_host":"$try_confport""/""$conf" "$down_type"
    fi
    if [ "$?" = "1" ]; then
        try_host=$dns2
        get_conf "http://""$try_host":"$try_confport""/""$conf" "$down_type"
    fi
    if [ "$?" = "0" ]; then
        export try_succ_host="$try_host"
        export try_succ_confport="$try_confport"
    fi
}

reload_gw() {
    . /etc/profile

    # ulimit
    if [ "$(ulimit -n)" -gt 999999 ]; then
        log "ulimit adbove 1000000." succ
    else
        ulimit -SHn 1048576
        log "ulimit:"$(ulimit -n)
    fi

    # ip_forward
    if sysctl -a 2>&1 | grep -qE "net\.ipv4\.ip_forward[ =]+1"; then
        log "[SYSCTL] Turn off net.ipv4.ip_forward..." warn
        sysctl -w net.ipv4.ip_forward=0
    else
        log "[OK] ip_forward disable." succ
    fi

    # fake ping
    if sysctl -a 2>&1 | grep -qE "net\.ipv4\.conf\.all\.route_localnet[ =]+1"; then
        log "[OK] net.ipv4.conf.all.route_localnet enabled." succ
    else
        log "[SYSCTL] Turn on net.ipv4.conf.all.route_localnet..." warn
        sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null 2>&1
    fi
    . /tmp/ppgw.ini
    if [ -z "$udp_enable" ]; then
        udp_enable="yes"
    fi
    if [ "$udp_enable" = "no" ]; then
        /usr/bin/nft_tcp.sh
    else
        /usr/bin/nft.sh
    fi
    # route table
    if ip route list table 100 2>&1 | grep -q local; then
        log "[OK] table100 OK." succ
    else
        log "[ADD] Add route table 100" warn
        ip route add local default dev lo table 100
    fi

    if ip rule | grep -q "fwmark 0x1 lookup 100"; then
        log "[OK] fwmark0x1 OK." succ
    else
        log "[ADD] Add fwmark lookup 100" warn
        ip rule add fwmark 1 table 100
    fi

    if [ -z "$fake_cidr" ]; then
        fake_cidr="7.0.0.0/8"
    fi

    if [ -z "$dns_ip" ]; then
        dns_ip="1.0.0.1"
    fi

    if [ -z "$openport" ]; then
        openport="false"
    else
        if [ "$openport" = "yes" ]; then
            openport="true"
        else
            openport="false"
        fi
    fi

    if [ -z "$dns_port" ]; then
        dns_port="53"
    fi
    if [ -z "$clash_web_port" ]; then
        clash_web_port="80"
    fi

    if [ -z "$clash_web_password" ]; then
        clash_web_password="clashpass"
    fi

    if [ -z "$mode" ]; then
        mode="socks5"
    fi

    if [ -z "$socks5_ip" ]; then
        socks5_ip=$gw
    fi

    if [ -z "$socks5_port" ]; then
        socks5_port="7890"
    fi

    if [ -z "$yamlfile" ]; then
        yamlfile="custom.yaml"
    fi
    fake_cidr_escaped=$(echo "$fake_cidr" | sed 's/\//\\\//g')
    sed 's/\r$//' /etc/config/clash/base.yaml >/tmp/clash_base.yaml
    sed -i "s/{fake_cidr}/$fake_cidr_escaped/g" /tmp/clash_base.yaml
    sed -i "s/{clash_web_port}/$clash_web_port/g" /tmp/clash_base.yaml
    sed -i "s/{dns_ip}/$dns_ip/g" /tmp/clash_base.yaml
    sed -i "s/{dns_port}/$dns_port/g" /tmp/clash_base.yaml
    sed -i "s/{clash_web_password}/$clash_web_password/g" /tmp/clash_base.yaml
    sed -i "s/{openport}/$openport/g" /tmp/clash_base.yaml
    sed -i "s/127.0.0.1/0.0.0.0/g" /tmp/clash_base.yaml
    if [ -e "/tmp/clash.yaml" ]; then
        rm "/tmp/clash.yaml"
    fi
    if [ "$mode" = "socks5" ]; then
        /etc/init.d/cron stop
        sed -i "s/{clashmode}/rule/g" /tmp/clash_base.yaml
        sed 's/\r$//' /etc/config/clash/socks5.yaml >/tmp/clash_socks5.yaml
        sed -i "s/{socks5_ip}/$socks5_ip/g" /tmp/clash_socks5.yaml
        sed -i "s/{socks5_port}/$socks5_port/g" /tmp/clash_socks5.yaml
        ppgw -input /tmp/clash_socks5.yaml -input /tmp/clash_base.yaml -output /tmp/clash.yaml
    fi
    if [ "$mode" = "yaml" ]; then
        /etc/init.d/cron stop
        try_conf "$yamlfile" "yaml"
    fi
    if [ "$mode" = "suburl" ]; then
        if echo "$suburl" | grep -q "//"; then
            if [ -z "$subtime" ]; then
                subtime="1d"
            fi
            if grep -q "proxies:" "/tmp/ppgw.yaml.down"; then
                log "Sub yaml OK, skip get."
            else
                get_conf "$suburl" "yaml" "yes"
            fi
            ppgw -interval "$subtime"
            /etc/init.d/cron reload
        else
            log "Bad suburl" warn
        fi
    fi
    if [ "$mode" = "yaml" ] || [ "$mode" = "suburl" ]; then
        if grep -q "rules:" /tmp/paopao_custom.yaml; then
            sed -i "s/{clashmode}/rule/g" /tmp/clash_base.yaml
            export clashmode=rule
        else
            sed -i "s/{clashmode}/global/g" /tmp/clash_base.yaml
            export clashmode=global
        fi
        if [ -f /tmp/paopao_custom.yaml ]; then
            ppgw -input /tmp/paopao_custom.yaml -input /tmp/clash_base.yaml -output /tmp/clash.yaml
        fi
    fi
    if [ "$mode" = "free" ]; then
        /etc/init.d/cron stop
        sed -i "s/{clashmode}/direct/g" /tmp/clash_base.yaml
        cat /tmp/clash_base.yaml >/tmp/clash.yaml
    fi
    if ps | grep -v "grep" | grep clash; then
        kill $(pgrep -x "/usr/bin/clash")
    fi
    log "Start clash..." warn
    start_clash
    sleep 3
    if [ -z "$fast_node" ]; then
        if [ "$clashmode" = "global" ]; then
            fast_node=yes
        else
            fast_node=no
        fi
    fi
    if [ "$fast_node" = "yes" ]; then
        fast_node_sel
    fi
}

if [ "$1" = "reload" ]; then
    reload_gw
    exit
fi

if [ "$1" = "cron" ]; then
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini
    fi
    get_conf "$suburl" "yaml" "yes"
    exit
fi
sysctl -w net.ipv6.conf.all.disable_ipv6=1
net_ready
cat /etc/banner >/dev/tty0
echo " " >/dev/tty0

last_hash="empty"
last_yaml_hash="empty"
while true; do
    try_conf "ppgw.ini" "ini"
    hash=$(gen_hash)
    log "[OLD PPGW HASH]: ""$last_hash"
    log "[NEW PPGW HASH]: ""$hash"
    if [ "$hash" != "$last_hash" ]; then
        if echo "$hash" | grep -Eqo "[a-z0-9]{32}"; then
            log "The hash has changed, reload gateway." warn
            reload_gw
            last_hash="$hash"
            continue
        fi
    fi
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini
    fi
    if [ "$mode" = "yaml" ]; then
        try_conf "$yamlfile" "yaml"
    fi
    if [ "$mode" = "yaml" ] || [ "$mode" = "suburl" ]; then
        yaml_hash=$(gen_yaml_hash "/tmp/ppgw.yaml.down")
        log "[OLD YAML HASH]: ""$last_yaml_hash"
        log "[NEW YAML HASH]: ""$yaml_hash"
        if [ "$last_yaml_hash" != "$yaml_hash" ]; then
            log "The yaml hash has changed, reload gateway." warn
            reload_gw
            last_yaml_hash="$yaml_hash"
            continue
        fi
    fi

    if ps | grep -v "grep" | grep "clash"; then
        echo "Clash running OK."
    else
        ps | grep clash >/dev/tty0 &
        log "Try to run Clash again..." warn
        start_clash
    fi
    if [ -z "$fast_node" ]; then
        if [ "$clashmode" = "global" ]; then
            fast_node=yes
        else
            fast_node=no
        fi
    fi

    if [ "$fast_node" = "yes" ]; then
        if [ -z "$test_node_url" ]; then
            test_node_url="http://www.google.com"
        fi
        proxytest=$(ppgw -testProxy http://127.0.0.1:1080 -test_node_url "$test_node_url")
        if [ $? -eq 0 ]; then
            log "$proxytest" succ
        else
            log "Node Check Fail:""$proxytest" warn
            log "Try to switch the fastest node..." warn
            fast_node_sel
        fi
    fi
    if [ -z "$sleeptime" ] || [ "$sleeptime" -lt 30 ] || ! echo "$sleeptime" | grep -Eq '^[0-9]+$'; then
        sleeptime=30
    fi

    log "Same hash. Sleep ""$sleeptime""s."
    sleep "$sleeptime"
done
