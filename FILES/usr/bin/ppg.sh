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
    wait_delay=$1
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini 2>/dev/tty0
    fi
    if [ "$mode" = "ovpn" ]; then
        return 0
    fi
    if [ -z "$clash_web_port" ]; then
        clash_web_port="80"
    fi
    if [ -z "$clash_web_password" ]; then
        clash_web_password="clashpass"
    fi
    if [ -z "$test_node_url" ]; then
        test_node_url="https://www.youtube.com/generate_204"
    fi
    if [ -z "$ext_node" ]; then
        ext_node="Traffic|Expire| GB|Days|Date"
    fi
    log "Try to switch the fastest node..." warn
    ppgw -apiurl="http://127.0.0.1:""$clash_web_port" -secret="$clash_web_password" -test_node_url="$test_node_url" -ext_node="$ext_node" -waitdelay="$wait_delay" >/dev/tty0
}
kill_cron() {
    if ps | grep -v "grep" | grep "/etc/cron"; then
        /etc/init.d/cron stop
    fi
}
kill_clash_cache() {
    if [ -f /etc/config/clash/cache.db ]; then
        rm -f /etc/config/clash/cache.db
    fi
}
kill_clash() {
    if ps | grep -v "grep" | grep "/etc/config/clash"; then
        kill $(pgrep -x "/usr/bin/clash")
    fi
    if [ -f /usr/bin/v2ray ]; then
        if ps | grep -v "grep" | grep "/etc/config/v2ray"; then
            kill $(pgrep -x "/usr/bin/v2ray")
        fi
    fi
    nft flush ruleset
}
load_clash() {
    log "Loading clash..." warn
    # ulimit
    if [ "$(ulimit -n)" -gt 999999 ]; then
        log "ulimit adbove 1000000." succ
    else
        ulimit -SHn 1048576
        log "ulimit:"$(ulimit -n)
    fi

    if [ -f /tmp/clash.yaml ]; then
        if [ -f /tmp/ppgw.ini ]; then
            . /tmp/ppgw.ini 2>/dev/tty0
        fi
        if [ -z "$test_node_url" ]; then
            test_node_url="https://www.youtube.com/generate_204"
        fi
        if [ -z "$clash_web_port" ]; then
            clash_web_port="80"
        fi
        if [ -z "$clash_web_password" ]; then
            clash_web_password="clashpass"
        fi
        sed "s|https://www.youtube.com/generate_204|$test_node_url|g" /etc/config/clash/clash-dashboard/index_base.html >/etc/config/clash/clash-dashboard/index.html
        if ps | grep -v "grep" | grep "/etc/config/clash"; then
            ppgw -reload -apiurl="http://127.0.0.1:""$clash_web_port" -secret="$clash_web_password" >/dev/tty0 2>&1
        else
            /usr/bin/clash -d /etc/config/clash -f /tmp/clash.yaml >/dev/tty0 2>&1 &
            if [ -f /usr/bin/v2ray ]; then
                /usr/bin/v2ray run -c /etc/config/v2ray/sniff.json >/dev/tty0 2>&1 &
            fi
        fi
    else
        log "The clash.yaml generation failed." warn
        return 1
    fi
    if [ "$1" = "yes" ]; then
        fast_node_sel 1500 || sleep 3
        fast_node_sel 2000 || sleep 6
        fast_node_sel 3000 || sleep 9
        fast_node_sel 4000 || sleep 12
        fast_node_sel 5000
        sleep 15
    fi
    if [ "$2" = "no" ]; then
        if nft list ruleset | grep "clashtcp"; then
            log "[OK] nft rule TCP OK." succ

        else
            log "[ADD] Add nft rule TCP..." warn
            /usr/bin/nft_tcp.sh
        fi
    else
        if nft list ruleset | grep "clashboth"; then
            log "[OK] nft rule TCP/UDP OK." succ
        else
            log "[ADD] Add nft rule TCP/UDP..." warn
            /usr/bin/nft.sh
        fi
    fi
    ppgw -apiurl="http://127.0.0.1:""$clash_web_port" -secret="$clash_web_password" -closeall >/dev/tty0
}

kill_ovpn() {
    if ps | grep -v "grep" | grep "/tmp/paopao.ovpn"; then
        kill $(pgrep -x "openvpn")
    fi
    ovpn_tun="tun114"
    if ip a | grep -q $ovpn_tun; then
        ip link set $ovpn_tun down >/dev/tty0
        ip link delete $ovpn_tun >/dev/tty0
    fi

}

load_ovpn() {
    log "Loading openvpn..." warn
    # ulimit
    if [ "$(ulimit -n)" -gt 999999 ]; then
        log "ulimit adbove 1000000." succ
    else
        ulimit -SHn 1048576
        log "ulimit:"$(ulimit -n)
    fi
    if [ -f /tmp/ppgw.ovpn.down ]; then
        grep -E "^remote " /tmp/ppgw.ovpn.down | cut -d" " -f2 | grep -Eo "[-._0-9a-zA-Z]+" >/tmp/ovpn_remote.list
        echo "127.0.0.1 localhost" >/etc/hosts
        echo "" >>/tmp/ovpn_remote.list
        while read ovpn_remote; do
            echo "Test "$dnsserver
            genHost=$(ppgw -server "$dns_ip" -port "$dns_port" -rawURL "ovpn://""$ovpn_remote")
            echo "$genHost" >>/etc/hosts
            log "ovpn remote: ""$genHost"
        done </tmp/ovpn_remote.list

        sed -r "/^dev /d" /tmp/ppgw.ovpn.down >/tmp/paopao.ovpn
        if [ -f /tmp/ppgw.ini ]; then
            . /tmp/ppgw.ini 2>/dev/tty0
        fi
        if [ -n "$ovpn_username" ]; then
            sed -r "/^auth-user-pass /d" /tmp/ppgw.ovpn.down >/tmp/paopao.ovpn
            sed -i "/^service /d" /tmp/paopao.ovpn
            sed -i "/^block-outside-dns /d" /tmp/paopao.ovpn
            echo " " >>/tmp/paopao.ovpn
            echo "auth-user-pass /tmp/ovpn_pass.txt" >>/tmp/paopao.ovpn
            echo "$ovpn_username" >/tmp/ovpn_pass.txt
            echo "$ovpn_password" >>/tmp/ovpn_pass.txt
        fi
        echo "dev tun114" >>/tmp/paopao.ovpn
        if ! grep -q route-nopull /tmp/paopao.ovpn; then
            echo "route-nopull" >>/tmp/paopao.ovpn
        fi
        openvpn --config /tmp/paopao.ovpn >/dev/tty0 2>&1 &
        while ! ip a | grep -q 'tun114 '; do
            touch /tmp/ovpn_wait.txt
            log "Waiting for openvpn tun to be ready." warn
            sleep 1
            echo "1" >>/tmp/ovpn_wait.txt
            if [ "$(cat /tmp/ovpn_wait.txt | wc -l)" -gt 10 ]; then
                break
            fi
        done
    else
        log "The paopao.ovpn generation failed." warn
    fi
}

gen_hash() {
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini 2>/dev/tty0
        str="ppgw""$fake_cidr""$dns_ip""$dns_port""$openport""$sleeptime""$clash_web_port""$clash_web_password""$mode""$udp_enable""$socks5_ip""$socks5_port""$ovpnfile""$ovpn_username""$ovpn_password""$yamlfile""$suburl""$subtime""$fast_node""$test_node_url""$ext_node"
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

gen_ovpn_hash() {
    calcfile=$1
    if [ -f "$calcfile" ]; then
        md5sum "$calcfile" | grep -Eo "[a-z0-9]{32}" | head -1
    else
        echo "$calcfile"" does not exist"
    fi
}

get_conf() {
    net_ready
    sleep 1
    down_url=$1
    down_type=$2
    if [ "$down_type" = "ini" ]; then
        if [ -f /www/ppgw.ini ]; then
            if [ -f /tmp/ppgw.ini ]; then
                log "Load local ppgw.ini" succ
            else
                cp /www/ppgw.ini /tmp/ppgw.ini
            fi
            return 0
        fi
        file_down="/tmp/ppgw.ini.down"
    fi
    if [ "$down_type" = "yaml" ]; then
        file_down="/tmp/ppgw.yaml.down"
    fi
    if [ "$down_type" = "ovpn" ]; then
        file_down="/tmp/ppgw.ovpn.down"
    fi
    file_down_tmp="$file_down"".tmp"
    if [ -f "$file_down_tmp" ]; then
        rm "$file_down_tmp"
    fi
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini 2>/dev/tty0
    fi
    if [ -z "$dns_ip" ]; then
        dns_ip="1.0.0.1"
    fi
    if [ -z "$dns_port" ]; then
        dns_port="53"
    fi
    echo "127.0.0.1 localhost" >/etc/hosts
    genHost=$(ppgw -server "$dns_ip" -port "$dns_port" -rawURL "$down_url")
    if [ "$?" = "1" ]; then
        log "Nslookup failed." warn
        return 1
    fi
    echo "$genHost" >>/etc/hosts
    ppgw -downURL "$down_url" -output "$file_down_tmp" >/dev/tty0 2>&1
    echo "127.0.0.1 localhost" >/etc/hosts
    if [ "$down_type" = "ini" ]; then
        if head -1 "$file_down_tmp" | grep -q "#paopao-gateway"; then
            checkflag=0
            if sed 's/\r$//' "$file_down_tmp" | grep -E '^[_a-zA-Z0-9]+="[^\"]+$' >/dev/tty0 2>&1; then
                checkflag=1
            fi
            if sed 's/\r$//' "$file_down_tmp" | grep -E '^[_a-zA-Z0-9]+=[^"]+"$' >/dev/tty0 2>&1; then
                checkflag=1
            fi
            if [ "$checkflag" = "1" ]; then
                log "[Fail] Unclosed double quotes found in ""$down_url" warn
                return 1
            fi
            cp "$file_down_tmp" "$file_down"
            sed 's/\r$//' "$file_down" | grep -E "^[_a-zA-Z0-9]+=" >"/tmp/ppgw.ini"
            log "[Succ] Get ""$down_url" succ
            return 0
        fi
    fi
    if [ "$down_type" = "yaml" ]; then
        if grep -q "proxies:" "$file_down_tmp"; then
            cp "$file_down_tmp" "$file_down"
            if [ -f /www/ppgw.ini ]; then
                . /www/ppgw.ini
            fi
            if [ "$fast_node" = "yes" ]; then
                sed 's/\r$//' "$file_down" | grep -v "\- RULE-SET" | sed "s/rule-providers:/rule-disable-providers:/g" | sed "s/proxy-groups:/proxy-disable-groups:/g" | sed "s/rules:/ru-disable-les:/g" >"/tmp/paopao_custom.yaml"
            else
                if [ -f /www/clash_core ]; then
                    sed 's/\r$//' "$file_down" >"/tmp/paopao_custom.yaml"
                else
                    sed 's/\r$//' "$file_down" | grep -v "\- RULE-SET" >"/tmp/paopao_custom.yaml"
                fi
            fi
            log "[Succ] Get ""$down_url" succ
            return 0
        fi
    fi
    if [ "$down_type" = "ovpn" ]; then
        if grep -q "remote" "$file_down_tmp"; then
            cp "$file_down_tmp" "$file_down"
            log "[Succ] Get ""$down_url" succ
            return 0
        fi
    fi
    log "[Fail] Get ""$down_url" warn
    return 1
}

try_conf() {
    net_ready
    ntpd -n -q -p ntp.aliyun.com >/dev/tty0
    export gw=$(ip route show | grep "default via" | head -1 | grep -Eo "$IPREX4" | head -1)
    dns1=$(grep nameserver /etc/resolv.conf | grep -Eo "$IPREX4" | head -1)
    dns2=$(grep nameserver /etc/resolv.conf | grep -Eo "$IPREX4" | tail -1)
    conf_port=7889
    conf_name=$1
    down_type=$2
    log "Try to get new ""$conf_name"
    if [ -f /www/ppgwurl.ini ] && [ "$down_type" = "ini" ]; then
        . /www/ppgwurl.ini
        if [ -n "$ppgwurl" ]; then
            get_conf "$ppgwurl" "ini"
            return 0
        fi
    fi

    if [ -f /www/custom.yaml ] && [ "$down_type" = "yaml" ]; then
        if [ -f "/tmp/ppgw.yaml.down" ] && [ -f "/tmp/paopao_custom.yaml" ]; then
            log "Load local yaml" succ
        else
            cp /www/custom.yaml /tmp/ppgw.yaml.down
            cp /www/custom.yaml /tmp/paopao_custom.yaml
        fi
        return 0
    fi

    if [ -f /www/custom.ovpn ] && [ "$down_type" = "ovpn" ]; then
        if [ -f "/tmp/ppgw.ovpn.down" ] && [ -f "/tmp/paopao.ovpn" ]; then
            log "Load local ovpn" succ
        else
            cp /www/custom.ovpn /tmp/ppgw.ovpn.down
        fi
        return 0
    fi

    if [ -n "$try_succ_host" ]; then
        get_conf "http://""$try_succ_host":"$conf_port""/""$conf_name" "$down_type"
    fi
    if [ "$?" = "1" ] || [ -z "$try_succ_host" ]; then
        paopao=$(ppgw -rawURL "http://paopao.dns" | cut -d" " -f1)
        try_host=$paopao
        get_conf "http://""$try_host":"$conf_port""/""$conf_name" "$down_type"
    fi
    if [ "$?" = "1" ]; then
        try_host=$gw
        get_conf "http://""$try_host":"$conf_port""/""$conf_name" "$down_type"
    fi
    if [ "$?" = "1" ]; then
        try_host=$dns1
        get_conf "http://""$try_host":"$conf_port""/""$conf_name" "$down_type"
    fi
    if [ "$?" = "1" ]; then
        try_host=$dns2
        get_conf "http://""$try_host":"$conf_port""/""$conf_name" "$down_type"
    fi
    if [ "$?" = "0" ]; then
        export try_succ_host="$try_host"
    fi
}

reload_gw() {
    . /etc/profile
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
    . /tmp/ppgw.ini 2>/dev/tty0
    if [ -z "$udp_enable" ]; then
        udp_enable="no"
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

    if [ -z "$dns_port" ]; then
        dns_port="53"
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

    if [ -z "$clash_web_port" ]; then
        clash_web_port="80"
    fi

    if [ -z "$clash_web_password" ]; then
        clash_web_password="clashpass"
    fi

    if [ -z "$mode" ]; then
        mode="free"
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

    if [ -z "$ovpnfile" ]; then
        ovpnfile="custom.ovpn"
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
        kill_cron
        sed -i "s/{clashmode}/rule/g" /tmp/clash_base.yaml
        sed 's/\r$//' /etc/config/clash/socks5.yaml >/tmp/clash_socks5.yaml
        sed -i "s/{socks5_ip}/$socks5_ip/g" /tmp/clash_socks5.yaml
        sed -i "s/{socks5_port}/$socks5_port/g" /tmp/clash_socks5.yaml
        ppgw -input /tmp/clash_socks5.yaml -input /tmp/clash_base.yaml -output /tmp/clash.yaml
    fi
    if [ "$mode" = "yaml" ]; then
        kill_cron
        try_conf "$yamlfile" "yaml"
    fi
    if [ "$mode" = "ovpn" ]; then
        kill_cron
        try_conf "$ovpnfile" "ovpn"
        sed -i "s/{clashmode}/direct/g" /tmp/clash_base.yaml
        sed -i "s/#interface-name/interface-name/g" /tmp/clash_base.yaml
        cat /tmp/clash_base.yaml >/tmp/clash.yaml
        kill_ovpn
        load_ovpn
    fi
    if [ "$mode" = "suburl" ]; then
        if echo "$suburl" | grep -q "//"; then
            if [ -z "$subtime" ]; then
                subtime="1d"
            fi
            if grep -q "proxies:" "/tmp/ppgw.yaml.down"; then
                log "Sub yaml OK, skip get."
            else
                get_conf "$suburl" "yaml"
            fi
            ppgw -interval "$subtime"
            /etc/init.d/cron reload
        else
            log "Bad suburl" warn
        fi
    fi

    if [ "$mode" = "yaml" ] || [ "$mode" = "suburl" ]; then
        if [ "$fast_node" = "yes" ]; then
            export clashmode=global
        else
            if grep -q "rules:" /tmp/paopao_custom.yaml; then
                export clashmode=rule
            else
                export clashmode=global
            fi
        fi
        if [ -f /tmp/paopao_custom.yaml ]; then
            sed -i "s/{clashmode}/$clashmode/g" /tmp/clash_base.yaml
            ppgw -input /tmp/paopao_custom.yaml -input /tmp/clash_base.yaml -output /tmp/clash.yaml
        fi
    fi

    if [ "$mode" = "free" ]; then
        kill_cron
        sed -i "s/{clashmode}/direct/g" /tmp/clash_base.yaml
        cat /tmp/clash_base.yaml >/tmp/clash.yaml
    fi
    log "Load clash config..." warn
    if [ -z "$fast_node" ]; then
        if [ "$clashmode" = "global" ]; then
            fast_node=yes
        else
            fast_node=no
        fi
    fi
    load_clash $fast_node $udp_enable

}

if [ "$1" = "reload" ]; then
    reload_gw
    exit
fi

if [ "$1" = "cron" ]; then
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini 2>/dev/tty0
    fi
    get_conf "$suburl" "yaml"
    reload_gw
    exit
fi
sysctl -w net.ipv6.conf.all.disable_ipv6=1
net_ready
cat /etc/banner >/dev/tty0
echo " " >/dev/tty0

last_hash="empty"
last_yaml_hash="empty"
last_ovpn_hash="empty"
while true; do
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini 2>/dev/tty0
        old_fake_cidr=$fake_cidr
        old_openport=$openport
        old_clash_web_port=$clash_web_port
        old_clash_web_password=$clash_web_password
        old_suburl=$suburl
        old_fast_node=$fast_node
    fi
    try_conf "ppgw.ini" "ini"
    hash=$(gen_hash)
    log "[OLD PPGW HASH]: ""$last_hash"
    log "[NEW PPGW HASH]: ""$hash"
    if [ "$hash" != "$last_hash" ]; then
        if echo "$hash" | grep -Eqo "[a-z0-9]{32}"; then
            log "The hash has changed, reload gateway." warn
            if [ -f /tmp/ppgw.ini ]; then
                . /tmp/ppgw.ini 2>/dev/tty0
            fi
            if [ "$old_fake_cidr" != "$fake_cidr" ]; then
                kill_clash
                kill_clash_cache
            fi
            if [ "$old_openport" != "$openport" ]; then
                kill_clash
            fi
            if [ "$old_clash_web_port" != "$clash_web_port" ]; then
                kill_clash
            fi
            if [ "$old_clash_web_password" != "$clash_web_password" ]; then
                kill_clash
            fi
            if [ "$old_fast_node" != "$fast_node" ]; then
                if [ "$mode" = "suburl" ]; then
                    get_conf "$suburl" "yaml"
                fi
            fi
            if [ "$mode" = "suburl" ]; then
                if [ "$old_suburl" != "$suburl" ]; then
                    get_conf "$suburl" "yaml"
                fi
            fi
            reload_gw
            if [ -f /tmp/ppgw.ini ]; then
                last_hash=$(gen_hash)
            fi
            continue
        fi
    fi
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini 2>/dev/tty0
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
            if [ -f /tmp/ppgw.yaml.down ]; then
                last_yaml_hash=$(gen_yaml_hash "/tmp/ppgw.yaml.down")
            fi
            continue
        fi
    fi
    if [ "$mode" = "ovpn" ]; then
        ovpn_hash=$(gen_ovpn_hash "/tmp/ppgw.ovpn.down")
        log "[OLD OVPN HASH]: ""$last_ovpn_hash"
        log "[NEW OVPN HASH]: ""$ovpn_hash"
        if [ "$last_ovpn_hash" != "$ovpn_hash" ]; then
            log "The ovpn hash has changed, reload gateway." warn
            reload_gw
            if [ -f /tmp/ppgw.ovpn.down ]; then
                last_ovpn_hash=$(gen_ovpn_hash "/tmp/ppgw.ovpn.down")
            fi
            continue
        fi
    fi
    if [ -z "$fast_node" ]; then
        if [ "$clashmode" = "global" ]; then
            fast_node=yes
        else
            fast_node=no
        fi
    fi
    if ps | grep -v "grep" | grep "/etc/config/clash"; then
        echo "Clash running OK."
        if [ "$fast_node" = "yes" ] || [ "$fast_node" = "check" ]; then
            if [ -z "$test_node_url" ]; then
                test_node_url="https://www.youtube.com/generate_204"
            fi
            proxytest=$(ppgw -testProxy http://127.0.0.1:1080 -test_node_url "$test_node_url")
            if [ $? -eq 0 ]; then
                log "$proxytest" succ
            else
                log "Node Check Fail:""$proxytest" warn
                log "Try to update and reload..." warn
                if [ "$mode" = "ovpn" ]; then
                    try_conf "$ovpnfile" "ovpn"
                fi
                if [ "$mode" = "suburl" ]; then
                    get_conf "$suburl" "yaml"
                fi
                reload_gw
            fi
        fi
    else
        log "Try to run Clash again..." warn
        load_clash $fast_node $udp_enable
    fi

    if [ -z "$sleeptime" ] || [ "$sleeptime" -lt 30 ] || ! echo "$sleeptime" | grep -Eq '^[0-9]+$'; then
        sleeptime=30
    fi
    log "Same hash. Sleep ""$sleeptime""s."
    sleep "$sleeptime"
done
