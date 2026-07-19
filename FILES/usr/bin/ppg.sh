#!/bin/sh
IPREX4='([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
PUBIPREX6="2[0-9a-fA-F]{3}:[0-9a-fA-F:]+"
NTP_SERVERS="-p 111.230.189.174 -p 47.96.149.233 -p 106.55.184.199 -p 203.107.6.88"

ppgw() { /usr/bin/sniffbox ppgw "$@"; }

set_default() {
    eval "case \${$1} in '') $1=\"$2\" ;; esac"
}

apply_defaults() {
    set_default test_node_url "http://cp.cloudflare.com/generate_204"
    set_default fall_direct "no"
    set_default ext_node "Traffic|Expire| GB|Days|Date"
    set_default down_url "download_url_not_found"
    set_default dns_ip "223.5.5.5"
    set_default dns_port "53"
    set_default udp_enable "no"
    set_default fake_cidr "7.0.0.0/8"
    set_default openport "no"
    set_default mode "free"
    set_default socks5_ip "$gw"
    set_default socks5_port "7890"
    set_default yamlfile "custom.yaml"
    set_default ovpnfile "custom.ovpn"
    set_default dns_burn "yes"
    set_default ex_dns "223.5.5.5:53,1.0.0.1:53"
    set_default subtime "1d"
    set_default tomorrow "tomorrow"
}

require_ini() {
    if [ ! -f /tmp/ppgw.ini ]; then
        log "ppgw.ini not available, skip $1" warn
        return 1
    fi
    return 0
}

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
    eth0ip=$(ip -4 addr show dev eth0 scope global | grep inet | grep -Eo "$IPREX4" | head -1)
    export eth0ip
    eth0mac=$(ip link show dev eth0 | grep -Eo "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}" | head -1)
    dns1=$(grep nameserver /etc/resolv.conf | grep -Eo "$IPREX4" | head -1)
    dns2=$(grep nameserver /etc/resolv.conf | grep -Eo "$IPREX4" | tail -1)
    if [ -z "$dns1" ]; then
        log "Error: eth0 DNS not found." warn
    fi
    if [ "$dns1" != "$dns2" ]; then
        if echo "$dns2" | grep -qEo "$IPREX4"; then
            eth0dns="$dns1 $dns2"
        fi
    else
        eth0dns="$dns1"
    fi
    eth0gw=$(ip r | grep eth0 | grep "default via" | grep -Eo "$IPREX4" | head -1)
    log "eth0 ready: IP:[""$eth0ip""] MAC:[""$eth0mac""]" succ
    log "            DNS:[""$eth0dns""] GW:[""$eth0gw""]" succ
    if grep -q eth06 /etc/config/network; then
        eth0ip6=$(ip -6 addr show dev eth0 scope global | grep inet6 | grep -Eo "$PUBIPREX6" | head -1)
        if [ -n "$eth0ip6" ]; then
            export eth0ip6
            log "eth0 IPv6 ready:[""$eth0ip6""]" succ
        else
            log "eth0 IPv6 not found." warn
        fi
        eth0ula=$(ip -6 addr show dev eth0 scope global | grep -E "inet6 (fd|fc)" | head -1 | sed -n 's/.*inet6 \([^ ]*\).*/\1/p')
        if [ -n "$eth0ula" ]; then
            log "eth0 ULA ready:[""$eth0ula""]" succ
        fi
    fi
    if ! pidof ntpd >/dev/null 2>&1; then
        ntpd $NTP_SERVERS >/dev/null 2>&1 &
    fi
}


sync_ntp() {
    ntpd -n -q $NTP_SERVERS >/dev/tty0 2>&1
}

safe_kill() {
    target_path="$1"
    if [ -z "$target_path" ]; then return 1; fi
    self_pid="$$"
    parent_pid="$PPID"
    pids=""
    for pid in $(pgrep -f "$target_path"); do
        if [ "$pid" = "$self_pid" ] || [ "$pid" = "$parent_pid" ]; then
            continue
        fi
        if [ ! -r "/proc/$pid/cmdline" ]; then
            continue
        fi
        exe_link=$(readlink "/proc/$pid/exe" 2>/dev/null)
        cmd0=$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | head -1)
        if [ "$exe_link" = "$target_path" ] || [ "$cmd0" = "$target_path" ]; then
            pids="$pids $pid"
        fi
    done
    pids=$(echo $pids)
    if [ -z "$pids" ]; then
        return 0
    fi
    # SIGTERM (graceful)
    for pid in $pids; do
        kill -TERM "$pid" 2>/dev/null
    done
    # wait up to 10s, re-send TERM at 5s in case the process was not ready
    i=0
    while [ "$i" -lt 10 ]; do
        all_dead=1
        for pid in $pids; do
            if kill -0 "$pid" 2>/dev/null; then
                all_dead=0
                break
            fi
        done
        if [ "$all_dead" -eq 1 ]; then
            log "$target_path stopped." succ
            return 0
        fi
        if [ "$i" -eq 5 ]; then
            for pid in $pids; do
                kill -TERM "$pid" 2>/dev/null
            done
        fi
        sleep 1
        i=$((i + 1))
    done
    # SIGKILL fallback
    for pid in $pids; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null
        fi
    done
    sleep 1
    for pid in $pids; do
        if kill -0 "$pid" 2>/dev/null; then
            log "$target_path kill FAILED pid=$pid" warn
            return 1
        fi
    done
    log "$target_path force killed." warn
    return 0
}

load_box() {
    require_ini "load_box" || return 1
    force_reload="$1"
    if nft list ruleset | grep -q "ppgw_tproxy"; then
        if [ "$force_reload" = "force" ]; then
            log "[RELOAD] Reload nft rule..." warn
            /usr/bin/nft.sh
        fi
    else
        log "[ADD] Add nft rule..." warn
        /usr/bin/nft.sh
    fi
    if pidof sniffbox >/dev/null 2>&1; then
        log "sniffbox Running OK." succ
    else
    /usr/bin/sniffbox >/dev/tty0 2>&1 &
    fi
}
kill_box(){
    safe_kill "/usr/bin/sniffbox"
    nft flush ruleset
}
hot_reload_box(){
    pid=$(pidof sniffbox)
    if [ -n "$pid" ]; then
        kill -HUP "$pid"
    else
        load_box
    fi
}
cold_reload_box(){
    kill_box
    load_box
}
box_hot_changed(){
    if [ "$old_box" != "$box" ]; then return 0; fi
    if [ "$old_clash_web_password" != "$clash_web_password" ]; then return 0; fi
    if [ "$old_dns_ip" != "$dns_ip" ] || [ "$old_dns_port" != "$dns_port" ]; then return 0; fi
    if [ "$old_openport_auth" != "$openport_auth" ]; then return 0; fi
    if [ "$old_admin_cidr" != "$admin_cidr" ]; then return 0; fi
    if [ "$old_proxy_cidr" != "$proxy_cidr" ]; then return 0; fi
    if [ "$old_max_rec" != "$max_rec" ]; then return 0; fi
    if [ "$old_net_cleanday" != "$net_cleanday" ]; then return 0; fi
    return 1
}


kill_clash() {
    safe_kill "/usr/bin/clash"
}
load_clash() {
    if [ -f /tmp/clash.yaml ]; then
        log "Loading clash..." warn
        # ulimit
        if [ "$(ulimit -n)" -gt 999999 ]; then
            log "ulimit adbove 1000000." succ
        else
            ulimit -SHn 1048576
            log "ulimit:"$(ulimit -n)
        fi
        if [ -f /tmp/ppgw.ini ]; then
            . /tmp/ppgw.ini 2>/dev/tty0
        fi
        apply_defaults
        closeall_flag="no"
        is_reload=0
        log "[MODE]:""$mode"" [VERSION] :""$(clash -v)" succ
        echo "127.0.0.1 localhost" >/etc/hosts
        ppgw -genhost /tmp/clash.yaml -server "$dns_ip" -port "$dns_port" >>/etc/hosts
        if pidof clash >/dev/null 2>&1; then
            log "Clash already running, just reload yaml config." succ
            is_reload=1
            old_node=$(ppgw -now_node 2>/dev/tty0)
            old_node_hash=$(ppgw -nodehash "$old_node" -yaml /tmp/clash.yaml.last 2>/dev/null)
            old_rule_hash=""
            old_ppsub_hash=""
            if [ -f /tmp/ppgw_state.last ]; then
                . /tmp/ppgw_state.last
            fi
            ppgw -reload >/dev/tty0 2>&1
        else
            sync_ntp
            ppgw -clash-up
        fi
    else
        log "The clash.yaml generation failed." warn
        return 1
    fi
    if ppgw -clash-ready -timeout 10; then
        echo "clash api ok."
    else
        echo "clash api timeout."
    fi
    if pidof clash >/dev/null 2>&1 && [ "$is_reload" = "1" ]; then
        new_node=$(ppgw -now_node 2>/dev/tty0)
        if [ "$PPGW_FORCE_CLOSEALL" = "1" ]; then
            closeall_flag="yes"
        elif [ "$mode" = "suburl" ] && echo "$suburl" | grep -qEo "^ppsub@"; then
            new_ppsub_hash=$(md5sum /etc/config/clash/clash-dashboard/data/ppsub.json 2>/dev/null | cut -d' ' -f1)
            if [ "$old_ppsub_hash" != "$new_ppsub_hash" ]; then
                closeall_flag="yes"
            fi
        elif [ "$fast_node" = "yes" ]; then
            if [ "$old_node" != "$new_node" ]; then
                closeall_flag="yes"
            else
                new_node_hash=$(ppgw -nodehash "$new_node" -yaml /tmp/clash.yaml 2>/dev/null)
                if [ "$old_node_hash" != "$new_node_hash" ]; then
                    closeall_flag="yes"
                fi
            fi
        else
            new_rule_hash=$(ppgw -rulehash -yaml /tmp/clash.yaml 2>/dev/null)
            if [ "$old_rule_hash" != "$new_rule_hash" ]; then
                closeall_flag="yes"
            fi
        fi
        if [ "$closeall_flag" = "yes" ]; then
            ppgw -closeall >/dev/tty0
        fi
    fi
    unset PPGW_FORCE_CLOSEALL
    if pidof clash >/dev/null 2>&1 && [ "$1" = "yes" ]; then
        ppgw -fastnode -test_node_url="$test_node_url" -ext_node="$ext_node" >/dev/tty0
        if [ $? -ne 0 ]; then
            if [ "$fall_direct" = "yes" ]; then
                ppgw -spec_node="DIRECT" >/dev/tty0
                www_test=$(ppgw -testProxy -test_node_url "http://120.53.53.53")
                if [ $? -eq 0 ]; then
                    log "[fall_direct] Switch to DIRECT." succ
                else
                    kill_clash
                fi
            else
                kill_clash
            fi
            return 3
        fi
    fi
    if [ -f /tmp/clash.yaml ]; then
        cp /tmp/clash.yaml /tmp/clash.yaml.last
        last_rule_hash=$(ppgw -rulehash -yaml /tmp/clash.yaml 2>/dev/null)
        echo "last_rule_hash=$last_rule_hash" >/tmp/ppgw_state.last
    fi
    if [ -f /etc/config/clash/clash-dashboard/data/ppsub.json ]; then
        last_ppsub_hash=$(md5sum /etc/config/clash/clash-dashboard/data/ppsub.json 2>/dev/null | cut -d' ' -f1)
        echo "last_ppsub_hash=$last_ppsub_hash" >>/tmp/ppgw_state.last
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
            apply_defaults
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
        log "paopao.ovpn generated; openvpn managed by sniffbox." succ
    else
        log "The paopao.ovpn generation failed." warn
    fi
}

gen_hash() {
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini 2>/dev/tty0
        str="ppgw""$fake_cidr""$dns_ip""$dns_port""$openport""$openport_auth""$clash_web_password""$mode""$udp_enable""$socks5_ip""$socks5_port""$socks5_username""$socks5_password""$ovpnfile""$ovpn_username""$ovpn_password""$yamlfile""$suburl""$subtime""$subcron""$fast_node""$test_node_url""$ext_node""$fall_direct""$dns_burn""$ex_dns""$net_rec""$max_rec""$net_cleanday""$pplog""$pplog_uuid""$admin_cidr""$proxy_cidr"
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
    submode_flag=""
    if [ -f /tmp/ppgw.ini ]; then
        submode_flag=$(grep -E "^mode" /tmp/ppgw.ini | tail -1)
    fi
    if echo "$down_url" | grep -qEo "^ppsub@"; then
        down_url=$(echo "$down_url" | sed "s/^ppsub@//g")
        down_type=ppsub
    fi
    if echo "$submode_flag" | grep -E -q "^mode=[\"']?suburl[\"']?" && [ -f /www/ppsub.json ]; then
        down_type="ppsub"
    fi
    apply_defaults
    if [ "$down_type" = "ini" ]; then
        if [ -f /www/ppgw.ini ]; then
            if [ -f /tmp/ppgw.ini ]; then
                log "Load local ppgw.ini" succ
            else
                cp /www/ppgw.ini /tmp/ppgw.ini.tmp
                submode_flag=$(cat "/tmp/ppgw.ini.tmp" | grep -E "^mode[ ]*=" | tail -1)
                suburl_flag=$(cat "/tmp/ppgw.ini.tmp" | grep -E "^suburl[ ]*=" | tail -1)
                if (echo "$submode_flag" | grep -E -q "^mode=[\"']?suburl[\"']?" && echo "$suburl_flag" | grep -E -q "^suburl=[\"']?ppsub@") || echo "$submode_flag" | grep -E -q "^mode=[\"']?free[\"']?"; then
                    grep -v "^fast_node" "/tmp/ppgw.ini.tmp" >"/tmp/ppgw.ini"
                    echo 'fast_node=no' >>"/tmp/ppgw.ini"
                    echo 'fall_direct=no' >>"/tmp/ppgw.ini"
                else
                    cat "/tmp/ppgw.ini.tmp" >"/tmp/ppgw.ini"
                fi
                rm "/tmp/ppgw.ini.tmp"
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
    if [ "$down_type" = "ppsub" ]; then
        file_down_tmp="/etc/config/clash/clash-dashboard/data/ppsub.json"
        mkdir -p "/etc/config/clash/clash-dashboard/data"
    fi
    if [ -f "$file_down_tmp" ]; then
        rm "$file_down_tmp"
    fi
    if [ "$down_type" = "ppsub" ] && [ -f /www/ppsub.json ]; then
        cp /www/ppsub.json "$file_down_tmp"
        log "Load local ppsub.json" succ
    else
        if [ -f /tmp/ppgw.ini ]; then
            . /tmp/ppgw.ini 2>/dev/tty0
            apply_defaults
        fi
        echo "127.0.0.1 localhost" >/etc/hosts
        if echo "$down_url" | grep -qE "^http://paopao\.dns([:/]|$)"; then
            dns1=$(grep nameserver /etc/resolv.conf | grep -Eo "$IPREX4" | head -1)
            dns2=$(grep nameserver /etc/resolv.conf | grep -Eo "$IPREX4" | tail -1)
            genHost_p1=$(ppgw -server "$dns1" -port "53" -rawURL "$down_url" | cut -d" " -f1)
            genHost_p2=$(ppgw -server "$dns2" -port "53" -rawURL "$down_url" | cut -d" " -f1)
            genHost_p3=$(ppgw -server "$dns_ip" -port "$dns_port" -rawURL "$down_url" | cut -d" " -f1)
            paopaohost_list="$genHost_p1 $genHost_p2 $genHost_p3"
            paopaohost=$(echo "$paopaohost_list" | grep -E "$IPREX4" | head -1)
            if [ -z "$paopaohost" ]; then
                log "Nslookup DNS failed: ""$down_url" warn
                return 1
            fi
            echo "$paopaohost" >>/etc/hosts
        else
            genHost=$(ppgw -server "$dns_ip" -port "$dns_port" -rawURL "$down_url")
            if [ "$?" = "1" ]; then
                log "Nslookup DNS failed: ""$down_url" warn
                return 1
            fi
            echo "$genHost" >>/etc/hosts
        fi
        if echo "$down_url" | grep https; then
            sync_ntp
        fi
        ppgw -downURL "$down_url" -output "$file_down_tmp" >/dev/tty0 2>&1
    fi
    echo "127.0.0.1 localhost" >/etc/hosts
    if [ "$down_type" = "ini" ]; then
        if head -1 "$file_down_tmp" | grep -q "#paopao-gateway"; then
            checkflag=0
            if sed 's/\r/\n/g' "$file_down_tmp" | grep -E '^[_a-zA-Z0-9]+="[^\"]+$' >/dev/tty0 2>&1; then
                checkflag=1
            fi
            if sed 's/\r/\n/g' "$file_down_tmp" | grep -E '^[_a-zA-Z0-9]+=[^"]+"$' >/dev/tty0 2>&1; then
                checkflag=1
            fi
            if [ "$checkflag" = "1" ]; then
                log "[Fail] Unclosed double quotes found in ""$down_url" warn
                return 1
            fi
            cp "$file_down_tmp" "$file_down"
            sed 's/\r/\n/g' "$file_down" | grep -E "^[_a-zA-Z0-9]+=" >"/tmp/ppgw.ini.tmp"
            submode_flag=$(cat "/tmp/ppgw.ini.tmp" | grep -E "^mode[ ]*=" | tail -1)
            suburl_flag=$(cat "/tmp/ppgw.ini.tmp" | grep -E "^suburl[ ]*=" | tail -1)
            if (echo "$submode_flag" | grep -E -q "^mode=[\"']?suburl[\"']?" && echo "$suburl_flag" | grep -E -q "^suburl=[\"']?ppsub@") || echo "$submode_flag" | grep -E -q "^mode=[\"']?free[\"']?"; then
                grep -v "^fast_node" "/tmp/ppgw.ini.tmp" >"/tmp/ppgw.ini"
                echo 'fast_node=no' >>"/tmp/ppgw.ini"
                echo 'fall_direct=no' >>"/tmp/ppgw.ini"
            else
                cat "/tmp/ppgw.ini.tmp" >"/tmp/ppgw.ini"
            fi
            rm "/tmp/ppgw.ini.tmp"
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
                if grep -oq "proxy-providers:" "$file_down"; then
                    sed 's/\r/\n/g' "$file_down" | grep -v "\- RULE-SET" | sed "s/rule-providers:/rule-disable-providers:/g" | sed "s/rules:/ru-disable-les:/g" >"/tmp/paopao_custom.yaml"
                else
                    sed 's/\r/\n/g' "$file_down" | grep -v "\- RULE-SET" | sed "s/rule-providers:/rule-disable-providers:/g" | sed "s/proxy-groups:/proxy-disable-groups:/g" | sed "s/rules:/ru-disable-les:/g" >"/tmp/paopao_custom.yaml"
                fi
            else
                sed 's/\r/\n/g' "$file_down" >"/tmp/paopao_custom.yaml"
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
    if [ "$down_type" = "ppsub" ]; then
        if grep -qEo '"exported_at' "$file_down_tmp"; then
            log "[Succ] Get ""$down_url" succ
            ppsub_output="/tmp/paopao_custom.yaml"
            ppsub_cpy="/tmp/ppgw.yaml.down"
            if [ -f "$ppsub_output" ]; then
                rm "$ppsub_output"
            fi
            if [ -f "$ppsub_cpy" ]; then
                rm "$ppsub_cpy"
            fi
            . /tmp/ppgw.ini 2>/dev/tty0
            apply_defaults
            if [ "$dns_burn" != "no" ]; then
                export dns_burn="yes"
                export ex_dns="$ex_dns"
            fi
            export dns_ip="$dns_ip"
            export dns_port="$dns_port"
            ppgw -ppsub "$file_down_tmp" -output "$ppsub_output" >/dev/tty0 2>&1
            if pidof clash >/dev/null 2>&1; then
                rm -f /tmp/ppsub_reload_pending
            elif [ ! -f /tmp/ppsub_reload_pending ]; then
                : >/tmp/ppsub_reload_pending
                log "Clash not up during ppsub; reload in 30s to complete subdns via proxy." warn
                (sleep 30; pidof clash >/dev/null 2>&1 && /usr/bin/ppg.sh reload >/dev/tty0 2>&1) </dev/null >/dev/null 2>&1 &
            fi
            if grep -q "proxies:" "$ppsub_output"; then
                cp "$ppsub_output" "$ppsub_cpy"
                return 0
            fi
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

    if [ -f /www/ppgw.ini ] && [ "$down_type" = "ini" ]; then
        if [ -f /tmp/ppgw.ini ]; then
            log "Load local ppgw.ini" succ
        else
            get_conf "local" "ini"
        fi
        return 0
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

    if echo "$conf_name" | grep -qiE "^https?://"; then
        log "Get ""$conf_name"" from remote URL"
        get_conf "$conf_name" "$down_type"
        return $?
    fi

    if [ -n "$try_succ_host" ]; then
        log "Try[0] to get ""$conf_name"" from last succ way: ""http://""$try_succ_host":"$conf_port""/""$conf_name"
        get_conf "http://""$try_succ_host":"$conf_port""/""$conf_name" "$down_type"
    fi
    if [ "$?" = "1" ] || [ -z "$try_succ_host" ]; then
        paopao=$(ppgw -rawURL "http://paopao.dns" | cut -d" " -f1)
        try_host=$paopao
        log "Try[1] to get ""$conf_name"" from paopao.dns"
        get_conf "http://paopao.dns":"$conf_port""/""$conf_name" "$down_type"
    fi
    if [ "$?" = "1" ]; then
        try_host=$gw
        log "Try[2] to get ""$conf_name"" from gateway ""$gw"
        get_conf "http://""$try_host":"$conf_port""/""$conf_name" "$down_type"
    fi
    if [ "$?" = "1" ]; then
        try_host=$dns1
        log "Try[3] to get ""$conf_name"" from dns1 ""$dns1"
        get_conf "http://""$try_host":"$conf_port""/""$conf_name" "$down_type"
    fi
    if [ "$?" = "1" ]; then
        try_host=$dns2
        log "Try[4] to get ""$conf_name"" from dns2 ""$dns2"
        get_conf "http://""$try_host":"$conf_port""/""$conf_name" "$down_type"
    fi
    if [ "$?" = "0" ]; then
        export try_succ_host="$try_host"
    fi
}

reload_gw() {
    require_ini "reload_gw" || return 1
    force_nft="$1"
    . /etc/profile
    sync_ntp
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
    apply_defaults

    if [ -n "$mode" ]; then
        log "[MODE] : ""$mode" succ
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

    # IPv6 TPROXY policy routing - only when this box runs IPv6 — same eth06 probe
    if grep -q -r eth06 /etc/config/network; then
        if ip -6 route list table 100 2>&1 | grep -q local; then
            log "[OK] table100 v6 OK." succ
        else
            log "[ADD] Add v6 route table 100" warn
            ip -6 route add local default dev lo table 100
        fi
        if ip -6 rule | grep -q "fwmark 0x1 lookup 100"; then
            log "[OK] fwmark0x1 v6 OK." succ
        else
            log "[ADD] Add v6 fwmark lookup 100" warn
            ip -6 rule add fwmark 1 table 100
        fi
    fi

    if [ "$mode" = "yaml" ] || [ "$mode" = "suburl" ]; then
        sed 's/\r/\n/g' /etc/config/clash/base.yaml >/tmp/clash_base.yaml
        sed -i "s/{dns_ip}/$dns_ip/g" /tmp/clash_base.yaml
        sed -i "s/{dns_port}/$dns_port/g" /tmp/clash_base.yaml
        if grep -q -r eth06 /etc/config/network; then
            sed -i 's/^ipv6: false$/ipv6: true/' /tmp/clash_base.yaml
        fi
        if [ -e "/tmp/clash.yaml" ]; then
            rm "/tmp/clash.yaml"
        fi
        if [ "$mode" = "yaml" ]; then
            try_conf "$yamlfile" "yaml"
        fi
        if [ "$mode" = "suburl" ]; then
            if echo "$suburl" | grep -q "//"; then
                if grep -q "proxies:" "/tmp/ppgw.yaml.down"; then
                    log "Sub yaml OK, skip get."
                else
                    get_conf "$suburl" "yaml"
                fi
            else
                log "Bad suburl" warn
            fi
        fi

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

        log "Load clash config..." warn
        if [ -z "$fast_node" ]; then
            if [ "$clashmode" = "global" ]; then
                fast_node=yes
            else
                fast_node=no
            fi
        fi
        # burn dns
        if [ "$fast_node" = "yes" ]; then
            if [ "$dns_burn" = "yes" ]; then
                ppgw -dnslist "$dns_ip"":""$dns_port"",""$ex_dns" -dnsinput /tmp/clash.yaml -output /tmp/clash_dnsburn.yaml >/dev/tty0
                if grep -q tproxy-port /tmp/clash_dnsburn.yaml; then
                    cat /tmp/clash_dnsburn.yaml >/tmp/clash.yaml
                fi
            fi
        fi
        if [ "$force_nft" = "force" ]; then
            load_box force
        else
            load_box
        fi
        load_clash "$fast_node"
    else
        if pidof clash >/dev/null 2>&1; then
            log "[KILL] Clash not needed in ""$mode"" mode, stop it." warn
            kill_clash
        fi
        if [ "$mode" = "ovpn" ]; then
            try_conf "$ovpnfile" "ovpn"
            load_ovpn
        fi
        if [ "$force_nft" = "force" ]; then
            load_box force
        else
            load_box
        fi
    fi

}

if [ "$1" = "reload" ]; then
    log "Force reload gateway..." warn
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini 2>/dev/tty0
        apply_defaults
    fi
    old_fake_cidr=$fake_cidr
    old_udp_enable=$udp_enable
    old_net_rec=$net_rec
    old_pplog=$pplog
    old_pplog_uuid=$pplog_uuid
    old_mode=$mode
    old_socks5_ip=$socks5_ip
    old_socks5_port=$socks5_port
    old_socks5_username=$socks5_username
    old_socks5_password=$socks5_password
    old_box=$box
    old_clash_web_password=$clash_web_password
    old_dns_ip=$dns_ip
    old_dns_port=$dns_port
    old_openport_auth=$openport_auth
    old_admin_cidr=$admin_cidr
    old_proxy_cidr=$proxy_cidr
    old_max_rec=$max_rec
    old_net_cleanday=$net_cleanday

    if [ -f /tmp/sniffbox_running.ini ]; then
        . /tmp/sniffbox_running.ini 2>/dev/tty0
        apply_defaults
        old_fake_cidr=$fake_cidr
        old_udp_enable=$udp_enable
        old_net_rec=$net_rec
        old_pplog=$pplog
        old_pplog_uuid=$pplog_uuid
        old_mode=$mode
        old_socks5_ip=$socks5_ip
        old_socks5_port=$socks5_port
        old_socks5_username=$socks5_username
        old_socks5_password=$socks5_password
        if [ -f /tmp/ppgw.ini ]; then . /tmp/ppgw.ini 2>/dev/tty0; apply_defaults; fi
    fi

    if ! try_conf "ppgw.ini" "ini"; then
        log "Cannot get ppgw.ini, abort reload." warn
        exit 1
    fi
    . /tmp/ppgw.ini 2>/dev/tty0
    apply_defaults

    # Detect sniffbox changes and reload.
    need_cold_reload=0
    if [ "$old_fake_cidr" != "$fake_cidr" ]; then
        need_cold_reload=1
        log "fake_cidr changed, cold reload box." warn
    fi
    if [ "$old_udp_enable" != "$udp_enable" ]; then
        need_cold_reload=1
        log "udp_enable changed, cold reload box." warn
    fi
    if [ "$old_net_rec" != "$net_rec" ]; then
        need_cold_reload=1
        log "net_rec changed, cold reload box." warn
    fi
    if [ "$old_pplog" != "$pplog" ] || [ "$old_pplog_uuid" != "$pplog_uuid" ]; then
        need_cold_reload=1
        log "pplog config changed, cold reload box." warn
    fi
    if [ "$old_mode" != "$mode" ]; then
        mode_engine_changed=0
        if [ "$old_mode" = "yaml" ] || [ "$old_mode" = "suburl" ]; then
            if [ "$mode" != "yaml" ] && [ "$mode" != "suburl" ]; then
                mode_engine_changed=1
            fi
        elif [ "$old_mode" = "ovpn" ]; then
            if [ "$mode" != "ovpn" ]; then
                mode_engine_changed=1
            fi
        else
            mode_engine_changed=1
        fi
        if [ "$mode_engine_changed" = "1" ]; then
            need_cold_reload=1
            log "Mode engine changed from [""$old_mode""] to [""$mode""], cold reload box." warn
        fi
    fi
    if [ "$mode" = "socks5" ]; then
        if [ "$old_socks5_ip" != "$socks5_ip" ] || [ "$old_socks5_port" != "$socks5_port" ] || [ "$old_socks5_username" != "$socks5_username" ] || [ "$old_socks5_password" != "$socks5_password" ]; then
            need_cold_reload=1
            log "socks5 upstream/auth changed, cold reload box." warn
        fi
    fi

    if [ "$need_cold_reload" = "1" ]; then
        cold_reload_box
    elif box_hot_changed; then
        log "The box config has changed, hot reload box." warn
        hot_reload_box
    fi

    if [ "$mode" = "yaml" ]; then
        try_conf "$yamlfile" "yaml"
    fi
    if [ "$mode" = "suburl" ]; then
        get_conf "$suburl" "yaml"
    fi
    if [ "$mode" = "ovpn" ]; then
        try_conf "$ovpnfile" "ovpn"
    fi
    export PPGW_FORCE_CLOSEALL=1
    reload_gw force
    log "Force reload gateway finsished." warn
    exit
fi
net_ready
cat /etc/banner >/dev/tty0
echo " " >/dev/tty0
sleep_count=0
last_hash="empty"
last_yaml_hash="empty"
last_ovpn_hash="empty"
while true; do
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini 2>/dev/tty0
        apply_defaults
        old_fake_cidr=$fake_cidr
        old_openport=$openport
        old_openport_auth=$openport_auth
        old_clash_web_password=$clash_web_password
        old_net_rec=$net_rec
        old_max_rec=$max_rec
        old_net_cleanday=$net_cleanday
        old_box=$box
        old_udp_enable=$udp_enable
        old_dns_ip=$dns_ip
        old_dns_port=$dns_port
        old_pplog=$pplog
        old_pplog_uuid=$pplog_uuid
        old_admin_cidr=$admin_cidr
        old_proxy_cidr=$proxy_cidr
        old_socks5_ip=$socks5_ip
        old_socks5_port=$socks5_port
        old_socks5_username=$socks5_username
        old_socks5_password=$socks5_password
        old_mode=$mode
        if [ -f /tmp/sniffbox_running.ini ]; then
            . /tmp/sniffbox_running.ini 2>/dev/tty0
            apply_defaults
            old_fake_cidr=$fake_cidr
            old_udp_enable=$udp_enable
            old_net_rec=$net_rec
            old_pplog=$pplog
            old_pplog_uuid=$pplog_uuid
            old_mode=$mode
            old_socks5_ip=$socks5_ip
            old_socks5_port=$socks5_port
            old_socks5_username=$socks5_username
            old_socks5_password=$socks5_password
            . /tmp/ppgw.ini 2>/dev/tty0
            apply_defaults
        fi
    fi
    if ! try_conf "ppgw.ini" "ini"; then
        log "Failed to get ppgw.ini, retry later." warn
        sleep 30
        continue
    fi
    hash=$(gen_hash)
    log "[OLD PPGW HASH]: ""$last_hash"
    log "[NEW PPGW HASH]: ""$hash"
    if [ "$hash" != "$last_hash" ]; then
        if echo "$hash" | grep -Eqo "[a-z0-9]{32}"; then
            log "The hash has changed, reload gateway." warn
            if [ -f /tmp/ppgw.ini ]; then
                . /tmp/ppgw.ini 2>/dev/tty0
                apply_defaults
            fi
            need_kill_clash=0
            need_cold_reload=0
            cold_reload_done=0
            if [ "$old_fake_cidr" != "$fake_cidr" ]; then
                need_cold_reload=1
            fi
            if [ "$old_udp_enable" != "$udp_enable" ]; then
                need_cold_reload=1
            fi
            if [ "$old_net_rec" != "$net_rec" ]; then
                need_cold_reload=1
            fi
            if [ "$old_pplog" != "$pplog" ] || [ "$old_pplog_uuid" != "$pplog_uuid" ]; then
                need_cold_reload=1
            fi
            if [ "$old_mode" != "$mode" ]; then
                mode_engine_changed=0
                if [ "$old_mode" = "yaml" ] || [ "$old_mode" = "suburl" ]; then
                    if [ "$mode" != "yaml" ] && [ "$mode" != "suburl" ]; then
                        mode_engine_changed=1
                        log "Leaving clash mode, stop clash." warn
                        kill_clash
                    fi
                elif [ "$old_mode" = "ovpn" ]; then
                    if [ "$mode" != "ovpn" ]; then
                        mode_engine_changed=1
                        log "Leaving ovpn mode; sniffbox will stop openvpn on cold reload." warn
                    fi
                else
                    mode_engine_changed=1
                fi
                if [ "$mode_engine_changed" = "1" ]; then
                    need_cold_reload=1
                    log "Mode engine changed from [""$old_mode""] to [""$mode""], cold reload box." warn
                else
                    log "Mode changed within clash engine [""$old_mode""] -> [""$mode""], skip cold reload box." warn
                fi
            fi
            if [ "$mode" = "socks5" ]; then
                if [ "$old_socks5_ip" != "$socks5_ip" ] || [ "$old_socks5_port" != "$socks5_port" ] || [ "$old_socks5_username" != "$socks5_username" ] || [ "$old_socks5_password" != "$socks5_password" ]; then
                    need_cold_reload=1
                    log "socks5 upstream/auth changed, cold reload box." warn
                fi
            fi
            if [ "$need_kill_clash" = "1" ]; then
                kill_clash
            fi
            if [ "$need_cold_reload" = "1" ]; then
                cold_reload_box
                cold_reload_done=1
            fi
            if [ "$mode" = "suburl" ]; then
                get_conf "$suburl" "yaml"
            fi
            if box_hot_changed && [ "$cold_reload_done" != "1" ]; then
                log "The box config has changed, hot reload box." warn
                hot_reload_box
            fi
            nft_changed=0
            if [ "$old_dns_ip" != "$dns_ip" ] || [ "$old_dns_port" != "$dns_port" ] || [ "$old_udp_enable" != "$udp_enable" ] || [ "$old_openport" != "$openport" ] || [ "$old_box" != "$box" ]; then
                nft_changed=1
            fi
            if [ "$nft_changed" = "1" ]; then
                reload_gw force
            else
                reload_gw
            fi
            if [ "$mode" = "yaml" ] || [ "$mode" = "suburl" ]; then
                if [ -f "/tmp/ppgw.yaml.down" ]; then
                    last_yaml_hash=$(gen_yaml_hash "/tmp/ppgw.yaml.down")
                fi
            fi
            if [ -f /tmp/ppgw.ini ]; then
                last_hash=$(gen_hash)
            fi
            continue
        fi
    fi
    if [ -f /tmp/ppgw.ini ]; then
        . /tmp/ppgw.ini 2>/dev/tty0
        apply_defaults
        if box_hot_changed; then
            log "The box config has changed, hot reload box." warn
            hot_reload_box
        fi
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
    if [ "$mode" = "yaml" ] || [ "$mode" = "suburl" ]; then
        load_box
        if pidof clash >/dev/null 2>&1; then
            log "Clash Running OK." succ
            if [ "$mode" = "suburl" ] && echo "$suburl" | grep -qEo "^ppsub@"; then
                ppgw -healthcheck "/etc/config/clash/clash-dashboard/data/ppsub.json" >/dev/tty0 2>&1
                if [ $? -eq 0 ]; then
                    echo PPsub health check succ
                else
                    log "PPsub health check failed, close all connections." warn
                    ppgw -closeall >/dev/tty0 2>&1
                    log "PPsub: Try to update and reload..." warn
                    get_conf "$suburl" "yaml" || log "Failed to update suburl, keep current config." warn
                    reload_gw
                    ppgw -healthcheck "/etc/config/clash/clash-dashboard/data/ppsub.json" >/dev/tty0 2>&1
                    if [ $? -ne 0 ]; then
                        log "PPsub health check still failed after reload, try kill clash and reload." warn
                        kill_clash
                        load_clash no
                    fi
                fi
            fi
            do_proxytest=0
            if [ "$fast_node" = "yes" ]; then
                do_proxytest=1
            elif [ "$fast_node" = "check" ]; then
                # ppsub has its own global health check, skip fast_node=check proxy test
                if [ "$mode" = "suburl" ]; then
                    if ! echo "$suburl" | grep -qEo "^ppsub@"; then
                        do_proxytest=1
                    fi
                else
                    do_proxytest=1
                fi
            fi
            if [ "$do_proxytest" -eq 1 ]; then
                proxytest=$(ppgw -testProxy -test_node_url "$test_node_url")
                if echo "$proxytest" | grep -q "success"; then
                    log "$proxytest" succ
                else
                    log "Node Check Fail:""$proxytest" warn
                    log "Try to update and reload..." warn
                    if [ "$mode" = "suburl" ]; then
                        get_conf "$suburl" "yaml" || log "Failed to update suburl, keep current config." warn
                    fi
                    reload_gw
                fi
            fi
        else
            log "Try to run Clash again..." warn
            if [ "$mode" = "suburl" ]; then
                get_conf "$suburl" "yaml" || log "Failed to update suburl, keep current config." warn
            fi
            if [ "$mode" = "yaml" ]; then
                try_conf "$yamlfile" "yaml"
            fi
            load_clash $fast_node
        fi
    else
        log "Box mode ""$mode"", ensure box running." succ
        load_box
    fi
    if [ -f /tmp/ppgw.ini ]; then
        log "Same hash. Sleep 30s."
        sleep 30
        sleep_count=$((sleep_count + 1))
    fi
    if [ "$mode" = "suburl" ]; then
        if [ -f /tmp/ppgw.ini ]; then
            . /tmp/ppgw.ini 2>/dev/tty0
            apply_defaults
        fi
        # ppgw apply subtime/subcron
        current_hour=$(date +%H)
        current_date=$(date +%Y-%m-%d)
        subcron=$(grep -E "^subcron[ ]*=" /tmp/ppgw.ini | grep -Eo "(1[0-9]|2[0-3]|[0-9])" | tail -1)
        if echo "$subcron" | grep -Eqo '^(1[0-9]|2[0-3]|[0-9])$'; then
            ppgw_subtime=6000
            if [ "$current_hour" -lt "$subcron" ]; then
                next_run=$(date +"%Y-%m-%d ${subcron}:XX")
            else
                tomorrow=$(date +%Y-%m-%d -d @$(($(date +%s) + 86400)) 2>/dev/null || date -v+1d +%Y-%m-%d 2>/dev/null)
                next_run="${tomorrow} ${subcron}:XX"
            fi
            log "[SUBCRON][NEXT SUB-TIME] ""$next_run""" warn
            if [ "$current_hour" -eq "$subcron" ]; then
                if [ -z "$last_run_date" ] || [ "$last_run_date" != "$current_date" ]; then
                    sleep_count=9999
                    last_run_date="$current_date"
                fi
            fi
        else
            subcron=""
            ppgw_subtime=$(ppgw -interval "$subtime" -sleeptime 30)
            log "[SUBTIME][NEXT SUB-TIME] ""$sleep_count""/""$ppgw_subtime"""
        fi
        if [ "$sleep_count" -ge "$ppgw_subtime" ]; then
            # apply ppgw_subtime
            sleep_count=0
            log "Apply suburl to get new subscription..." warn
            old_sub_yaml_hash=$(gen_yaml_hash "/tmp/ppgw.yaml.down")
            log "[OLD SUB YAML HASH]: ""$old_sub_yaml_hash"
            if ! get_conf "$suburl" "yaml"; then
                log "Failed to get subscription, retry later." warn
                sleep_count=$((ppgw_subtime / 2))
                continue
            fi
            new_sub_yaml_hash=$(gen_yaml_hash "/tmp/ppgw.yaml.down")
            log "[NEW SUB YAML HASH]: ""$new_sub_yaml_hash"
            if [ "$old_sub_yaml_hash" != "$new_sub_yaml_hash" ]; then
                log "The sub hash has changed, reload gateway." warn
                reload_gw
                continue
            fi
        fi
    fi
done
