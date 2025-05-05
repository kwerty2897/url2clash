#!/bin/bash

# Proxy URL converter for Clash Meta (Bash version)
# Supports: vless://, vmess://, ss://, hy://, hy2://, tuic://
# Usage: ./convert.sh 'your_proxy_url_here'

if [ $# -eq 0 ]; then
    echo "Usage: $0 'your_proxy_url_here'"
    exit 1
fi

url="$1"

# URL decode function
url_decode() {
    printf '%b' "${1//%/\\x}"
}

# Common function to get name
get_name() {
    local url="$1"
    local default_name="$2"
    if [[ "$url" == *"#"* ]]; then
        url_decode "${url#*#}"
    else
        echo "$default_name"
    fi
}

convert_vless() {
    local uri="${url#vless://}"
    local user="${uri%%@*}"
    local server_port="${uri#*@}"
    local server="${server_port%%:*}"
    local port="${server_port#*:}"
    port="${port%%/*}"
    local query="${server_port#*\?}"
    query="${query%%#*}"
    
    local name="$(get_name "$url" "$server:$port")"

    echo "  - name: \"$name\""
    echo "    type: vless"
    echo "    server: $server"
    echo "    port: $port"
    echo "    uuid: $user"
    echo "    network: tcp"
    echo "    tls: true"
    
    # Parse query parameters
    while IFS='=' read -r key value; do
        case "$key" in
            sni) echo "    servername: $value" ;;
            flow) echo "    flow: $value" ;;
            fp) echo "    client-fingerprint: $value" ;;
            alpn) 
                echo "    alpn:"
                IFS=',' read -ra alpn_values <<< "$value"
                for a in "${alpn_values[@]}"; do
                    echo "      - $a"
                done
                ;;
            security)
                if [ "$value" = "reality" ]; then
                    echo "    reality-opts:"
                    echo "      public-key: $(grep -o 'pbk=[^&]*' <<< "$query" | cut -d= -f2)"
                    echo "      short-id: $(grep -o 'sid=[^&]*' <<< "$query" | cut -d= -f2)"
                fi
                ;;
            type)
                case "$value" in
                    ws)
                        echo "    ws-opts:"
                        echo "      path: \"$(grep -o 'path=[^&]*' <<< "$query" | cut -d= -f2 || echo "/")\""
                        local host="$(grep -o 'host=[^&]*' <<< "$query" | cut -d= -f2)"
                        [ -n "$host" ] && echo "      headers:" && echo "        Host: \"$host\""
                        ;;
                    grpc)
                        echo "    grpc-opts:"
                        echo "      grpc-service-name: \"$(grep -o 'serviceName=[^&]*' <<< "$query" | cut -d= -f2)\""
                        ;;
                esac
                ;;
        esac
    done < <(tr '&' '\n' <<< "$query")
}

convert_vmess() {
    local base64="${url#vmess://}"
    base64="${base64%%#*}"
    local json="$(base64 -d <<< "$base64" 2>/dev/null)"
    
    local server="$(jq -r '.add' <<< "$json")"
    local port="$(jq -r '.port' <<< "$json")"
    local name="$(get_name "$url" "$server:$port")"

    echo "  - name: \"$name\""
    echo "    type: vmess"
    echo "    server: $server"
    echo "    port: $port"
    echo "    uuid: $(jq -r '.id' <<< "$json")"
    echo "    alterId: $(jq -r '.aid // 0' <<< "$json")"
    echo "    cipher: $(jq -r '.type // "auto"' <<< "$json")"
    echo "    udp: true"
    
    # TLS settings
    if [ "$(jq -r '.tls' <<< "$json")" = "tls" ]; then
        echo "    tls: true"
        local sni="$(jq -r '.sni' <<< "$json")"
        local host="$(jq -r '.host' <<< "$json")"
        [ "$sni" != "null" ] && echo "    servername: $sni" || [ "$host" != "null" ] && echo "    servername: $host"
        
        # ALPN
        local alpn="$(jq -r '.alpn' <<< "$json")"
        if [ "$alpn" != "null" ]; then
            echo "    alpn:"
            jq -r '.alpn | split(",")[]' <<< "$json" | while read -r a; do
                echo "      - $a"
            done
        fi
    fi
    
    # Transport settings
    case "$(jq -r '.net' <<< "$json")" in
        "ws")
            echo "    network: ws"
            echo "    ws-opts:"
            echo "      path: \"$(jq -r '.path // "/"' <<< "$json")\""
            local host="$(jq -r '.host' <<< "$json")"
            [ "$host" != "null" ] && echo "      headers:" && echo "        Host: \"$host\""
            ;;
        "grpc")
            echo "    network: grpc"
            echo "    grpc-opts:"
            echo "      grpc-service-name: \"$(jq -r '.path' <<< "$json")\""
            ;;
        "h2")
            echo "    network: http"
            echo "    http-opts:"
            echo "      path:"
            echo "        - \"$(jq -r '.path // "/"' <<< "$json")\""
            local host="$(jq -r '.host' <<< "$json")"
            [ "$host" != "null" ] && echo "      headers:" && echo "        Host:" && echo "          - \"$host\""
            ;;
    esac
}

convert_ss() {
    local no_scheme="${url#ss://}"
    local at_part="${no_scheme%%@*}"
    local server_part="${no_scheme#*@}"
    
    local method_pass="$(base64 -d <<< "$at_part")"
    local method="${method_pass%%:*}"
    local password="${method_pass#*:}"
    
    local server="${server_part%%:*}"
    local port="${server_part#*:}"
    port="${port%%/*}"
    
    local name="$(get_name "$url" "$server:$port")"

    echo "  - name: \"$name\""
    echo "    type: ss"
    echo "    server: $server"
    echo "    port: $port"
    echo "    cipher: $method"
    echo "    password: \"$password\""
    echo "    udp: true"
}

convert_hy() {
    local uri="${url#hy://}"
    local server_port="${uri%%\?*}"
    local server="${server_port%%:*}"
    local port="${server_port#*:}"
    local query="${uri#*\?}"
    
    local name="$(get_name "$url" "$server:$port")"

    echo "  - name: \"$name\""
    echo "    type: hysteria"
    echo "    server: $server"
    echo "    port: $port"
    
    # Parse query parameters
    while IFS='=' read -r key value; do
        case "$key" in
            protocol) echo "    protocol: $value" ;;
            upmbps) echo "    up: $value" ;;
            downmbps) echo "    down: $value" ;;
            obfs) echo "    obfs: $value" ;;
            obfsParam) echo "    obfs-password: $value" ;;
            sni) echo "    sni: $value" ;;
            insecure) echo "    insecure: $value" ;;
        esac
    done < <(tr '&' '\n' <<< "$query")
}

convert_hy2() {
    local uri="${url#hy2://}"
    local userinfo="${uri%%@*}"
    local server_port="${uri#*@}"
    local server="${server_port%%:*}"
    local port="${server_port#*:}"
    port="${port%%/*}"
    local query="${server_port#*\?}"
    
    local name="$(get_name "$url" "$server:$port")"

    echo "  - name: \"$name\""
    echo "    type: hysteria2"
    echo "    server: $server"
    echo "    port: $port"
    echo "    password: \"$userinfo\""
    
    # Parse query parameters
    while IFS='=' read -r key value; do
        case "$key" in
            sni) echo "    sni: $value" ;;
            obfs) echo "    obfs: $value" ;;
            obfs-password) echo "    obfs-password: $value" ;;
        esac
    done < <(tr '&' '\n' <<< "$query")
}

convert_tuic() {
    local uri="${url#tuic://}"
    local userinfo="${uri%%@*}"
    local uuid="${userinfo%%:*}"
    local password="${userinfo#*:}"
    local server_port="${uri#*@}"
    local server="${server_port%%:*}"
    local port="${server_port#*:}"
    port="${port%%/*}"
    local query="${server_port#*\?}"
    
    local name="$(get_name "$url" "$server:$port")"

    echo "  - name: \"$name\""
    echo "    type: tuic"
    echo "    server: $server"
    echo "    port: $port"
    echo "    uuid: $uuid"
    echo "    password: \"$password\""
    echo "    ip: $server"
    echo "    heartbeat-interval: 10000"
    echo "    udp-relay-mode: native"
    echo "    congestion-controller: bbr"
    echo "    reduce-rtt: false"
    echo "    request-timeout: 8000"
    echo "    udp-timeout: 3000"
    
    # Parse query parameters
    while IFS='=' read -r key value; do
        case "$key" in
            sni) echo "    sni: $value" ;;
            alpn) 
                echo "    alpn:"
                IFS=',' read -ra alpn_values <<< "$value"
                for a in "${alpn_values[@]}"; do
                    echo "      - $a"
                done
                ;;
        esac
    done < <(tr '&' '\n' <<< "$query")
}

# Main conversion
case "$url" in
    vless://*)
        echo "proxies:"
        convert_vless
        ;;
    vmess://*)
        echo "proxies:"
        convert_vmess
        ;;
    ss://*)
        echo "proxies:"
        convert_ss
        ;;
    hy://*)
        echo "proxies:"
        convert_hy
        ;;
    hy2://*)
        echo "proxies:"
        convert_hy2
        ;;
    tuic://*)
        echo "proxies:"
        convert_tuic
        ;;
    *)
        echo "Error: Unsupported URL format" >&2
        exit 1
        ;;
esac