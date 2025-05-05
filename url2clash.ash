#!/bin/sh

# Proxy URL converter for Clash Meta (Ash compatible)
# Supports: vless://, vmess://, ss://, hy://, hy2://, tuic://
# Usage: ./convert.sh 'your_proxy_url_here'

if [ $# -eq 0 ]; then
    echo "Usage: $0 'your_proxy_url_here'"
    exit 1
fi

url="$1"

# Basic URL decode function
url_decode() {
    echo -e "${1//%/\\x}"
}

# Common function to get name
get_name() {
    local url="$1"
    local default_name="$2"
    local name="${url#*#}"
    if [ "$name" = "$url" ]; then
        echo "$default_name"
    else
        url_decode "$name"
    fi
}

convert_vless() {
    uri="${url#vless://}"
    user="${uri%%@*}"
    server_port="${uri#*@}"
    server="${server_port%%:*}"
    port="${server_port#*:}"
    port="${port%%/*}"
    
    name="$(get_name "$url" "$server:$port")"
    query="${server_port#*\?}"
    query="${query%%#*}"

    echo "  - name: \"$name\""
    echo "    type: vless"
    echo "    server: $server"
    echo "    port: $port"
    echo "    uuid: $user"
    echo "    network: tcp"
    echo "    tls: true"
    
    # Parse query parameters
    echo "$query" | tr '&' '\n' | while IFS='=' read -r key value; do
        case "$key" in
            sni) echo "    servername: $value" ;;
            flow) echo "    flow: $value" ;;
            fp) echo "    client-fingerprint: $value" ;;
            alpn) echo "    alpn:" && echo "$value" | tr ',' '\n' | while read -r a; do echo "      - $a"; done ;;
            security)
                if [ "$value" = "reality" ]; then
                    echo "    reality-opts:"
                    echo "      public-key: $(echo "$query" | sed -n 's/.*pbk=\([^&]*\).*/\1/p')"
                    echo "      short-id: $(echo "$query" | sed -n 's/.*sid=\([^&]*\).*/\1/p')"
                fi
                ;;
            type)
                case "$value" in
                    ws)
                        echo "    ws-opts:"
                        echo "      path: \"$(echo "$query" | sed -n 's/.*path=\([^&]*\).*/\1/p' || echo "/")\""
                        host="$(echo "$query" | sed -n 's/.*host=\([^&]*\).*/\1/p')"
                        [ -n "$host" ] && echo "      headers:" && echo "        Host: \"$host\""
                        ;;
                    grpc)
                        echo "    grpc-opts:"
                        echo "      grpc-service-name: \"$(echo "$query" | sed -n 's/.*serviceName=\([^&]*\).*/\1/p')\""
                        ;;
                esac
                ;;
        esac
    done
}

convert_vmess() {
    base64="${url#vmess://}"
    base64="${base64%%#*}"
    json="$(echo "$base64" | base64 -d 2>/dev/null)"
    
    name="$(get_name "$url" "$(echo "$json" | grep -o '"add":"[^"]*"' | cut -d'"' -f4):$(echo "$json" | grep -o '"port":[0-9]*' | cut -d':' -f2)")"
    
    echo "  - name: \"$name\""
    echo "    type: vmess"
    echo "    server: $(echo "$json" | grep -o '"add":"[^"]*"' | cut -d'"' -f4)"
    echo "    port: $(echo "$json" | grep -o '"port":[0-9]*' | cut -d':' -f2)"
    echo "    uuid: $(echo "$json" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)"
    echo "    alterId: $(echo "$json" | grep -o '"aid":[0-9]*' | cut -d':' -f2 || echo 0)"
    echo "    cipher: $(echo "$json" | grep -o '"type":"[^"]*"' | cut -d'"' -f4 || echo "auto")"
    echo "    udp: true"
    
    # TLS settings
    if echo "$json" | grep -q '"tls":"tls"'; then
        echo "    tls: true"
        sni="$(echo "$json" | grep -o '"sni":"[^"]*"' | cut -d'"' -f4)"
        host="$(echo "$json" | grep -o '"host":"[^"]*"' | cut -d'"' -f4)"
        [ -n "$sni" ] && echo "    servername: $sni" || [ -n "$host" ] && echo "    servername: $host"
        
        # ALPN
        alpn="$(echo "$json" | grep -o '"alpn":"[^"]*"' | cut -d'"' -f4)"
        if [ -n "$alpn" ]; then
            echo "    alpn:"
            echo "$alpn" | tr ',' '\n' | while read -r a; do echo "      - $a"; done
        fi
    fi
    
    # Transport settings
    net="$(echo "$json" | grep -o '"net":"[^"]*"' | cut -d'"' -f4)"
    case "$net" in
        ws)
            echo "    network: ws"
            echo "    ws-opts:"
            path="$(echo "$json" | grep -o '"path":"[^"]*"' | cut -d'"' -f4 || echo "/")"
            echo "      path: \"$path\""
            host="$(echo "$json" | grep -o '"host":"[^"]*"' | cut -d'"' -f4)"
            [ -n "$host" ] && echo "      headers:" && echo "        Host: \"$host\""
            ;;
        grpc)
            echo "    network: grpc"
            echo "    grpc-opts:"
            echo "      grpc-service-name: \"$(echo "$json" | grep -o '"path":"[^"]*"' | cut -d'"' -f4)\""
            ;;
        h2)
            echo "    network: http"
            echo "    http-opts:"
            echo "      path:"
            path="$(echo "$json" | grep -o '"path":"[^"]*"' | cut -d'"' -f4 || echo "/")"
            echo "        - \"$path\""
            host="$(echo "$json" | grep -o '"host":"[^"]*"' | cut -d'"' -f4)"
            [ -n "$host" ] && echo "      headers:" && echo "        Host:" && echo "          - \"$host\""
            ;;
    esac
}

convert_ss() {
    no_scheme="${url#ss://}"
    at_part="${no_scheme%%@*}"
    server_part="${no_scheme#*@}"
    
    method_pass="$(echo "$at_part" | base64 -d)"
    method="${method_pass%%:*}"
    password="${method_pass#*:}"
    
    server="${server_part%%:*}"
    port="${server_part#*:}"
    port="${port%%/*}"
    
    name="$(get_name "$url" "$server:$port")"

    echo "  - name: \"$name\""
    echo "    type: ss"
    echo "    server: $server"
    echo "    port: $port"
    echo "    cipher: $method"
    echo "    password: \"$password\""
    echo "    udp: true"
}

convert_hy() {
    uri="${url#hy://}"
    server_port="${uri%%\?*}"
    server="${server_port%%:*}"
    port="${server_port#*:}"
    query="${uri#*\?}"
    
    name="$(get_name "$url" "$server:$port")"

    echo "  - name: \"$name\""
    echo "    type: hysteria"
    echo "    server: $server"
    echo "    port: $port"
    
    # Parse query parameters
    echo "$query" | tr '&' '\n' | while IFS='=' read -r key value; do
        case "$key" in
            protocol) echo "    protocol: $value" ;;
            upmbps) echo "    up: $value" ;;
            downmbps) echo "    down: $value" ;;
            obfs) echo "    obfs: $value" ;;
            obfsParam) echo "    obfs-password: $value" ;;
            sni) echo "    sni: $value" ;;
            insecure) echo "    insecure: $value" ;;
        esac
    done
}

convert_hy2() {
    uri="${url#hy2://}"
    userinfo="${uri%%@*}"
    server_port="${uri#*@}"
    server="${server_port%%:*}"
    port="${server_port#*:}"
    port="${port%%/*}"
    query="${server_port#*\?}"
    
    name="$(get_name "$url" "$server:$port")"

    echo "  - name: \"$name\""
    echo "    type: hysteria2"
    echo "    server: $server"
    echo "    port: $port"
    echo "    password: \"$userinfo\""
    
    # Parse query parameters
    echo "$query" | tr '&' '\n' | while IFS='=' read -r key value; do
        case "$key" in
            sni) echo "    sni: $value" ;;
            obfs) echo "    obfs: $value" ;;
            obfs-password) echo "    obfs-password: $value" ;;
        esac
    done
}

convert_tuic() {
    uri="${url#tuic://}"
    userinfo="${uri%%@*}"
    uuid="${userinfo%%:*}"
    password="${userinfo#*:}"
    server_port="${uri#*@}"
    server="${server_port%%:*}"
    port="${server_port#*:}"
    port="${port%%/*}"
    query="${server_port#*\?}"
    
    name="$(get_name "$url" "$server:$port")"

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
    echo "$query" | tr '&' '\n' | while IFS='=' read -r key value; do
        case "$key" in
            sni) echo "    sni: $value" ;;
            alpn) echo "    alpn: [${value//,/ }]" ;;
        esac
    done
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