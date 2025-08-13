import sys
import json
import base64
from urllib.parse import urlparse, parse_qs, unquote

def b64decode_auto(data: str) -> str:
    if not data:
        return ""
    data = data.replace("-", "+").replace("_", "/")
    pad = (4 - len(data) % 4) % 4
    data = data + ("=" * pad)
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def yaml_quote(s):
    if s is None:
        return None
    s = str(s)
    s = s.replace("\\", "\\\\").replace("\"", "\\\"")
    return f"\"{s}\""

def emit_line(lines, text="", indent=0):
    lines.append((" " * indent) + text)

def emit_kv(lines, key, value, indent=0, quote=True):
    if value is None or value == "":
        return
    if isinstance(value, bool):
        emit_line(lines, f"{key}: {'true' if value else 'false'}", indent)
        return
    if quote and not isinstance(value, (int, float)):
        value = yaml_quote(value)
    emit_line(lines, f"{key}: {value}", indent)

def emit_bool(lines, key, flag, indent=0):
    if flag is None:
        return
    emit_line(lines, f"{key}: {'true' if flag else 'false'}", indent)

def emit_list(lines, key, items, indent=0):
    if not items:
        return
    emit_line(lines, f"{key}:", indent)
    for it in items:
        emit_line(lines, f"- {yaml_quote(it)}", indent + 2)

def parsed_qs(parsed):
    return {k: v[0] if v else "" for k, v in parse_qs(parsed.query).items()}

def parse_vless(u):
    q = parsed_qs(u)
    name = unquote(u.fragment) if u.fragment else (u.hostname or "vless")
    proxy = {
        "name": name,
        "type": "vless",
        "server": u.hostname,
        "port": u.port,
        "uuid": u.username,
        "network": q.get("type", "tcp"),
        "udp": True,
    }
    sec = q.get("security", "")
    if sec == "reality":
        proxy["tls"] = True
        proxy["reality-opts"] = {
            "public-key": q.get("pbk"),
            "short-id": q.get("sid")
        }
    elif sec == "tls":
        proxy["tls"] = True
    if q.get("flow"): proxy["flow"] = q["flow"]
    if q.get("sni"): proxy["servername"] = q["sni"]
    if q.get("fp"):  proxy["client-fingerprint"] = q["fp"]
    if q.get("type") == "ws":
        ws = {"path": q.get("path", "")}
        if q.get("host"):
            ws["headers"] = {"Host": q["host"]}
        proxy["ws-opts"] = ws
    return proxy

def parse_vmess(u):
    rest = (u.netloc or "") + (u.path or "")
    if "@" not in rest and not u.query:
        decoded = b64decode_auto(rest)
        try:
            cfg = json.loads(decoded)
        except Exception:
            raise ValueError("Invalid vmess base64 JSON")
        name = unquote(u.fragment) if u.fragment else (cfg.get("ps") or cfg.get("add") or "vmess")
        proxy = {
            "name": name,
            "type": "vmess",
            "server": cfg.get("add"),
            "port": int(cfg.get("port")) if str(cfg.get("port")).isdigit() else cfg.get("port"),
            "uuid": cfg.get("id"),
            "cipher": "auto",
            "network": cfg.get("net", "tcp"),
            "udp": True,
        }
        aid = cfg.get("aid")
        if aid not in (None, "0", 0):
            proxy["alterId"] = aid
        tls = str(cfg.get("tls") or "").lower()
        if tls in ("tls", "1", "true"):
            proxy["tls"] = True
        if cfg.get("sni"):
            proxy["servername"] = cfg["sni"]
        if cfg.get("skip-cert-verify") is True:
            proxy["skip-cert-verify"] = True
        if proxy["network"] == "ws":
            ws = {"path": cfg.get("path", "")}
            if cfg.get("host"):
                ws["headers"] = {"Host": cfg["host"]}
            proxy["ws-opts"] = ws
        return proxy
    else:
        q = parsed_qs(u)
        name = unquote(u.fragment) if u.fragment else (u.hostname or "vmess")
        proxy = {
            "name": name,
            "type": "vmess",
            "server": u.hostname,
            "port": u.port,
            "uuid": u.username,
            "cipher": "auto",
            "network": q.get("type", "tcp"),
            "udp": True,
        }
        if q.get("security") == "tls":
            proxy["tls"] = True
        if q.get("sni"): proxy["servername"] = q["sni"]
        if proxy["network"] == "ws":
            ws = {"path": q.get("path", "")}
            if q.get("host"):
                ws["headers"] = {"Host": q["host"]}
            proxy["ws-opts"] = ws
        return proxy

def parse_ss(u):
    rest = (u.netloc or "") + (u.path or "")
    name = unquote(u.fragment) if u.fragment else "ss"
    method = password = host = port = None
    if "@" not in rest:
        decoded = b64decode_auto(rest)
        if "@" in decoded and ":" in decoded:
            userinfo, hostinfo = decoded.split("@", 1)
            if ":" in userinfo:
                method, password = userinfo.split(":", 1)
            if ":" in hostinfo:
                host, port = hostinfo.split(":", 1)
        else:
            method = decoded.split(":", 1)[0] if ":" in decoded else decoded
            password = decoded.split(":", 1)[1] if ":" in decoded else ""
    else:
        if u.username and ":" in u.username:
            method, password = u.username.split(":", 1)
        else:
            method = u.username
        host = u.hostname
        port = str(u.port) if u.port is not None else None

    q = parsed_qs(u)
    proxy = {
        "name": name if name != "ss" else (host or "ss"),
        "type": "ss",
        "server": host,
        "port": int(port) if port and str(port).isdigit() else port,
        "cipher": method,
        "password": password,
        "udp": True,
    }
    if q.get("plugin"):
        proxy["plugin"] = q["plugin"]
        parts = q["plugin"].split(";")
        if len(parts) > 1:
            popt = {}
            for p in parts[1:]:
                if not p:
                    continue
                if "=" in p:
                    k, v = p.split("=", 1)
                    popt[k] = v
                else:
                    popt[p] = "true"
            if popt:
                proxy["plugin-opts"] = popt
    return proxy

def parse_trojan(u):
    q = parsed_qs(u)
    name = unquote(u.fragment) if u.fragment else (u.hostname or "trojan")
    proxy = {
        "name": name,
        "type": "trojan",
        "server": u.hostname,
        "port": u.port,
        "password": u.username,
        "udp": True,
    }
    if q.get("security") == "tls" or q.get("sni"):
        proxy["tls"] = True
    if q.get("sni"):
        proxy["servername"] = q["sni"]
    if q.get("type") == "ws":
        proxy["network"] = "ws"
        ws = {"path": q.get("path", "")}
        if q.get("host"):
            ws["headers"] = {"Host": q["host"]}
        proxy["ws-opts"] = ws
    return proxy

def parse_hy(u, hy2=False):
    q = parsed_qs(u)
    name = unquote(u.fragment) if u.fragment else (u.hostname or ("hysteria2" if hy2 else "hysteria"))
    proxy = {
        "name": name,
        "type": "hysteria2" if hy2 else "hysteria",
        "server": u.hostname,
        "port": u.port,
        "udp": True, 
    }
    if hy2:
        proxy["password"] = u.username
    else:
        proxy["auth"] = q.get("auth")
        if "insecure" in q:
            val = q["insecure"]
            proxy["insecure"] = val in ("1", "true", "True")
        if "upmbps" in q:
            proxy["up-mbps"] = int(q["upmbps"]) if q["upmbps"].isdigit() else q["upmbps"]
        if "downmbps" in q:
            proxy["down-mbps"] = int(q["downmbps"]) if q["downmbps"].isdigit() else q["downmbps"]
    if q.get("alpn"):
        proxy["alpn"] = [x.strip() for x in q["alpn"].split(",") if x.strip()]
    return proxy

def parse_tuic(u):
    q = parsed_qs(u)
    name = unquote(u.fragment) if u.fragment else (u.hostname or "tuic")
    uuid = passwd = None
    if u.username and ":" in u.username:
        uuid, passwd = u.username.split(":", 1)
    else:
        uuid = u.username
    proxy = {
        "name": name,
        "type": "tuic",
        "server": u.hostname,
        "port": u.port,
        "uuid": uuid,
        "password": passwd,
        "udp": True,
    }
    if q.get("sni"):
        proxy["sni"] = q["sni"]
    if q.get("alpn"):
        proxy["alpn"] = [x for x in q["alpn"].split(",") if x]
    if q.get("congestion_control"):
        proxy["congestion-controller"] = q["congestion_control"]
    elif q.get("congestion-controller"):
        proxy["congestion-controller"] = q["congestion-controller"]
    if q.get("udp_relay_mode"):
        proxy["udp-relay-mode"] = q["udp_relay_mode"]
    return proxy

def parse_one(url: str):
    u = urlparse(url)
    scheme = (u.scheme or "").lower()
    if scheme == "vless":   return parse_vless(u)
    if scheme == "vmess":   return parse_vmess(u)
    if scheme == "ss":      return parse_ss(u)
    if scheme == "trojan":  return parse_trojan(u)
    if scheme == "hysteria": return parse_hy(u, hy2=False)
    if scheme == "hy":      return parse_hy(u, hy2=False)
    if scheme == "hy2":     return parse_hy(u, hy2=True)
    if scheme == "tuic":    return parse_tuic(u)
    raise ValueError(f"Unsupported scheme: {scheme or '(empty)'}")

def emit_yaml(proxies):
    lines = []
    emit_line(lines, "proxies:")
    for p in proxies:
        emit_line(lines, "- name: " + yaml_quote(p.get("name") or "proxy"), 2)
        emit_kv(lines, "type", p.get("type"), 4)
        emit_kv(lines, "server", p.get("server"), 4, quote=False)
        if p.get("port") is not None:
            emit_kv(lines, "port", p.get("port"), 4, quote=False)
        for k in ("uuid", "password", "cipher", "alterId", "network", "flow",
                  "servername", "client-fingerprint", "sni", "auth_str", "auth"):
            if k in p:
                emit_kv(lines, k, p[k], 4)
        if "tls" in p:
            emit_bool(lines, "tls", bool(p["tls"]), 4)
        if "udp" in p:
            emit_bool(lines, "udp", bool(p["udp"]), 4)
        if "insecure" in p:
            emit_bool(lines, "insecure", bool(p["insecure"]), 4)
        if "up-mbps" in p:
            emit_kv(lines, "up-mbps", p["up-mbps"], 4, quote=False)
        if "down-mbps" in p:
            emit_kv(lines, "down-mbps", p["down-mbps"], 4, quote=False)
        if "ws-opts" in p and isinstance(p["ws-opts"], dict):
            emit_line(lines, "ws-opts:", 4)
            if "path" in p["ws-opts"]:
                emit_kv(lines, "path", p["ws-opts"]["path"], 6)
            if p["ws-opts"].get("headers"):
                emit_line(lines, "headers:", 6)
                for hk, hv in p["ws-opts"]["headers"].items():
                    emit_kv(lines, hk, hv, 8)
        if "reality-opts" in p and isinstance(p["reality-opts"], dict):
            emit_line(lines, "reality-opts:", 4)
            for rk, rv in p["reality-opts"].items():
                if rv:
                    emit_kv(lines, rk, rv, 6)
        if "plugin" in p:
            emit_kv(lines, "plugin", p["plugin"], 4)
        if "plugin-opts" in p and isinstance(p["plugin-opts"], dict):
            emit_line(lines, "plugin-opts:", 4)
            for pk, pv in p["plugin-opts"].items():
                emit_kv(lines, pk, pv, 6)
        if "alpn" in p and isinstance(p["alpn"], list):
            emit_list(lines, "alpn", p["alpn"], 4)
        for extra in ("obfs", "obfs-password", "congestion-controller", "udp-relay-mode", "skip-cert-verify"):
            if extra in p:
                emit_kv(lines, extra, p[extra], 4)
    return "\n".join(lines) + "\n"

def main():
    if len(sys.argv) < 2:
        print(f"Usage:\n  {sys.argv[0]} 'proxy_url' [more_urls...]", file=sys.stderr)
        sys.exit(1)
    proxies = []
    for arg in sys.argv[1:]:
        try:
            proxies.append(parse_one(arg))
        except Exception as e:
            print(f"# Failed to parse: {arg}\n# {e}", file=sys.stderr)
            sys.exit(2)
    sys.stdout.write(emit_yaml(proxies))

if __name__ == "__main__":
    main()
