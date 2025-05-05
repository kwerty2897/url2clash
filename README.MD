# Proxy URL to Clash Meta

## Supported Protocols
- `vless://` (with Reality support)
- `vmess://`
- `ss://`
- `hy://` (Hysteria v1)
- `hy2://` (Hysteria v2) 
- `tuic://`

## Usage

### PowerShell
```powershell
.\url2clash.ps1 'your_proxy_url_here'
```
*Requires: PowerShell 5.1+*

### Bash
```bash
./url2clash.sh 'your_proxy_url_here'
```
*Requires: `jq`, `base64`*

### Ash (for routers/BusyBox)
```bash
./url2clash.ash 'your_proxy_url_here'
```
*Requires: `base64`*