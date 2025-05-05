<#
.SYNOPSIS
    Converts proxy links to Clash Meta format
.DESCRIPTION
    Supports: vless://, vmess://, ss://, hy://, hy2://, tuic://
#>

param (
    [string]$proxyUrl
)

# Check if URL parameter is provided
if (-not $proxyUrl) {
    Write-Host "Usage: .\convert.ps1 'your_proxy_url_here'"
    exit 1
}

function ConvertTo-Clash {
    param ([string]$url)
    switch -Regex ($url) {
        "^vless://" { Convert-VLESS $url }
        "^vmess://" { Convert-VMess $url }
        "^ss://"   { Convert-SS $url }
        "^hy://"   { Convert-Hysteria $url }
        "^hy2://"  { Convert-Hysteria2 $url }
        "^tuic://" { Convert-Tuic $url }
        default { throw "Unsupported URL format" }
    }
}

function Convert-VLESS {
    param ([string]$url)
    $uri = [System.Uri]$url
    $user,$server = $uri.UserInfo.Split('@')
    $query = [System.Web.HttpUtility]::ParseQueryString($uri.Query)
    
    $name = if ($uri.Fragment) { [System.Web.HttpUtility]::UrlDecode($uri.Fragment.TrimStart('#')) } else { "$server`:$($uri.Port)" }
    
    $config = @{
        name    = $name
        type    = "vless"
        server  = $server
        port    = $uri.Port
        uuid    = $user
        network = $query["type"] ?? "tcp"
        tls     = $true
    }

    if ($query["sni"]) { $config.servername = $query["sni"] }
    if ($query["flow"]) { $config.flow = $query["flow"] }
    if ($query["fp"]) { $config."client-fingerprint" = $query["fp"] }
    if ($query["security"] -eq "reality") {
        $config."reality-opts" = @{
            "public-key" = $query["pbk"]
            "short-id"   = $query["sid"]
        }
    }
    Format-Output $config
}

function Convert-VMess {
    param ([string]$url)
    $base64 = $url.Substring(8).Split('#')[0]
    $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64)) | ConvertFrom-Json

    $name = if ($url.Contains('#')) { 
        [System.Web.HttpUtility]::UrlDecode($url.Split('#')[1]) 
    } else { 
        "$($json.add):$($json.port)" 
    }

    $config = @{
        name    = $name
        type    = "vmess"
        server  = $json.add
        port    = $json.port
        uuid    = $json.id
        alterId = $json.aid ?? 0
        cipher  = $json.type ?? "auto"
        udp     = $true
    }

    if ($json.tls -eq "tls") {
        $config.tls = $true
        $config.servername = $json.sni ?? $json.host
    }
    if ($json.net -eq "ws") {
        $config.network = "ws"
        $config."ws-opts" = @{
            path    = $json.path ?? "/"
            headers = @{ Host = $json.host }
        }
    }
    Format-Output $config
}

function Convert-SS {
    param ([string]$url)
    $no_scheme = $url.Substring(5)
    $at_pos = $no_scheme.IndexOf('@')
    $hash_pos = $no_scheme.IndexOf('#')
    
    $method_pass = [System.Text.Encoding]::UTF8.GetString(
        [System.Convert]::FromBase64String(
            $no_scheme.Substring(0, $at_pos)
        )
    )
    $method, $password = $method_pass.Split(':', 2)
    
    $server_port = if ($hash_pos -eq -1) { $no_scheme.Substring($at_pos + 1) } 
                  else { $no_scheme.Substring($at_pos + 1, $hash_pos - $at_pos - 1) }
    $server, $port = $server_port.Split(':', 2)
    
    $name = if ($hash_pos -ne -1) { 
        [System.Web.HttpUtility]::UrlDecode($no_scheme.Substring($hash_pos + 1)) 
    } else { 
        "$server`:$port" 
    }

    $config = @{
        name     = $name
        type     = "ss"
        server   = $server
        port     = $port
        cipher   = $method
        password = $password
        udp      = $true
    }
    Format-Output $config
}

function Format-Output {
    param ([hashtable]$config)
    $yaml = "  - name: `"$($config.name)`"`n"
    $yaml += "    type: $($config.type)`n"
    $yaml += "    server: $($config.server)`n"
    $yaml += "    port: $($config.port)`n"
    
    foreach ($key in $config.Keys) {
        if ($key -notin "name","type","server","port") {
            $value = $config[$key]
            if ($value -is [hashtable]) {
                $yaml += "    $($key):`n"
                foreach ($subKey in $value.Keys) {
                    $yaml += "      $($subKey): $($value[$subKey])`n"
                }
            } else {
                $yaml += "    $($key): $value`n"
            }
        }
    }
    $yaml.Trim()
}

# Main execution
try {
    Write-Output "proxies:"
    ConvertTo-Clash $proxyUrl
} catch {
    Write-Error "Error: $_"
    exit 1
}