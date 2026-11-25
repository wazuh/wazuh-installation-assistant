# agent-conf-5x.ps1 - Windows counterpart of agent-conf-5x.py (arm AG1 of the 4.x -> 5.0 migration lab).
# Brings an upgraded Windows agent's own ossec.conf to the 5.0 shape: the first <client> block becomes <agent> with one
# <manager><endpoint>, <config-profile>, <notify_time>, <auto_restart> and the <enrollment> options 5.0 still reads;
# <client_buffer> and the options 5.0 ignores are dropped. Refuses on a 4.x agent (it would not start), keeps a backup,
# validates by starting the service and restores the backup if the agent does not come up.
#   powershell -ExecutionPolicy Bypass -File agent-conf-5x.ps1 [-Endpoint host[:port]] [-EndpointPolicy last|first] [-Restart]
param(
  [string]$Endpoint = '',
  [ValidateSet('', 'first', 'last')][string]$EndpointPolicy = '',
  [switch]$Restart,
  [string]$AgentDir = 'C:\Program Files (x86)\ossec-agent'
)
$ErrorActionPreference = 'Stop'
$conf = Join-Path $AgentDir 'ossec.conf'
$ver = $null
try { $ver = (Get-Content (Join-Path $AgentDir 'VERSION.json') -Raw | ConvertFrom-Json).version } catch { }
if (-not $ver -or [version]($ver -replace '[^0-9.]', '') -lt [version]'5.0.0') {
  Write-Output "refused: the installed agent is '$ver'; a 4.x agent does not start with an <agent> block. Convert after the upgrade."
  exit 2
}
$text = [IO.File]::ReadAllText($conf)
$live = [regex]::Replace($text, '(?s)<!--.*?-->', '')
if ($live -notmatch '<client>') { Write-Output 'no <client> block: nothing to do'; exit 0 }
$m = [regex]::Match($text, '(?s)([ \t]*)<client>(.*?)</client>')
$indent = $m.Groups[1].Value; $body = [regex]::Replace($m.Groups[2].Value, '(?s)<!--.*?-->', '')
function Tag($s, $n) { $x = [regex]::Match($s, "(?s)<$n>\s*(.*?)\s*</$n>"); if ($x.Success) { return $x.Groups[1].Value } else { return $null } }
$addrs = @([regex]::Matches($body, '(?s)<server>(.*?)</server>') | ForEach-Object { Tag $_.Groups[1].Value 'address' } | Where-Object { $_ })
$report = [ordered]@{ servers_4x = $addrs; kept = [ordered]@{}; dropped = [ordered]@{} }
if ($Endpoint) { $chosen = $Endpoint }
elseif ($addrs.Count -eq 1) { $chosen = $addrs[0] }
elseif ($addrs.Count -gt 1 -and $EndpointPolicy) { $chosen = if ($EndpointPolicy -eq 'first') { $addrs[0] } else { $addrs[-1] } }
else {
  Write-Output "refused: $($addrs.Count) manager addresses ($($addrs -join ', ')): 5.0 dials only the last one and never fails over. Pass -Endpoint (one address in the listener certificate that reaches every node) or -EndpointPolicy last|first."
  exit 2
}
if ($addrs.Count -gt 1) { $report.dropped['other_managers'] = @($addrs | Where-Object { $_ -ne ($chosen -split ':')[0] }) }
$lines = @("$indent<agent>", "$indent  <manager>", "$indent    <endpoint>$chosen</endpoint>", "$indent  </manager>")
foreach ($k in 'config-profile', 'notify_time', 'auto_restart') { $v = Tag $body $k; if ($null -ne $v) { $lines += "$indent  <$k>$v</$k>"; $report.kept[$k] = $v } }
foreach ($k in 'time-reconnect', 'crypto_method', 'ip_update_interval', 'force_reconnect_interval', 'remote_conf') { $v = Tag $body $k; if ($null -ne $v) { $report.dropped[$k] = $v } }
$enr = Tag $body 'enrollment'
if ($null -ne $enr) {
  $sub = @()
  foreach ($k in 'enabled', 'agent_name', 'groups', 'agent_address', 'delay_after_enrollment', 'use_source_ip', 'authorization_pass_path') { $v = Tag $enr $k; if ($k -eq 'authorization_pass_path' -and $v -in @('etc/authd.pass','authd.pass')) { $report.dropped["enrollment/$k"] = "$v (4.x default)"; continue }; if ($null -ne $v) { $sub += "$indent    <$k>$v</$k>" } }
  foreach ($k in 'manager_address', 'port', 'ssl_cipher', 'server_ca_path', 'agent_certificate_path', 'agent_key_path', 'auto_method') { $v = Tag $enr $k; if ($null -ne $v) { $report.dropped["enrollment/$k"] = $v } }
  if ($sub.Count) { $lines += "$indent  <enrollment>"; $lines += $sub; $lines += "$indent  </enrollment>" }
}
$lines += "$indent</agent>"
$new = $text.Substring(0, $m.Index) + ($lines -join "`r`n") + $text.Substring($m.Index + $m.Length)
# E4-rpm gap 6: each removed block is reported by its own name (the key was the regex with its non-letters stripped:
# "s tclient_bufferclient_buffer trn")
foreach ($blk in @(@('client_buffer', '(?s)[ \t]*<client_buffer>.*?</client_buffer>[ \t]*\r?\n?'), @('wodle cis-cat', '(?s)[ \t]*<wodle name="cis-cat">.*?</wodle>[ \t]*\r?\n?'), @('wodle osquery', '(?s)[ \t]*<wodle name="osquery">.*?</wodle>[ \t]*\r?\n?'))) {
  $name = $blk[0]; $rx = $blk[1]
  if ([regex]::IsMatch($new, $rx)) { $report.dropped[$name] = 'removed'; $new = [regex]::Replace($new, $rx, '') }
}
$backup = "$conf.4x-backup-$(Get-Date -Format yyyyMMddHHmmss)"
Copy-Item $conf $backup
[IO.File]::WriteAllText($conf, $new)
$report['backup'] = $backup
if ($Restart) {
  Restart-Service WazuhSvc
  Start-Sleep 10
  $svc = (Get-Service WazuhSvc).Status
  $report['service'] = "$svc"
  if ($svc -ne 'Running') { Copy-Item $backup $conf -Force; Start-Service WazuhSvc; $report['restored'] = $true; $report | ConvertTo-Json -Depth 4; exit 3 }
}
$report | ConvertTo-Json -Depth 4
