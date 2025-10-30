# Helper script to get OpenSSL modules directory
$line = (openssl version -a 2>$null | Select-String 'MODULESDIR').Line
if ($line -match 'MODULESDIR:\s*"([^"]+)"') {
    Write-Output $matches[1]
}
