param(
    [Parameter(Mandatory=$true)]
    [string]$Path
)

if (-not (Test-Path $Path)) {
    Write-Error "File not found: $Path"
    exit 1
}

$bytes = [System.IO.File]::ReadAllBytes($Path)

if ($bytes.Length -lt 0x40 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
    Write-Error "Not a valid MZ/PE file: $Path"
    exit 1
}

$peSigOffset = [System.BitConverter]::ToUInt32($bytes, 0x3C)
if ($peSigOffset -ge $bytes.Length - 4 -or
    [System.BitConverter]::ToUInt32($bytes, $peSigOffset) -ne 0x00004550) {
    Write-Error "PE signature not found"
    exit 1
}

# --- 1. Strip Rich Header ---
# (Not removable via Cargo.toml — written by link.exe, not rustc)
$richFound = $false
for ($i = 0x80; $i -lt $peSigOffset - 8; $i++) {
    if ($bytes[$i]   -eq 0x52 -and $bytes[$i+1] -eq 0x69 -and
        $bytes[$i+2] -eq 0x63 -and $bytes[$i+3] -eq 0x68) {   # "Rich"

        $xorKey     = [System.BitConverter]::ToUInt32($bytes, $i + 4)
        $dansBytes  = [System.BitConverter]::GetBytes([uint32](0x536E6144 -bxor $xorKey))

        $start = 0x80
        for ($k = 0x80; $k -lt $i - 4; $k++) {
            if ($bytes[$k]   -eq $dansBytes[0] -and $bytes[$k+1] -eq $dansBytes[1] -and
                $bytes[$k+2] -eq $dansBytes[2] -and $bytes[$k+3] -eq $dansBytes[3]) {
                $start = $k
                break
            }
        }

        for ($j = $start; $j -lt $i + 8 -and $j -lt $peSigOffset; $j++) {
            $bytes[$j] = 0
        }
        Write-Host "[OK] Rich header stripped (0x$($start.ToString('X'))..0x$(($i+8).ToString('X')))"
        $richFound = $true
        break
    }
}
if (-not $richFound) {
    Write-Host "[--] No Rich header found (GNU toolchain or already stripped)"
}

# --- 2. Spoof TimeDateStamp ---
# (Not removable via Cargo.toml — PE header field set by the linker)
$fileHeaderOff    = $peSigOffset + 4
$timeDateStampOff = $fileHeaderOff + 4
$fakeTs           = [System.BitConverter]::GetBytes([uint32]0x62E5C6D0)
$fakeTs.CopyTo($bytes, $timeDateStampOff)
Write-Host "[OK] TimeDateStamp spoofed to 0x62E5C6D0"

[System.IO.File]::WriteAllBytes($Path, $bytes)
Write-Host "[OK] PE obfuscation complete: $Path"