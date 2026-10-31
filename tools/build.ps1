# Builds SerialPill with an isolated PlatformIO core (~/.serialpill-pio) and creates the
# Shelly OTA package in dist/. Run from PowerShell (ESP-IDF refuses MSYS/Git Bash).
#   powershell -ExecutionPolicy Bypass -File tools\build.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$py = "$env:USERPROFILE\.serialpill-venv\Scripts\python.exe"
$ca = "$env:USERPROFILE\.serialpill-venv\ca-bundle.pem"
$env:PLATFORMIO_CORE_DIR = "$env:USERPROFILE\.serialpill-pio"
if (Test-Path $ca) {
    # TLS-inspecting antivirus (Norton) re-signs github.com; trust the Windows root store.
    $env:SSL_CERT_FILE = $ca; $env:REQUESTS_CA_BUNDLE = $ca; $env:PIP_CERT = $ca
    $env:UV_NATIVE_TLS = "1"; $env:UV_SYSTEM_CERTS = "1"     # old and new uv spelling
    # pioarduino points SSL_CERT_FILE at the certifi bundle of its own penv, which pip updates
    # replace: put the Windows-store bundle there before every build.
    $penvPy = "$env:PLATFORMIO_CORE_DIR\penv\Scripts\python.exe"
    if (Test-Path $penvPy) {
        $certifi = & $penvPy -c "import certifi; print(certifi.where())" 2>$null
        if ($certifi -and (Test-Path $certifi)) { Copy-Item $ca $certifi -Force }
    }
}
Push-Location $root
try {
    & $py -m platformio run
    if ($LASTEXITCODE -ne 0) { throw "build failed" }
    & $py tools\mkpkg.py --app .pio\build\pill\firmware.bin --bootloader .pio\build\pill\bootloader.bin --out dist
    if ($LASTEXITCODE -ne 0) { throw "packaging failed" }
} finally { Pop-Location }
