# Configure ngrok to skip browser warning
# This creates an ngrok config file that adds the skip-warning header automatically

Write-Host "⚙️  Configuring ngrok to skip browser warning..." -ForegroundColor Green
Write-Host ""

$ngrokConfigPath = "$env:APPDATA\ngrok\ngrok.yml"

# Create ngrok config directory if it doesn't exist
$ngrokConfigDir = Split-Path -Parent $ngrokConfigPath
if (-not (Test-Path $ngrokConfigDir)) {
    New-Item -ItemType Directory -Path $ngrokConfigDir -Force | Out-Null
}

# Read existing config or create new
$config = @"
version: "2"
authtoken: YOUR_AUTHTOKEN_HERE
tunnels:
  backend:
    proto: http
    addr: 3000
    inspect: false
    request_header:
      add:
        - "ngrok-skip-browser-warning: true"
"@

# Check if config exists
if (Test-Path $ngrokConfigPath) {
    Write-Host "⚠️  ngrok.yml already exists at: $ngrokConfigPath" -ForegroundColor Yellow
    Write-Host "   Backing up to ngrok.yml.backup" -ForegroundColor Yellow
    Copy-Item $ngrokConfigPath "$ngrokConfigPath.backup" -ErrorAction SilentlyContinue
}

# Write config
$config | Out-File -FilePath $ngrokConfigPath -Encoding utf8
Write-Host "✅ Created ngrok config at: $ngrokConfigPath" -ForegroundColor Green
Write-Host ""
Write-Host "⚠️  IMPORTANT: Replace YOUR_AUTHTOKEN_HERE with your actual ngrok authtoken!" -ForegroundColor Yellow
Write-Host "   Get it from: https://dashboard.ngrok.com/get-started/your-authtoken" -ForegroundColor Cyan
Write-Host ""
Write-Host "Then start ngrok with:" -ForegroundColor Cyan
Write-Host "  .\ngrok\ngrok.exe start backend" -ForegroundColor White
Write-Host ""
Write-Host "OR visit the ngrok URL once in your browser to accept the warning." -ForegroundColor Gray

