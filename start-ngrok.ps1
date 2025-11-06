# Start ngrok with browser warning disabled
# This script starts ngrok with configuration to skip the browser warning page

Write-Host "🚀 Starting ngrok tunnel..." -ForegroundColor Green
Write-Host ""

# Check if ngrok exists
$ngrokPath = ".\ngrok\ngrok.exe"
if (-not (Test-Path $ngrokPath)) {
    Write-Host "❌ ngrok.exe not found at: $ngrokPath" -ForegroundColor Red
    Write-Host "   Please download ngrok and place it in the .\ngrok\ directory" -ForegroundColor Yellow
    exit 1
}

# Check if backend is running on port 3000
$portInUse = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue
if (-not $portInUse) {
    Write-Host "⚠️  Warning: No process found on port 3000" -ForegroundColor Yellow
    Write-Host "   Make sure the backend server is running first!" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "📡 Starting ngrok tunnel to localhost:3000..." -ForegroundColor Cyan
Write-Host "   Note: You may need to visit the ngrok URL once in a browser" -ForegroundColor Gray
Write-Host "   to accept the warning, then API requests will work." -ForegroundColor Gray
Write-Host ""

# Start ngrok
# Note: ngrok free tier doesn't support disabling the warning via command line
# The user needs to visit the URL once in a browser, or we need a paid account
& $ngrokPath http 3000

