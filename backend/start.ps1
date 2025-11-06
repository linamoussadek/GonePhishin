# Start Backend Server
Write-Host "🚀 Starting Gone Phishin' Backend Server..." -ForegroundColor Green

# Check if .env exists
if (-not (Test-Path .env)) {
    Write-Host "⚠️  .env file not found. Copying from env-template.txt..." -ForegroundColor Yellow
    Copy-Item env-template.txt .env -ErrorAction SilentlyContinue
    Write-Host "✅ .env file created. Please update YOUR_NGROK_URL after setting up ngrok." -ForegroundColor Yellow
}

# Check if node_modules exists
if (-not (Test-Path node_modules)) {
    Write-Host "📦 Installing dependencies..." -ForegroundColor Cyan
    npm install
}

Write-Host "🌐 Starting server on port 3000..." -ForegroundColor Cyan
Write-Host "📡 Notary endpoint will be: http://localhost:3000/api/notary/observe" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. In another terminal, run: ngrok http 3000" -ForegroundColor White
Write-Host "2. Copy your ngrok URL" -ForegroundColor White
Write-Host "3. Update .env file: Replace YOUR_NGROK_URL with your ngrok URL" -ForegroundColor White
Write-Host "4. Update extension files: background/background.js and manifest.json" -ForegroundColor White
Write-Host ""

node server.js

