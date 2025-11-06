# Use localhost instead of ngrok for testing
Write-Host "🔄 Configuring for localhost testing (no ngrok needed)..." -ForegroundColor Cyan

cd C:\Users\mouss\OneDrive\Bureau\GonePhishin

# Update backend/.env - use localhost for redirect
if (Test-Path "backend\.env") {
    (Get-Content "backend\.env") -replace 'YOUR_NGROK_URL', 'localhost:3000' | Set-Content "backend\.env"
    Write-Host "✅ Updated backend/.env" -ForegroundColor Green
}

# Update background/background.js - use localhost
if (Test-Path "background\background.js") {
    (Get-Content "background\background.js") -replace 'YOUR_NGROK_URL', 'localhost:3000' | Set-Content "background\background.js"
    Write-Host "✅ Updated background/background.js" -ForegroundColor Green
}

# Update manifest.json - localhost is already in permissions
Write-Host "✅ manifest.json already has localhost permissions" -ForegroundColor Green

Write-Host ""
Write-Host "✅✅✅ Configured for localhost! ✅✅✅" -ForegroundColor Green
Write-Host ""
Write-Host "Note: This works for testing, but Chrome extensions may have CORS issues with localhost." -ForegroundColor Yellow
Write-Host "For production, you'll need ngrok with authentication." -ForegroundColor Yellow
Write-Host ""
Write-Host "Next: Reload extension in Chrome (chrome://extensions/)" -ForegroundColor Cyan

