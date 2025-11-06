# Complete Setup Script - Run this from the project root
Write-Host "🚀 Completing Gone Phishin' Setup..." -ForegroundColor Green
Write-Host ""

# Check if ngrok is running
Write-Host "🔍 Checking ngrok..." -ForegroundColor Cyan
$maxRetries = 10
$retry = 0
$success = $false

while ($retry -lt $maxRetries -and -not $success) {
    try {
        $tunnels = Invoke-RestMethod -Uri "http://127.0.0.1:4040/api/tunnels" -ErrorAction Stop
        if ($tunnels.tunnels -and $tunnels.tunnels.Count -gt 0) {
            $ngrokUrl = $tunnels.tunnels[0].public_url
            Write-Host "✅ Found ngrok URL: $ngrokUrl" -ForegroundColor Green
            
            $cleanUrl = $ngrokUrl -replace '^https?://', '' -replace '/$', ''
            
            Write-Host "🔄 Updating files..." -ForegroundColor Cyan
            
            # Update backend/.env
            if (Test-Path "backend\.env") {
                (Get-Content "backend\.env") -replace 'YOUR_NGROK_URL', $cleanUrl | Set-Content "backend\.env"
                Write-Host "  ✅ backend/.env" -ForegroundColor Green
            }
            
            # Update background/background.js
            if (Test-Path "background\background.js") {
                (Get-Content "background\background.js") -replace 'YOUR_NGROK_URL', $cleanUrl | Set-Content "background\background.js"
                Write-Host "  ✅ background/background.js" -ForegroundColor Green
            }
            
            # Update manifest.json
            if (Test-Path "manifest.json") {
                (Get-Content "manifest.json") -replace 'YOUR_NGROK_URL', $cleanUrl | Set-Content "manifest.json"
                Write-Host "  ✅ manifest.json" -ForegroundColor Green
            }
            
            Write-Host ""
            Write-Host "✅✅✅ SETUP COMPLETE! ✅✅✅" -ForegroundColor Green
            Write-Host ""
            Write-Host "ngrok URL: $ngrokUrl" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Next steps:" -ForegroundColor Yellow
            Write-Host "1. Reload extension in Chrome (chrome://extensions/)" -ForegroundColor White
            Write-Host "2. Test by going to https://github.com" -ForegroundColor White
            Write-Host "3. Click extension icon → Test TLS Check" -ForegroundColor White
            
            $success = $true
        } else {
            $retry++
            Write-Host "⏳ Waiting for ngrok tunnel... ($retry/$maxRetries)" -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
    } catch {
        $retry++
        if ($retry -lt $maxRetries) {
            Write-Host "⏳ ngrok not ready yet... ($retry/$maxRetries)" -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        } else {
            Write-Host ""
            Write-Host "⚠️ Could not connect to ngrok automatically." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Please:" -ForegroundColor Yellow
            Write-Host "1. Make sure ngrok is running: .\ngrok\ngrok.exe http 3000" -ForegroundColor White
            Write-Host "2. Check the ngrok window for the URL" -ForegroundColor White
            Write-Host "3. Run: .\update-ngrok-url.ps1 -NgrokUrl 'YOUR_URL'" -ForegroundColor White
        }
    }
}

