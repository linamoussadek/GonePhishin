# Get ngrok URL and update all files
Write-Host "🔍 Getting ngrok URL..." -ForegroundColor Cyan

Start-Sleep -Seconds 2
try {
    $tunnels = Invoke-RestMethod -Uri "http://127.0.0.1:4040/api/tunnels" -ErrorAction Stop
    if ($tunnels.tunnels -and $tunnels.tunnels.Count -gt 0) {
        $ngrokUrl = $tunnels.tunnels[0].public_url
        Write-Host "✅ Found ngrok URL: $ngrokUrl" -ForegroundColor Green
        
        # Remove https:// prefix for replacement
        $cleanUrl = $ngrokUrl -replace '^https?://', '' -replace '/$', ''
        
        Write-Host "🔄 Updating files..." -ForegroundColor Cyan
        
        # Update backend/.env
        if (Test-Path "backend\.env") {
            (Get-Content "backend\.env") -replace 'YOUR_NGROK_URL', $cleanUrl | Set-Content "backend\.env"
            Write-Host "✅ Updated backend/.env" -ForegroundColor Green
        }
        
        # Update background/background.js
        if (Test-Path "background\background.js") {
            (Get-Content "background\background.js") -replace 'YOUR_NGROK_URL', $cleanUrl | Set-Content "background\background.js"
            Write-Host "✅ Updated background/background.js" -ForegroundColor Green
        }
        
        # Update manifest.json
        if (Test-Path "manifest.json") {
            (Get-Content "manifest.json") -replace 'YOUR_NGROK_URL', $cleanUrl | Set-Content "manifest.json"
            Write-Host "✅ Updated manifest.json" -ForegroundColor Green
        }
        
        Write-Host ""
        Write-Host "✅ All files updated with: $ngrokUrl" -ForegroundColor Green
        Write-Host "📝 Next: Reload the extension in Chrome (chrome://extensions/)" -ForegroundColor Cyan
    } else {
        Write-Host "⚠️ No tunnels found. Make sure ngrok is running: .\ngrok\ngrok.exe http 3000" -ForegroundColor Yellow
    }
} catch {
    Write-Host "⚠️ Could not connect to ngrok API. Make sure:" -ForegroundColor Yellow
    Write-Host "   1. ngrok is running: .\ngrok\ngrok.exe http 3000" -ForegroundColor White
    Write-Host "   2. Check http://localhost:4040 for the URL" -ForegroundColor White
    Write-Host "   3. Then run: .\update-ngrok-url.ps1 -NgrokUrl 'YOUR_URL'" -ForegroundColor White
}

