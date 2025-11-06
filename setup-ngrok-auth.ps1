# Setup ngrok authentication
Write-Host "🔐 ngrok Authentication Setup" -ForegroundColor Green
Write-Host ""

Write-Host "1. Sign up at: https://dashboard.ngrok.com/signup" -ForegroundColor Cyan
Write-Host "2. Get your authtoken from: https://dashboard.ngrok.com/get-started/your-authtoken" -ForegroundColor Cyan
Write-Host ""

$authtoken = Read-Host "Paste your ngrok authtoken here"

if ($authtoken) {
    Write-Host "🔄 Setting up ngrok authtoken..." -ForegroundColor Yellow
    cd C:\Users\mouss\OneDrive\Bureau\GonePhishin
    .\ngrok\ngrok.exe config add-authtoken $authtoken
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Authtoken configured!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Now you can run: .\ngrok\ngrok.exe http 3000" -ForegroundColor Cyan
    } else {
        Write-Host "❌ Failed to set authtoken. Please try manually:" -ForegroundColor Red
        Write-Host ".\ngrok\ngrok.exe config add-authtoken YOUR_TOKEN" -ForegroundColor White
    }
} else {
    Write-Host "❌ No authtoken provided" -ForegroundColor Red
}

