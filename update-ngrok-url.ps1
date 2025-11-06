# Update ngrok URL in all necessary files
param(
    [Parameter(Mandatory=$true)]
    [string]$NgrokUrl
)

Write-Host "🔄 Updating ngrok URL to: $NgrokUrl" -ForegroundColor Cyan

# Remove https:// and trailing slash if present
$cleanUrl = $NgrokUrl -replace '^https?://', '' -replace '/$', ''

# Update backend/.env
$envFile = "backend\.env"
if (Test-Path $envFile) {
    $content = Get-Content $envFile -Raw
    $content = $content -replace 'YOUR_NGROK_URL', $cleanUrl
    Set-Content $envFile -Value $content -NoNewline
    Write-Host "✅ Updated backend/.env" -ForegroundColor Green
} else {
    Write-Host "⚠️  backend/.env not found" -ForegroundColor Yellow
}

# Update background/background.js
$bgFile = "background\background.js"
if (Test-Path $bgFile) {
    $content = Get-Content $bgFile -Raw
    $content = $content -replace 'YOUR_NGROK_URL', $cleanUrl
    Set-Content $bgFile -Value $content -NoNewline
    Write-Host "✅ Updated background/background.js" -ForegroundColor Green
} else {
    Write-Host "⚠️  background/background.js not found" -ForegroundColor Yellow
}

# Update manifest.json
$manifestFile = "manifest.json"
if (Test-Path $manifestFile) {
    $content = Get-Content $manifestFile -Raw
    $content = $content -replace 'YOUR_NGROK_URL', $cleanUrl
    Set-Content $manifestFile -Value $content -NoNewline
    Write-Host "✅ Updated manifest.json" -ForegroundColor Green
} else {
    Write-Host "⚠️  manifest.json not found" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "✅ All files updated!" -ForegroundColor Green
Write-Host "📝 Next: Reload the extension in Chrome (chrome://extensions/)" -ForegroundColor Cyan

