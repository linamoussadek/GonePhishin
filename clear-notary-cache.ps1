# Clear notary cache from Chrome extension storage
Write-Host "🧹 Clearing notary cache..." -ForegroundColor Cyan
Write-Host ""
Write-Host "To clear the cache:" -ForegroundColor Yellow
Write-Host "1. Open Chrome DevTools (F12)" -ForegroundColor White
Write-Host "2. Go to Application tab → Storage → Local Storage" -ForegroundColor White
Write-Host "3. Find keys starting with 'notary_cache_' and 'notary_rate_'" -ForegroundColor White
Write-Host "4. Delete them" -ForegroundColor White
Write-Host ""
Write-Host "Or reload the extension - it will use new endpoints on next query" -ForegroundColor Cyan
Write-Host ""
Write-Host "The extension has been updated to use ngrok URL." -ForegroundColor Green
Write-Host "After reloading, it will query: https://nonmagnetical-ronin-schizomycetic.ngrok-free.dev/api/notary/observe" -ForegroundColor Cyan

