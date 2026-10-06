Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "    FMagenticL Vercel Deployment Helper  " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Check if logged in
$whoami = npx --yes vercel whoami 2>&1
if ($whoami -match "Error: No existing credentials found") {
    Write-Host "`n[!] No existing Vercel session detected. Initiating browser login..." -ForegroundColor Yellow
    Write-Host "[*] Opening browser for authentication..." -ForegroundColor Green
    
    # Trigger interactive login
    npx --yes vercel login
} else {
    Write-Host "`n[+] Logged in as: $whoami" -ForegroundColor Green
}

Write-Host "`n[*] Deploying FMagenticL to Vercel (Production)..." -ForegroundColor Cyan
npx --yes vercel --prod --yes
