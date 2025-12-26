param(
    [string]$GitHubUsername = "SrivenSrilakshmi",
    [string]$RepoName = "privacy-llm-architecture",
    [string]$BranchName = "feature/privacy-llm-architecture"
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Privacy-Preserving LLM - GitHub Setup" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Get username if not provided
if ([string]::IsNullOrEmpty($GitHubUsername)) {
    $GitHubUsername = Read-Host "Enter your GitHub username"
}

# Check if git is installed
try {
    git --version | Out-Null
    Write-Host "[OK] Git is installed" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Git is not installed" -ForegroundColor Red
    Write-Host "Download from: https://git-scm.com/download/win" -ForegroundColor Yellow
    exit 1
}

# Initialize git if needed
Write-Host "`n[1/7] Initializing Git..." -ForegroundColor Cyan
if (-not (Test-Path ".git")) {
    git init
    Write-Host "[OK] Git initialized" -ForegroundColor Green
} else {
    Write-Host "[OK] Git already initialized" -ForegroundColor Green
}

# Create .gitignore
Write-Host "`n[2/7] Creating .gitignore..." -ForegroundColor Cyan
@"
__pycache__/
*.pyc
*.pyo
.Python
*.egg-info/
dist/
build/
venv/
.venv/
.env
.idea/
.vscode/
*.log
"@ | Set-Content -Path ".gitignore"
Write-Host "[OK] .gitignore created" -ForegroundColor Green

# Create branch
Write-Host "`n[3/7] Creating branch: $BranchName..." -ForegroundColor Cyan
git checkout -b $BranchName 2>$null
if ($LASTEXITCODE -ne 0) {
    git checkout $BranchName 2>$null
    Write-Host "[OK] Switched to existing branch" -ForegroundColor Yellow
} else {
    Write-Host "[OK] Branch created" -ForegroundColor Green
}

# Stage files
Write-Host "`n[4/7] Staging files..." -ForegroundColor Cyan
git add .
Write-Host "[OK] Files staged" -ForegroundColor Green

# Commit
Write-Host "`n[5/7] Committing..." -ForegroundColor Cyan
git commit -m "feat: Privacy-preserving LLM architecture with ZKP and selective encryption" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Committed" -ForegroundColor Green
} else {
    Write-Host "[INFO] Nothing to commit" -ForegroundColor Yellow
}

# Add remote
Write-Host "`n[6/7] Setting up remote..." -ForegroundColor Cyan
$remoteUrl = "https://github.com/$GitHubUsername/$RepoName.git"
git remote add origin $remoteUrl 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Remote added: $remoteUrl" -ForegroundColor Green
} else {
    git remote set-url origin $remoteUrl
    Write-Host "[OK] Remote updated: $remoteUrl" -ForegroundColor Yellow
}

# Push
Write-Host "`n[7/7] Pushing to GitHub..." -ForegroundColor Cyan
Write-Host "Repository: $remoteUrl" -ForegroundColor White
Write-Host "Branch: $BranchName`n" -ForegroundColor White

$confirm = Read-Host "Push to GitHub? (y/n)"
if ($confirm -eq 'y') {
    Write-Host "`nPushing (you may be prompted for credentials)..." -ForegroundColor Yellow
    git push -u origin $BranchName
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n[SUCCESS] Pushed to GitHub!" -ForegroundColor Green
        Write-Host "`nView at: https://github.com/$GitHubUsername/$RepoName" -ForegroundColor Cyan
    } else {
        Write-Host "`n[FAILED] Push failed" -ForegroundColor Red
        Write-Host "Try: Generate Personal Access Token at https://github.com/settings/tokens" -ForegroundColor Yellow
    }
} else {
    Write-Host "`nSkipped. Run manually: git push -u origin $BranchName" -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
