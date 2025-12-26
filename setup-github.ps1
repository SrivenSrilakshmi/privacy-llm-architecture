# Privacy-Preserving LLM Architecture Setup Script
# Run this script to initialize git and push to GitHub

param(
    [Parameter(Mandatory=$false)]
    [string]$GitHubUsername = "",
    
    [Parameter(Mandatory=$false)]
    [string]$RepoName = "privacy-llm-architecture",
    
    [Parameter(Mandatory=$false)]
    [string]$BranchName = "feature/privacy-llm-architecture",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipPush = $false
)

# Colors for output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

Write-ColorOutput "`n========================================" "Cyan"
Write-ColorOutput "Privacy-Preserving LLM - GitHub Setup" "Cyan"
Write-ColorOutput "========================================`n" "Cyan"

# Get GitHub username if not provided
if ([string]::IsNullOrEmpty($GitHubUsername)) {
    $GitHubUsername = Read-Host "Enter your GitHub username"
}

# Navigate to project directory
$projectPath = "C:\privacy-llm-architecture"
if (-not (Test-Path $projectPath)) {
    Write-ColorOutput "Error: Project directory not found at $projectPath" "Red"
    exit 1
}

Set-Location $projectPath
Write-ColorOutput "✓ Changed to project directory: $projectPath" "Green"

# Check if git is installed
try {
    git --version | Out-Null
    Write-ColorOutput "✓ Git is installed" "Green"
} catch {
    Write-ColorOutput "✗ Git is not installed. Please install Git first." "Red"
    Write-ColorOutput "  Download from: https://git-scm.com/download/win" "Yellow"
    exit 1
}

# Initialize git repository if not already initialized
if (-not (Test-Path ".git")) {
    Write-ColorOutput "`n[1/8] Initializing Git repository..." "Cyan"
    git init
    Write-ColorOutput "✓ Git repository initialized" "Green"
} else {
    Write-ColorOutput "`n[1/8] Git repository already initialized" "Green"
}

# Create .gitignore
Write-ColorOutput "`n[2/8] Creating .gitignore..." "Cyan"
$gitignoreContent = @"
# Python
__pycache__/
*.py[cod]
*`$py.class
*.so
.Python
*.egg
*.egg-info/
dist/
build/
develop-eggs/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
pip-wheel-metadata/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
ENV/
env/
.venv/
env.bak/
venv.bak/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~
.project
.pydevproject

# OS
.DS_Store
Thumbs.db
desktop.ini

# Logs
*.log
logs/

# Environment
.env
.env.local
.env.*.local

# Testing
.pytest_cache/
.coverage
.coverage.*
htmlcov/
.tox/
.nox/

# Jupyter
.ipynb_checkpoints/
*.ipynb

# Distribution
*.tar.gz
*.whl

# Temporary
*.tmp
*.bak
*.swp
"@

$gitignoreContent | Out-File -FilePath ".gitignore" -Encoding utf8
Write-ColorOutput "✓ .gitignore created" "Green"

# Check current branch
$currentBranch = git rev-parse --abbrev-ref HEAD 2>$null

if ($currentBranch -eq "HEAD") {
    # No commits yet, create initial commit on default branch
    Write-ColorOutput "`n[3/8] Creating initial commit..." "Cyan"
    git add .
    git commit -m "Initial commit: Privacy-preserving LLM architecture" 2>$null
    Write-ColorOutput "✓ Initial commit created" "Green"
}

# Create and switch to feature branch
Write-ColorOutput "`n[4/8] Creating feature branch: $BranchName..." "Cyan"
try {
    git checkout -b $BranchName 2>$null
    if ($LASTEXITCODE -ne 0) {
        # Branch might already exist
        git checkout $BranchName
        Write-ColorOutput "✓ Switched to existing branch: $BranchName" "Yellow"
    } else {
        Write-ColorOutput "✓ Created and switched to branch: $BranchName" "Green"
    }
} catch {
    Write-ColorOutput "! Branch may already exist, switching..." "Yellow"
    git checkout $BranchName
}

# Stage all files
Write-ColorOutput "`n[5/8] Staging files..." "Cyan"
git add .
$stagedFiles = (git diff --cached --name-only).Count
Write-ColorOutput "✓ Staged $stagedFiles files" "Green"

# Show what will be committed
Write-ColorOutput "`nFiles to be committed:" "Yellow"
git status --short

# Commit changes
Write-ColorOutput "`n[6/8] Committing changes..." "Cyan"
$commitMessage = @"
feat: Privacy-preserving LLM architecture with ZKP and selective encryption

Implements a cryptographically-secured architecture for LLM interactions:

Core Features:
- Selective encryption (ChaCha20-Poly1305, AES-GCM)
- Zero-knowledge proofs (Schnorr protocol)
- Modular skeleton & branches design
- GDPR/HIPAA/PCI-DSS compliance

Components:
- PII detectors: regex, transformer, hybrid
- Protection policies: minimal, contextual, compliance
- Encryption schemes: pluggable AEAD ciphers
- Proof systems: production-ready ZKP
- Complete test suite and demos

Architecture:
- Client-side PII processing (trusted zone)
- Server-side ZKP verification (untrusted zone)
- No raw PII transmission
- Cryptographic trust boundaries
"@

git commit -m $commitMessage 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-ColorOutput "✓ Changes committed" "Green"
} else {
    Write-ColorOutput "! No changes to commit (already committed)" "Yellow"
}

# Add remote
Write-ColorOutput "`n[7/8] Setting up remote..." "Cyan"
$remoteUrl = "https://github.com/$GitHubUsername/$RepoName.git"

$existingRemote = git remote get-url origin 2>$null
if ($existingRemote) {
    Write-ColorOutput "! Remote 'origin' already exists: $existingRemote" "Yellow"
    $updateRemote = Read-Host "Update remote URL? (y/n)"
    if ($updateRemote -eq 'y') {
        git remote set-url origin $remoteUrl
        Write-ColorOutput "✓ Remote URL updated to: $remoteUrl" "Green"
    }
} else {
    git remote add origin $remoteUrl
    Write-ColorOutput "✓ Remote 'origin' added: $remoteUrl" "Green"
}

# Push to GitHub
if (-not $SkipPush) {
    Write-ColorOutput "`n[8/8] Pushing to GitHub..." "Cyan"
    Write-ColorOutput "Repository: $remoteUrl" "White"
    Write-ColorOutput "Branch: $BranchName" "White"
    
    $pushConfirm = Read-Host "`nReady to push to GitHub? (y/n)"
    if ($pushConfirm -eq 'y') {
        Write-ColorOutput "`nPushing... (you may be prompted for authentication)" "Yellow"
        git push -u origin $BranchName
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "`n✓ Successfully pushed to GitHub!" "Green"
            Write-ColorOutput "`nNext steps:" "Cyan"
            Write-ColorOutput "  1. Visit: https://github.com/$GitHubUsername/$RepoName" "White"
            Write-ColorOutput "  2. Create a Pull Request if needed" "White"
            Write-ColorOutput "  3. Add repository description and topics" "White"
        } else {
            Write-ColorOutput "`n✗ Push failed. Check your authentication." "Red"
            Write-ColorOutput "`nTroubleshooting:" "Yellow"
            Write-ColorOutput "  1. Generate Personal Access Token: https://github.com/settings/tokens" "White"
            Write-ColorOutput "  2. Use token as password when prompted" "White"
            Write-ColorOutput "  3. Or set up SSH keys: https://docs.github.com/en/authentication" "White"
        }
    } else {
        Write-ColorOutput "`nPush cancelled. Run manually later:" "Yellow"
        Write-ColorOutput "  git push -u origin $BranchName" "White"
    }
} else {
    Write-ColorOutput "`n[8/8] Push skipped (use -SkipPush flag)" "Yellow"
    Write-ColorOutput "`nTo push manually:" "Cyan"
    Write-ColorOutput "  git push -u origin $BranchName" "White"
}

Write-ColorOutput "`n========================================" "Cyan"
Write-ColorOutput "Setup Complete!" "Cyan"
Write-ColorOutput "========================================`n" "Cyan"

Write-ColorOutput "Summary:" "Green"
Write-ColorOutput "  Repository: $RepoName" "White"
Write-ColorOutput "  Branch: $BranchName" "White"
Write-ColorOutput "  Remote: $remoteUrl" "White"

Write-ColorOutput "`nUseful commands:" "Yellow"
Write-ColorOutput "  git status          - Check current status" "White"
Write-ColorOutput "  git log --oneline   - View commit history" "White"
Write-ColorOutput "  git branch -a       - List all branches" "White"
Write-ColorOutput "  git remote -v       - View remotes" "White"
