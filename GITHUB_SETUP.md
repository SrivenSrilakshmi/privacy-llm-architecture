# GitHub Branch Push Guide

## Quick Setup (Copy & Paste Commands)

### Option 1: New Repository

```powershell
# Navigate to project
cd C:\privacy-llm-architecture

# Initialize Git (if not already done)
git init

# Create .gitignore
echo "__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.so
*.egg
*.egg-info/
dist/
build/
.venv/
venv/
ENV/
.env
.idea/
.vscode/
*.log" > .gitignore

# Create and switch to feature branch
git checkout -b feature/privacy-llm-architecture

# Add all files
git add .

# Commit
git commit -m "feat: Privacy-preserving LLM architecture with ZKP and selective encryption

- Implement skeleton framework with pluggable branches
- Add PII detectors (regex, transformer, hybrid)
- Add protection policies (minimal, contextual, compliance)
- Add encryption schemes (ChaCha20, AES-GCM)
- Add ZKP systems (Schnorr, mock)
- Complete end-to-end demos and tests
- GDPR/HIPAA/PCI-DSS compliance support"

# Connect to GitHub (replace YOUR_USERNAME and YOUR_REPO)
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git

# Push branch to GitHub
git push -u origin feature/privacy-llm-architecture
```

### Option 2: Existing Repository

```powershell
# Navigate to project
cd C:\privacy-llm-architecture

# Create and switch to feature branch
git checkout -b feature/privacy-llm-architecture

# Add all files
git add .

# Commit
git commit -m "feat: Privacy-preserving LLM architecture with ZKP and selective encryption"

# Push branch
git push -u origin feature/privacy-llm-architecture
```

---

## Step-by-Step Instructions

### 1. Create GitHub Repository (if needed)

Go to https://github.com/new and create a new repository:
- Repository name: `privacy-llm-architecture`
- Description: `Privacy-preserving LLM interaction architecture with selective encryption and zero-knowledge proofs`
- Visibility: Public or Private
- **DO NOT** initialize with README (we already have one)

### 2. Initialize Local Repository

```powershell
cd C:\privacy-llm-architecture
git init
```

### 3. Create .gitignore

```powershell
# Create .gitignore file
@"
# Python
__pycache__/
*.py[cod]
*$py.class
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
*.egg-info/
.installed.cfg

# Virtual Environment
venv/
ENV/
env/
.venv/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Logs
*.log

# Environment
.env
.env.local

# Testing
.pytest_cache/
.coverage
htmlcov/
"@ | Out-File -FilePath .gitignore -Encoding utf8
```

### 4. Create Feature Branch

```powershell
# Create and switch to new branch
git checkout -b feature/privacy-llm-architecture

# OR use different branch naming conventions:
# git checkout -b dev/privacy-architecture
# git checkout -b implement/zkp-selective-encryption
# git checkout -b release/v1.0
```

### 5. Stage All Files

```powershell
# Add all files
git add .

# Verify what will be committed
git status
```

### 6. Commit Changes

```powershell
git commit -m "feat: Privacy-preserving LLM architecture with ZKP and selective encryption

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
- Cryptographic trust boundaries"
```

### 7. Connect to GitHub Remote

```powershell
# Add remote (replace with your actual GitHub URL)
git remote add origin https://github.com/YOUR_USERNAME/privacy-llm-architecture.git

# Verify remote
git remote -v
```

### 8. Push to GitHub

```powershell
# Push branch to GitHub
git push -u origin feature/privacy-llm-architecture

# If you get authentication errors, you may need to use a Personal Access Token
# Generate one at: https://github.com/settings/tokens
```

### 9. Create Pull Request (Optional)

After pushing, go to your GitHub repository and you'll see a prompt to create a Pull Request.

Or manually:
1. Go to: `https://github.com/YOUR_USERNAME/YOUR_REPO/pulls`
2. Click "New Pull Request"
3. Select your feature branch
4. Add description and create PR

---

## Branch Naming Conventions

Choose a convention that fits your workflow:

```powershell
# Feature branches
git checkout -b feature/privacy-llm-architecture
git checkout -b feat/zkp-implementation

# Development branches
git checkout -b dev/selective-encryption
git checkout -b develop

# Release branches
git checkout -b release/v1.0.0
git checkout -b release/production

# Hotfix branches
git checkout -b hotfix/security-patch
git checkout -b fix/encryption-bug

# Research/experimental
git checkout -b research/zkp-optimization
git checkout -b experiment/new-detector
```

---

## Automated Script

Run the script below to automate the entire process:

```powershell
# Run: .\setup-github.ps1
```

(See setup-github.ps1 file)

---

## Troubleshooting

### Authentication Issues

If you get authentication errors:

**Option 1: Personal Access Token**
```powershell
# Generate token at: https://github.com/settings/tokens
# Use token as password when prompted
git push -u origin feature/privacy-llm-architecture
```

**Option 2: SSH Keys**
```powershell
# Generate SSH key
ssh-keygen -t ed25519 -C "your_email@example.com"

# Add to GitHub: https://github.com/settings/keys
# Change remote to SSH
git remote set-url origin git@github.com:YOUR_USERNAME/YOUR_REPO.git
git push -u origin feature/privacy-llm-architecture
```

### Large Files

If you have large files:
```powershell
# Install Git LFS
git lfs install

# Track large files
git lfs track "*.model"
git lfs track "*.bin"

# Add .gitattributes
git add .gitattributes
git commit -m "Add Git LFS tracking"
```

### Undo Last Commit (before push)

```powershell
# Undo commit but keep changes
git reset --soft HEAD~1

# Undo commit and discard changes
git reset --hard HEAD~1
```

---

## Next Steps After Push

1. **Add Repository Description** on GitHub
2. **Add Topics/Tags**: `privacy`, `llm`, `cryptography`, `zero-knowledge-proofs`, `gdpr`, `hipaa`
3. **Enable GitHub Pages** (for documentation)
4. **Add Status Badges** to README
5. **Set up CI/CD** (GitHub Actions)
6. **Add License** (MIT, Apache 2.0, etc.)
7. **Create Release** with version tag

---

## GitHub Actions CI (Optional)

Create `.github/workflows/test.yml` for automated testing:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - run: pip install -r requirements.txt
      - run: python tests/integration_test.py
```
