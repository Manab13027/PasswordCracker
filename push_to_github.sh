#!/bin/bash
GITHUB_USER="Manab13027"
REPO_NAME="Utilities"

echo "Paste your GitHub Personal Access Token and press Enter:"
read -s TOKEN

git init
git add .
git commit -m "initial commit" 2>/dev/null || echo "(nothing new to commit)"
git remote remove origin 2>/dev/null
git remote add origin "https://$TOKEN@github.com/$GITHUB_USER/$REPO_NAME.git"
git branch -M main
git pull origin main --allow-unrelated-histories 2>/dev/null || true
git push -u origin main
