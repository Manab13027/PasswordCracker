#!/bin/bash
GITHUB_USER="Manab13027"
REPO_NAME="Utilities"
TOKEN="YOUR_TOKEN"

git init
git add .
git commit -m "initial commit"
git remote remove origin 2>/dev/null
git remote add origin "https://$TOKEN@github.com/$GITHUB_USER/$REPO_NAME.git"
git branch -M main
git pull origin main --allow-unrelated-histories
git push -u origin main
