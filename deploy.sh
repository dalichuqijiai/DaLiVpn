#!/bin/bash
# ============================================================
# 大力VPN - 一键部署到 GitHub 并触发编译
# 使用方法:
#   1. 先登录 GitHub
#   2. 运行: bash deploy.sh
# ============================================================

set -e

GITHUB_USER="dalichuqijiai"
REPO_NAME="DaLiVpn"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "========================================"
echo "  大力VPN - 一键部署到 GitHub"
echo "========================================"
echo ""
echo "用户名: $GITHUB_USER"
echo "仓库名: $REPO_NAME"
echo ""

# 检查 gh 或 git
if command -v gh &>/dev/null; then
  echo "使用 GitHub CLI 创建仓库..."
  gh repo create "$REPO_NAME" --public --description "大力VPN - 基于 Bettbox 的 Android VPN 客户端" || true
  cd "$PROJECT_DIR"
  git init
  git add .
  git commit -m "🎉 大力VPN 初始提交"
  git branch -M main
  
  # 检查是否有 remote，没有则添加
  git remote add origin "https://github.com/$GITHUB_USER/$REPO_NAME.git" 2>/dev/null || \
    git remote set-url origin "https://github.com/$GITHUB_USER/$REPO_NAME.git"
  
  git push -u origin main
  echo ""
  echo "✅ 已推送到 GitHub !"
  echo ""
  
  # 打标签触发编译
  echo "是否现在打标签触发 APK 编译？[y/N]"
  read -r answer
  if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
    git tag v1.0.0
    git push origin v1.0.0
    echo ""
    echo "✅ 标签已推送，GitHub Actions 正在编译..."
    echo "   查看进度: https://github.com/$GITHUB_USER/$REPO_NAME/actions"
    echo "   下载 APK: https://github.com/$GITHUB_USER/$REPO_NAME/releases"
  fi
  
elif command -v git &>/dev/null; then
  echo ""
  echo "====== 手动操作步骤 ======"
  echo ""
  echo "第1步: 在 GitHub 网页上创建新仓库"
  echo "  → 打开 https://github.com/new"
  echo "  → 仓库名: $REPO_NAME"
  echo "  → 公开/私有均可"
  echo "  → 不要勾选任何初始化选项"
  echo "  → 点击 Create repository"
  echo ""
  echo "第2步: 运行以下命令（请按实际路径修改）"
  echo ""
  echo "  cd $PROJECT_DIR"
  echo "  git init"
  echo "  git add ."
  echo "  git commit -m \"🎉 大力VPN 初始提交\""
  echo "  git branch -M main"
  echo "  git remote add origin https://github.com/$GITHUB_USER/$REPO_NAME.git"
  echo "  git push -u origin main"
  echo ""
  echo "第3步: 触发 APK 编译"
  echo "  方法A（手动触发）:"
  echo "    GitHub → Actions → 构建大力VPN → Run workflow"
  echo ""
  echo "  方法B（打标签自动触发）:"
  echo "    git tag v1.0.0"
  echo "    git push origin v1.0.0"
  echo ""
  echo "第4步: 等待 20-30 分钟后下载 APK"
  echo "    https://github.com/$GITHUB_USER/$REPO_NAME/releases"
else
  echo "❌ 本机没有 git 或 gh，请先安装 git"
  echo "   macOS: brew install git"
  echo "   Ubuntu: sudo apt install git"
  echo "   Windows: https://git-scm.com/downloads"
fi
