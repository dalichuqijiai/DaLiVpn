#!/bin/bash
# =============================================================================
# 大力VPN - Bettbox 源码补丁脚本
# 用法: cd Bettbox源码目录 && bash /path/to/patch-source.sh
# =============================================================================

set -e

echo "========================================"
echo "  大力VPN - 开始打补丁"
echo "========================================"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(pwd)"

# 检查是否在 Bettbox 源码目录
if [ ! -f "pubspec.yaml" ] || ! grep -q "bett_box" pubspec.yaml; then
  echo "❌ 错误: 请在 Bettbox 源码根目录运行此脚本"
  echo "   用法: cd Bettbox && bash $0"
  exit 1
fi

# ============================================
# 1. 修改项目名称和描述
# ============================================
echo ""
echo "[1/7] 修改项目名称 → dali_vpn"
sed -i 's/^name: bett_box/name: dali_vpn/' pubspec.yaml
sed -i 's/description:.*/description: 大力VPN - 安全稳定的网络加速工具/' pubspec.yaml
echo "  ✅ pubspec.yaml 已修改"

# ============================================
# 2. Android 显示名称
# ============================================
echo "[2/7] 修改 Android 显示名称 → 大力VPN"
sed -i 's|android:label="Bettbox"|android:label="大力VPN"|g' android/app/src/main/AndroidManifest.xml
echo "  ✅ AndroidManifest.xml 已修改"

# ============================================
# 3. 修改包名
# ============================================
echo "[3/7] 修改包名 → com.dalivpn.app"
find . -type f \( -name "*.kt" -o -name "*.kts" -o -name "*.xml" -o -name "*.pro" -o -name "*.dart" \) \
  -not -path "./.git/*" -not -path "*/build/*" -not -path "*/.dart_tool/*" \
  -exec sed -i 's/com\.appshub\.bettbox/com.dalivpn.app/g' {} +

# Kotlin 源码目录迁移
if [ -d "android/app/src/main/kotlin/com/appshub/bettbox" ]; then
  mkdir -p android/app/src/main/kotlin/com/dalivpn/app
  cp -r android/app/src/main/kotlin/com/appshub/bettbox/* android/app/src/main/kotlin/com/dalivpn/app/
  rm -rf android/app/src/main/kotlin/com/appshub
fi

# 更新 package 声明
find android/app/src/main/kotlin -name "*.kt" -exec sed -i 's/package com\.appshub\.bettbox/package com.dalivpn.app/' {} +
echo "  ✅ 包名已修改"

# ============================================
# 4. Dart import 路径修正
# ============================================
echo "[4/7] 修正 Dart import 路径"
find . -type f -name "*.dart" -path "*/lib/*" -exec sed -i 's/package:bett_box\//package:dali_vpn\//g' {} +
echo "  ✅ import 路径已修正"

# ============================================
# 5. 嵌入订阅地址常量
# ============================================
echo "[5/7] 嵌入默认订阅地址"
cat >> lib/common/constant.dart << 'CONSTEOF'

/// 大力VPN - 默认订阅地址
const daliVpnDefaultSubscriptionUrl = 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt';
CONSTEOF
echo "  ✅ 订阅地址常量已添加"

# ============================================
# 6. 创建自动加载订阅模块
# ============================================
echo "[6/7] 注入首次启动自动加载逻辑"
cat > lib/common/auto_subscription.dart << 'DARTEOF'
import 'package:dali_vpn/common/constant.dart';
import 'package:dali_vpn/common/common.dart';
import 'package:dali_vpn/models/models.dart';
import 'package:dali_vpn/manager/manager.dart';

/// 首次启动自动添加默认订阅
Future<void> autoLoadDefaultSubscription() async {
  final profiles = globalState.config.profiles;
  if (profiles.isNotEmpty) {
    commonPrint.log('大力VPN: 已有订阅，跳过自动加载');
    return;
  }

  final url = daliVpnDefaultSubscriptionUrl;
  if (url.isEmpty) return;

  commonPrint.log('大力VPN: 首次启动，自动添加默认订阅...');

  final profile = Profile.normal(
    url: url,
    label: '大力VPN订阅',
    autoUpdate: true,
  );

  await globalState.appController.addProfile(profile);
  await globalState.appController.updateProfile(profile);
  commonPrint.log('大力VPN: 默认订阅已添加');
}
DARTEOF

# 在 controller.dart 的 init() 方法中插入调用
if grep -q "autoUpdateProfiles" lib/controller.dart; then
  sed -i 's/autoUpdateProfiles();/await autoLoadDefaultSubscription();\n    autoUpdateProfiles();/' lib/controller.dart
  # 添加 import
  if ! grep -q "auto_subscription.dart" lib/controller.dart; then
    sed -i 's/^import.*\/\/.*$/import "package:dali_vpn\/common\/auto_subscription.dart";\n&/' lib/controller.dart
  fi
  echo "  ✅ 自动加载逻辑已注入 controller.dart"
else
  echo "  ⚠️ 未找到 autoUpdateProfiles() 调用点，请手动检查"
fi

# ============================================
# 7. 验证
# ============================================
echo "[7/7] 验证修改结果"
echo ""
echo "  📋 关键修改检查:"
grep -q "dali_vpn" pubspec.yaml && echo "    ✅ pubspec.yaml name"
grep -q "大力VPN" android/app/src/main/AndroidManifest.xml && echo "    ✅ app label"
grep -q "com.dalivpn.app" android/app/build.gradle.kts && echo "    ✅ package name"
grep -q "daliVpnDefaultSubscriptionUrl" lib/common/constant.dart && echo "    ✅ subscription URL"
grep -q "autoLoadDefaultSubscription" lib/controller.dart && echo "    ✅ auto-load injected"
grep -q "dali_vpn" lib/common/constant.dart && echo "    ✅ repository updated"

echo ""
echo "========================================"
echo "  🎉 大力VPN 补丁应用完成！"
echo "========================================"
echo ""
echo "下一步:"
echo "  flutter pub get"
echo "  dart run build_runner build -d"
echo "  dart setup.dart android --arch arm64"
echo "  # APK 文件在 ./dist/ 目录"
echo ""
