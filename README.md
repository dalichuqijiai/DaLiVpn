# 🚀 大力VPN

> 基于 [Bettbox](https://github.com/appshubcc/Bettbox) (Mihomo/Clash Meta 内核) 修改的 Android VPN 客户端
> 内嵌订阅地址，首次启动自动加载节点，**60 个精选低延迟节点**

## ✨ 特点

- **即开即用** - 安装后打开，自动加载订阅节点，无需手动配置
- **60 个精选节点** - 从 3 个订阅源合并，云端 TLS 握手 + WebSocket 深度测速后选取延迟最低的 60 个
- **自动选择最快节点** - 内置 `Auto` (url-test) 组，启动后自动切到延迟最低的节点
- **每 6 小时自动刷新** - GitHub Actions 定时合并订阅源 + 测速 + 选优
- **多协议支持** - VLESS (Reality / WebSocket / gRPC) / Trojan / VMess
- **基于 Mihomo 内核** - 性能强劲，兼容 Clash Meta 生态
- **开源免费** - 基于 MIT 开源协议

## 📦 快速开始

### 方法一：直接下载编译好的 APK（推荐）⬇️

👉 **在 [GitHub Releases](https://github.com/dalichuqijiai/DaLiVpn/releases/latest) 页面下载最新 APK**

1. 点击上方链接进入 Releases 页面
2. 下载 `大力VPN-arm64-v8a.apk`（大多数现代手机适用）
3. 手机安装 APK（**安装前请关闭 Google Play Protect**，防止误报卸载）
4. 打开 APP → 自动加载 60 个节点 → 点击"连接"即可使用

> 💡 首次启动需联网拉取订阅（约 2-5 秒），请确保网络畅通。

### 方法二：自己用 GitHub Actions 编译

1. 打标签触发构建：
   ```bash
   git tag v1.x.0
   git push origin v1.x.0
   ```
2. 或手动触发：Actions → 构建大力VPN → Run workflow
3. 等待构建完成（约 13 分钟）
4. 在 [Releases](https://github.com/dalichuqijiai/DaLiVpn/releases) 页面下载 APK

### 方法三：本地编译（需要 Flutter + Android SDK + Go 环境）

```bash
# 1. 克隆本仓库
git clone https://github.com/dalichuqijiai/DaLiVpn.git
cd DaLiVpn

# 2. 克隆 Bettbox 并应用补丁
git clone --depth 1 https://github.com/appshubcc/Bettbox.git bettbox-src
# 用 bettbox-patches/ 覆盖上游 buggy 文件
for f in bettbox-patches/*.dart; do
  # 文件名映射见 .github/workflows/build-apk.yaml 的 patch 步骤
  cp "$f" "bettbox-src/lib/..."
done

# 3. 编译 arm64 APK
cd bettbox-src
flutter pub get
dart run build_runner build --delete-conflicting-outputs -d
dart setup.dart android --arch arm64

# 4. APK 在 build/app/outputs/flutter-apk/ 目录
```

## 📱 下载哪个 APK？

| 文件 | 适用设备 |
|------|---------|
| **`大力VPN-arm64-v8a.apk`** | **大多数现代手机（推荐）** |
| `大力VPN-armeabi-v7a.apk` | 老旧 32 位设备 |
| `大力VPN-x86_64.apk` | 平板、模拟器 |
| `大力VPN-universal.apk` | 全架构兼容（包较大） |

## 🔧 自定义修改

### 修改订阅地址

订阅地址写死在 `bettbox-src/lib/common/auto_sub.dart`：
```dart
const url = 'https://cdn.jsdelivr.net/gh/dalichuqijiai/DaLiVpn@main/assets/data/dali_config.yaml';
```
替换为你自己的订阅链接即可。

### 修改应用名称

在 `bettbox-src/android/app/src/main/AndroidManifest.xml` 中找到：
```xml
android:label="大力VPN"
```

### 节点池更新机制

- **`assets/data/dali_config.yaml`** - 经过测速的 60 节点配置（App 启动时拉取）
- **`.github/workflows/update-subs.yaml`** - 每 6 小时定时合并 3 个订阅源 + 深度测速 + 选优
- **`scripts/update_subs.rb`** - 节点转换 + TLS 握手测速的核心逻辑

## 📄 许可证

基于 [Bettbox](https://github.com/appshubcc/Bettbox) 项目修改，遵循原项目许可证。
