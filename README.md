# 🚀 大力VPN

> 基于 [Bettbox](https://github.com/appshubcc/Bettbox) 修改的 Android VPN 客户端
> 内嵌订阅地址，首次启动自动加载节点

## ✨ 特点

- **即开即用** - 安装后打开，自动加载订阅节点，无需手动配置
- **多协议支持** - VLESS Reality、VLESS WebSocket、XHTTP、gRPC 等
- **基于 Mihomo 内核** - 性能强劲，兼容 Clash Meta 生态
- **开源免费** - 基于 MIT 开源协议

## 📦 快速开始

### 方法一：直接下载编译好的 APK（推荐）

1. 在 [GitHub Releases](https://github.com/你的用户名/你的仓库名/releases) 页面下载最新 APK
2. 手机安装 APK
3. 打开 APP → 自动加载 62+ 条节点 → 点击"连接"即可使用

### 方法二：自己用 GitHub Actions 编译

1. Fork（或创建）本仓库到你的 GitHub
2. 打标签触发构建：
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
3. 或者手动触发：Actions → 构建大力VPN → Run workflow
4. 等待构建完成（约 20-30 分钟）
5. 在 Release 页面下载 APK

### 方法三：本地编译（需要 Android 开发环境）

```bash
# 1. 克隆 Bettbox
git clone https://github.com/appshubcc/Bettbox.git
cd Bettbox

# 2. 应用大力VPN补丁
bash ../scripts/patch-source.sh

# 3. 编译
flutter pub get
dart run build_runner build -d
dart setup.dart android --arch arm64

# 4. APK 在 ./dist/ 目录
```

## 📱 下载哪个 APK？

| 文件 | 适用设备 |
|------|---------|
| `大力VPN-android-arm64.apk` | **大多数现代手机** (推荐) |
| `大力VPN-android-arm.apk` | 老旧 32 位设备 |
| `大力VPN-android-amd64.apk` | 平板、模拟器 |
| `大力VPN-android-universal.apk` | 全架构兼容（包较大） |

## 🔧 自定义修改

### 修改订阅地址

在 `lib/common/constant.dart` 中找到：
```dart
const daliVpnDefaultSubscriptionUrl = '你的订阅地址';
```
替换为你自己的订阅链接即可。

### 修改应用名称

在 `android/app/src/main/AndroidManifest.xml` 中找到：
```xml
android:label="大力VPN"
```
替换为你想显示的名称。

## 📄 许可证

基于 [Bettbox](https://github.com/appshubcc/Bettbox) 项目修改，遵循原项目许可证。
