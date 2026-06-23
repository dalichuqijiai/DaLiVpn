import 'package:bett_box/common/common.dart';
import 'package:bett_box/models/models.dart';
import 'package:bett_box/state.dart';

/// 添加订阅并强制刷新配置
Future<void> loadSub() async {
  if (globalState.config.profiles.isNotEmpty) return;
  try {
    const url = 'https://raw.githubusercontent.com/dalichuqijiai/DaLiVpn/main/assets/data/dali_config.yaml';
    final p = Profile(
      id: 'dali_main',
      url: url,
      label: '大力VPN',
      autoUpdateDuration: Duration(hours: 6),
      autoUpdate: true,
    );
    await globalState.appController.addProfile(p);
    await globalState.appController.updateProfile(p);
    commonPrint.log('大力VPN: 订阅已加载');
  } catch (e) {
    commonPrint.log('大力VPN: 订阅加载失败: $e');
  }
}
