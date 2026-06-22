import 'package:dali_vpn/common/constant.dart';
import 'package:dali_vpn/common/common.dart';
import 'package:dali_vpn/models/models.dart';
import 'package:dali_vpn/models/profile.dart';
import 'package:dali_vpn/state.dart';

/// 首次启动自动添加默认订阅
Future<void> autoLoadDefaultSubscription() async {
  final profiles = globalState.config.profiles;
  if (profiles.isNotEmpty) {
    return;
  }

  final url = daliVpnDefaultSubscriptionUrl;
  if (url.isEmpty) return;

  commonPrint.log('大力VPN: 首次启动，自动添加默认订阅...');

  final profile = Profile.normal(
    url: url,
    label: '大力VPN订阅',
  );

  await globalState.appController.addProfile(profile);
  await globalState.appController.updateProfile(profile);
  commonPrint.log('大力VPN: 默认订阅已添加并开始更新');
}
