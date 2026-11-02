import 'package:flutter/services.dart';

class NativeHost {
  static const channel = MethodChannel('space.lopixel.pvp/host');
  Future<T?> invoke<T>(String method, [dynamic arguments]) async {
    try {
      return await channel.invokeMethod<T>(method, arguments);
    } on MissingPluginException {
      return null;
    }
  }

  void onAction(Future<void> Function(String, Map<String, dynamic>) handler) {
    channel.setMethodCallHandler((call) async {
      await handler(
        call.method,
        Map<String, dynamic>.from(call.arguments as Map? ?? {}),
      );
    });
  }

  Future<String?> readSession(String origin) =>
      invoke<String>('readSession', origin);
  Future<void> saveSession(String origin, String? session) =>
      invoke('saveSession', {'origin': origin, 'session': session});
  Future<String?> readPreferences(String key) =>
      invoke<String>('readPreferences', key);
  Future<void> savePreferences(String key, String value) =>
      invoke('savePreferences', {'key': key, 'value': value});
}
