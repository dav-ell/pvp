import 'dart:async';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/media.dart';
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/core/native.dart';

class NativeCaptureMedia extends CallMedia {
  @override
  Future<void> initialize() => local.initialize();
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final routes = <String>[], captures = <Map<dynamic, dynamic>>[];
  Completer<Map<String, dynamic>>? sourceRequest;
  late Completer<void> sourcesReached;
  setUp(() {
    routes.clear();
    captures.clear();
    sourceRequest = null;
    sourcesReached = Completer<void>();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(NativeHost.channel, (call) async {
          if (call.method == 'capturePermissions') {
            expect(call.arguments, {'camera': false});
            return true;
          }
          if (call.method == 'selectAudioDevice' &&
              call.arguments['kind'] == 'audioinput') {
            routes.add(call.arguments['id']);
            return 'System default';
          }
          return null;
        });
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(const MethodChannel('FlutterWebRTC.Method'), (
          call,
        ) async {
          if (call.method == 'createVideoRenderer') return {'textureId': 1};
          if (call.method == 'getSources') {
            if (!sourcesReached.isCompleted) sourcesReached.complete();
            if (sourceRequest != null) return sourceRequest!.future;
            return {
              'sources': [
                {
                  'deviceId': 'built-in',
                  'label': 'Built-in',
                  'kind': 'audioinput',
                },
              ],
            };
          }
          if (call.method == 'getUserMedia') {
            captures.add(call.arguments['constraints']);
            return {
              'streamId': 'capture',
              'audioTracks': [
                {
                  'id': 'mic',
                  'label': 'Built-in',
                  'kind': 'audio',
                  'enabled': true,
                  'settings': {},
                },
              ],
              'videoTracks': [],
            };
          }
          return null;
        });
  });
  test(
    'saved missing input falls back before capture after explicit consent',
    () async {
      final media = NativeCaptureMedia(),
          p = Preferences(microphone: 'missing');
      await media.acquire(p);
      expect(routes, ['']);
      expect(p.microphone, '');
      expect(captures.single['audio'].containsKey('deviceId'), false);
      expect(captures.single['video'], false);
      expect(media.microphoneNotice, contains('System default'));
      await media.stop();
      await media.local.dispose();
      media.dispose();
    },
  );
  test(
    'canceling during device enumeration never starts late capture',
    () async {
      sourceRequest = Completer<Map<String, dynamic>>();
      final media = NativeCaptureMedia(),
          p = Preferences(microphone: 'missing');
      final opening = media.acquire(p);
      await sourcesReached.future;
      await media.stop();
      sourceRequest!.complete({'sources': []});
      await opening;
      expect(routes, isEmpty);
      expect(captures, isEmpty);
      expect(media.stream, null);
      await media.local.dispose();
      media.dispose();
    },
  );
}
