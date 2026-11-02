import 'dart:convert';
import 'dart:io';
import 'dart:ui' as ui;
import 'package:flutter/rendering.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:integration_test/integration_test.dart';
import 'package:pvp_desktop/core/controller.dart';
import 'package:pvp_desktop/core/group_calls.dart';
import 'package:pvp_desktop/core/media.dart';
import 'package:pvp_desktop/core/native.dart';
import 'package:pvp_desktop/ui/app.dart';

class ListenerTestHost extends NativeHost {
  @override
  Future<String?> readSession(String origin) async => null;
  @override
  Future<void> saveSession(String origin, String? session) async {}
  @override
  Future<String?> readPreferences(String key) async => null;
  @override
  Future<void> savePreferences(String key, String value) async {}
}

void main() {
  final binding = IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  binding.framePolicy = LiveTestWidgetsFlutterBindingFramePolicy.benchmarkLive;
  testWidgets(
    'native joins without capture; browser listener upgrades on the existing link',
    (tester) async {
      const service = String.fromEnvironment('PVP_SERVICE'),
          control = String.fromEnvironment('PVP_CONTROL'),
          username = String.fromEnvironment('PVP_NATIVE_USER');
      Future<Map<String, dynamic>> command(String path) async {
        final client = HttpClient();
        try {
          final response = await (await client.getUrl(
            Uri.parse('$control/$path'),
          )).close();
          final body = await utf8.decoder.bind(response).join();
          expect(response.statusCode, 200, reason: body);
          return Map<String, dynamic>.from(jsonDecode(body));
        } finally {
          client.close(force: true);
        }
      }

      Future<void> until(Future<bool> Function() fn, String reason) async {
        final end = DateTime.now().add(const Duration(seconds: 20));
        while (DateTime.now().isBefore(end)) {
          if (await fn()) return;
          binding.scheduleWarmUpFrame();
          await tester.pump(const Duration(milliseconds: 100));
          await Future<void>.delayed(const Duration(milliseconds: 100));
        }
        fail(reason);
      }

      var captureCalls = 0;
      final c = PvpController(
        host: ListenerTestHost(),
        media: CallMedia(
          captureOverride: (_) => createLocalMediaStream('listener-main'),
        ),
        groupMedia: GroupMedia(
          captureOverride: (_) {
            captureCalls++;
            return createLocalMediaStream('listener-native');
          },
        ),
        address: service,
      );
      final screenshotKey = GlobalKey();
      await tester.pumpWidget(
        RepaintBoundary(
          key: screenshotKey,
          child: PvpApp(controller: c),
        ),
      );
      await c.initialize();
      await c.authenticate(
        username,
        'native-group-passphrase-123',
        'Native listener test',
        true,
      );
      await until(() async => c.meetingsAvailable, 'meeting capability');
      final peers = (await command('peers'))['peers'] as List;
      for (final peer in peers) {
        await c.addFriend(peer['username']);
      }
      await command('accept-requests');
      await c.refresh();
      // Each browser captures only after listening, and the native receiver checks real RTP.
      for (var i = 0; i < 2; i++) {
        final pair = await command(
              'native-target-meeting?native=${c.user!.id}&actor=$i',
            ),
            id = pair['meeting_id'] as String;
        await c.group.startMeeting(id, listen: true);
        expect(captureCalls, 0);
        expect(c.group.listening, isTrue);
        await until(() async => c.group.joined, 'native admitted');
        await command('pair-join?meeting=$id&actor=$i');
        await until(
          () async => c.group.links.isNotEmpty,
          'browser link exists',
        );
        await until(() async {
          for (final link in c.group.links.values) {
            final stats = await link.pc.getStats();
            if (stats.any(
              (s) =>
                  s.type == 'inbound-rtp' &&
                  s.values['kind'] == 'audio' &&
                  (s.values['bytesReceived'] as num? ?? 0) > 100,
            )) {
              return true;
            }
          }
          return false;
        }, 'native receives audio after listener microphone upgrade');
        expect(c.group.links.length, 1);
        if (i == 0) {
          binding.scheduleWarmUpFrame();
          await tester.pump(const Duration(milliseconds: 400));
          final boundary =
              screenshotKey.currentContext!.findRenderObject()
                  as RenderRepaintBoundary;
          final image = await boundary.toImage(pixelRatio: 1);
          final png = await image.toByteData(format: ui.ImageByteFormat.png);
          final client = HttpClient();
          try {
            final request = await client.postUrl(
              Uri.parse('$control/screenshot/native-listening'),
            );
            request.headers.contentType = ContentType.binary;
            request.add(png!.buffer.asUint8List());
            final response = await request.close();
            expect(response.statusCode, 200);
            await response.drain<void>();
          } finally {
            client.close(force: true);
          }
          image.dispose();
        }
        expect(c.group.links.values.single.audioSender, isNotNull);
        expect(
          captureCalls,
          0,
          reason: 'listening never requests a microphone',
        );
        expect(c.group.media.stream!.getAudioTracks(), isEmpty);
        await command('leave');
        await c.group.leave();
      }
      await c.signOut();
      await tester.pumpWidget(const SizedBox.shrink());
      c.group.dispose();
      c.dispose();
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );
}
