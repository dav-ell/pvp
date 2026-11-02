import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:integration_test/integration_test.dart';
import 'package:pvp_desktop/core/controller.dart';
import 'package:pvp_desktop/core/media.dart';
import 'package:pvp_desktop/core/group_calls.dart';
import 'package:pvp_desktop/core/native.dart';
import 'package:pvp_desktop/ui/app.dart';

class GroupTestHost extends NativeHost {
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
  // Drive widget layout without depending on an active display/vsync. The
  // native WebRTC engine, network sockets and track state remain real.
  binding.framePolicy = LiveTestWidgetsFlutterBindingFramePolicy.benchmarkLive;
  testWidgets(
    'native voice room grows with browser peers and returns to solo',
    (tester) async {
      Future<void> render([
        Duration duration = const Duration(milliseconds: 100),
      ]) async {
        binding.scheduleWarmUpFrame();
        await tester.pump(duration);
      }

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

      Future<void> until(bool Function() fn, String reason) async {
        final end = DateTime.now().add(const Duration(seconds: 45));
        while (!fn() && DateTime.now().isBefore(end)) {
          await render(const Duration(milliseconds: 100));
          await Future<void>.delayed(const Duration(milliseconds: 50));
        }
        expect(fn(), true, reason: reason);
      }

      final media = CallMedia(
        captureOverride: (_) =>
            createLocalMediaStream('native-group-empty-main'),
      );
      final groupMedia = GroupMedia(
        captureOverride: (constraints) {
          expect(constraints['video'], false);
          return createLocalMediaStream('native-voice-empty-capture');
        },
      );
      final c = PvpController(
        host: GroupTestHost(),
        media: media,
        groupMedia: groupMedia,
        address: service,
      );
      await tester.pumpWidget(PvpApp(controller: c));
      await c.initialize();
      await c.authenticate(
        username,
        'native-group-passphrase-123',
        'Native group peer',
        true,
      );
      await until(
        () => c.group.voiceAvailable,
        'server advertises group support',
      );
      final peers = (await command('peers'))['peers'] as List;
      for (final peer in peers) {
        await c.addFriend(peer['username']);
      }
      await command('accept-requests');
      await c.refresh();
      await c.group.enterVoice();
      await until(() => c.group.joined, 'native opens voice room');
      expect(c.group.room?['voice'], true);
      await command('join-voice');
      await until(
        () =>
            c.group.links.length == 2 &&
            c.group.links.values.every((l) => l.status == 'Connected'),
        'native connects directly to two browsers',
      );
      await until(
        () => c.group.links.values.every(
          (l) => l.remote?.getAudioTracks().isNotEmpty == true,
        ),
        'native receives both microphone streams',
      );
      final connections = c.group.links.values.map((l) => l.pc).toList();
      await command('enable-video');
      await until(
        () => c.group.links.values.every((l) => l.renderer.videoWidth > 0),
        'browser opt-in video reaches native without reconnecting',
      );
      expect(c.group.links.values.map((l) => l.pc).toList(), connections);
      await command('disable-video');
      await command('leave');
      await until(
        () => c.group.participants.length == 1 && c.group.links.isEmpty,
        'native room remains open alone',
      );
      await c.group.leave();
      await c.signOut();
      await tester.pumpWidget(const SizedBox.shrink());
      c.dispose();
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );
}
