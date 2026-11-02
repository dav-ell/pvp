import 'dart:typed_data';
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
    'native plus five browsers: encrypted group reception and native opaque forwarding',
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
        captureOverride: (_) =>
            createLocalMediaStream('native-group-empty-capture'),
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
      await until(() => c.group.available, 'server advertises group support');
      final peers = (await command('peers'))['peers'] as List;
      for (final peer in peers) {
        await c.addFriend(peer['username']);
      }
      await command('accept-requests');
      await c.refresh();
      const recurring = bool.fromEnvironment('PVP_TEST_MEETINGS');
      String? meetingId;
      if (recurring) {
        await until(
          () => c.meetingsAvailable,
          'server advertises recurring meetings',
        );
        await c.host.invoke('show');
        final created = await c.api.request(
          '/meetings',
          method: 'POST',
          data: {
            'name': 'Weekly native meeting',
            'peer_ids': <String>[],
            'open_invite': true,
          },
        );
        meetingId = created['meeting_id'] as String;
        expect(
          groupMedia.stream,
          isNull,
          reason: 'creating a recurring meeting does not capture',
        );
        await c.refreshMeetings();
        debugPrint('Native-created recurring meeting ready');
        final link =
            'pvp://meeting/$meetingId?origin=${Uri.encodeComponent(Uri.parse(service).origin)}';
        await command('native-link?url=${Uri.encodeComponent(link)}');
        await until(
          () => find.text('Join meeting').evaluate().isNotEmpty,
          'macOS URL opens the real native preview',
        );
        expect(
          groupMedia.stream,
          isNull,
          reason: 'deep link opens preview without capture',
        );
        final join = find.text('Join meeting');
        await tester.ensureVisible(join);
        await tester.tap(join);
        await until(
          () => c.group.room != null,
          'native entered persistent meeting',
        );
        debugPrint('Native recurring meeting joined; joining browsers');
        await command('join-meeting?id=$meetingId');
      } else {
        await c.group.start(peers.map((p) => p['id'] as String).toList());
        await command('join');
      }
      await until(
        () => c.group.participants.length == 6,
        'six participants admitted',
      );
      await until(
        () =>
            c.group.links.length == 5 &&
            c.group.links.values.every((l) => l.renderer.videoWidth > 0),
        'native receives five real browser video streams',
      );
      // The real engine may adapt decoded size under local CPU/load. Keep the
      // strict resolution check available for dedicated performance runs;
      // quality-policy tests separately enforce the configured 480p baseline.
      if (const bool.fromEnvironment('PVP_TEST_STRICT_RESOLUTION')) {
        await until(
          () =>
              c.group.links.values.every((l) => l.renderer.videoHeight >= 480),
          'native decodes all five browser cameras at 480p or better',
        );
      }
      debugPrint(
        'Native decoded sizes: ${c.group.links.values.map((l) => '${l.renderer.videoWidth}x${l.renderer.videoHeight}').join(', ')}',
      );
      await until(
        () => c.group.links.values.every((l) => l.evidence?.direct == true),
        'every native peer link has a selected direct route',
      );
      await until(
        () => c.group.links.values.every(
          (l) => l.bandwidthSupported && l.meter.rate != null,
        ),
        'all native group links report live bandwidth and receive-limit support',
      );
      final limitedLink = c.group.links[peers[0]['id']]!;
      limitedLink.caps.receive.camera = 64;
      await c.group.updateBandwidth();
      await command('verify-bandwidth?kbps=64');
      limitedLink.caps.receive.screen = 4000;
      await c.group.updateBandwidth();
      await command('verify-bandwidth?kbps=64');
      limitedLink.caps.receive.camera = null;
      limitedLink.caps.receive.screen = null;
      await c.group.updateBandwidth();
      await command('verify-bandwidth?kbps=0');
      for (final link in c.group.links.values) {
        final stats = await link.pc.getStats();
        expect(
          stats.any(
            (s) =>
                s.type == 'transport' &&
                s.values['dtlsState'] == 'connected' &&
                s.values['dtlsCipher'] != null &&
                s.values['srtpCipher'] != null,
          ),
          true,
        );
        expect(
          stats.any(
            (s) =>
                s.type == 'inbound-rtp' &&
                s.values['kind'] == 'audio' &&
                (s.values['bytesReceived'] as num? ?? 0) > 0,
          ),
          true,
        );
      }
      debugPrint('Native group encrypted media verified');
      await until(
        () => c.group.chat.ready.length == 5,
        'all native/browser chat channels ready',
      );
      await command('chat-send-browser');
      await until(
        () =>
            c.group.chat.items.any((i) => i.text == 'Browser → native chat 🌍'),
        'native receives browser chat',
      );
      await until(
        () => c.group.chat.items.any((i) => i.name == 'browser-native.bin'),
        'native receives file offer',
      );
      final browserFile = c.group.chat.items.firstWhere(
        (i) => i.name == 'browser-native.bin',
      );
      expect(
        browserFile.bytes,
        isNull,
        reason: 'file does not transfer before acceptance',
      );
      c.group.chat.accept(browserFile);
      await until(
        () => browserFile.bytes != null,
        'native receives complete chunked file',
      );
      expect(
        browserFile.bytes,
        orderedEquals(List.generate(70000, (i) => i % 256)),
      );
      await until(
        () => c.group.chat.items.any((i) => i.name == 'browser-native.png'),
        'native receives image offer',
      );
      final browserImage = c.group.chat.items.firstWhere(
        (i) => i.name == 'browser-native.png',
      );
      c.group.chat.accept(browserImage);
      await until(
        () => browserImage.bytes != null,
        'native receives accepted image',
      );
      c.group.chat.text('Native → browser chat 🌍');
      c.group.chat.offer(
        'native-browser.bin',
        Uint8List.fromList(List.generate(70000, (i) => (255 - i) % 256)),
      );
      await command('chat-receive-native');
      debugPrint('Bidirectional native/browser text and binary chat verified');
      await tester.tap(find.byTooltip('Chat'));
      await render(const Duration(milliseconds: 100));
      expect(find.text('Chat'), findsOneWidget);
      expect(
        find.byType(Image),
        findsWidgets,
        reason: 'native image preview renders',
      );
      // Opening chat scrolls to the newest item; the first text may be virtualized.
      tester.widget<ListView>(find.byType(ListView).last).controller!.jumpTo(0);
      await render(const Duration(milliseconds: 100));
      expect(find.text('Browser → native chat 🌍'), findsOneWidget);
      await tester.tap(find.byTooltip('Close chat'));
      await render(const Duration(milliseconds: 100));

      // Choose a browser source whose tree places native as the first forwarder.
      final ids = c.group.participants.map((m) => m['id'] as String).toList()
        ..sort();
      final nativeIndex = ids.indexOf(c.user!.id),
          source = ids[(nativeIndex - 1 + ids.length) % ids.length];
      final path = c.group.tree(source), leaf = path[5];
      expect(path[1], c.user!.id);
      await command('verify-forwarded?source=$source&leaf=$leaf');
      await until(
        () => c.group.links.values.any((l) => l.forwardedBytes > 0),
        'native forwards encrypted browser video to a second-hop leaf',
      );
      expect(
        find.text(recurring ? 'Weekly native meeting' : 'Group call'),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
      if (recurring) {
        await c.host.invoke('show');
        debugPrint('Starting native owner admin UI test');
        await tester.tap(find.byTooltip('People'));
        await render(const Duration(milliseconds: 100));
        await until(
          () => find
              .descendant(
                of: find.byType(Dialog),
                matching: find.byTooltip('Manage Browser 0'),
              )
              .evaluate()
              .isNotEmpty,
          'native member admin actions',
        );
        final manage = find.descendant(
          of: find.byType(Dialog),
          matching: find.byTooltip('Manage Browser 0'),
        );
        await tester.ensureVisible(manage);
        await render(const Duration(milliseconds: 100));
        await tester.tap(manage);
        await render(const Duration(milliseconds: 100));
        await tester.tap(find.text('Make admin'));
        await until(
          () => c.group.participants.any(
            (m) => m['id'] == peers[0]['id'] && m['is_admin'] == true,
          ),
          'native owner appointed browser admin',
        );
        await tester.tap(find.byTooltip('Back to call'));
        await render(const Duration(milliseconds: 100));
        debugPrint('Native owner appointed browser admin');
        await command('moderate?actor=0&target=1&action=mute');
        final targetId = peers[1]['id'] as String;
        await until(
          () =>
              c.group.links[targetId]?.remote?.getAudioTracks().every(
                (t) => !t.enabled,
              ) ==
              true,
          'native receiver blocks admin-muted browser audio',
        );
        // The platform setter is asynchronous. Observe the native receiver,
        // rather than assuming the Dart track's immediate cached flag is proof.
        bool engineBlocked = false;
        final receiverDeadline = DateTime.now().add(
          const Duration(seconds: 10),
        );
        while (DateTime.now().isBefore(receiverDeadline)) {
          final nativeReceivers = await c.group.links[targetId]!.pc
              .getReceivers();
          final audio = nativeReceivers
              .where((r) => r.track?.kind == 'audio')
              .toList();
          engineBlocked =
              audio.isNotEmpty && audio.every((r) => r.track?.enabled == false);
          if (engineBlocked) {
            break;
          }
          await Future<void>.delayed(const Duration(milliseconds: 50));
        }
        expect(
          engineBlocked,
          true,
          reason:
              'native engine confirms receiving audio disabled, independently of cached stream state',
        );
        await command('moderate?actor=0&target=1&action=allow');
        await until(
          () =>
              c.group.links[targetId]?.remote?.getAudioTracks().every(
                (t) => t.enabled,
              ) ==
              true,
          'native receiver permits audio after allow-unmute',
        );
      }
      await command('leave');
      await c.group.leave();
      expect(
        c.group.chat.items,
        isEmpty,
        reason: 'meeting chat clears on leaving',
      );
      expect(c.group.links, isEmpty);
      expect(c.group.media.stream, isNull);
      if (recurring) {
        await c.group.startMeeting(meetingId!);
        await until(
          () => c.group.room != null,
          'same permanent link reopens after all leave',
        );
        expect(c.group.room!['meeting_id'], meetingId);
        await c.group.leave();
        debugPrint('Starting browser owner / native target test');
        final pair = await command(
          'native-target-meeting?native=${c.user!.id}',
        );
        final pairId = pair['meeting_id'] as String;
        await c.group.startMeeting(pairId);
        await until(
          () => c.group.room != null,
          'native joins browser-owned recurring meeting',
        );
        await command('pair-join?meeting=$pairId');
        debugPrint('Browser owner joined native target');
        await until(
          () => c.group.participants.length == 2,
          'native and browser pair joined',
        );
        await command(
          'pair-mute?meeting=$pairId&native=${c.user!.id}&muted=true',
        );
        await until(
          () => c.group.moderatorMuted && c.group.media.muted,
          'browser admin muted native client',
        );
        c.group.toggleMic();
        expect(c.group.media.muted, true);
        await render();
        expect(find.text('Muted by admin'), findsOneWidget);
        await command(
          'pair-mute?meeting=$pairId&native=${c.user!.id}&muted=false',
        );
        await until(
          () => !c.group.moderatorMuted,
          'browser admin allows native unmute',
        );
        expect(
          c.group.media.muted,
          true,
          reason: 'admin cannot turn on native microphone',
        );
        c.group.toggleMic();
        expect(c.group.media.muted, false);
        await command('pair-kick?meeting=$pairId&native=${c.user!.id}');
        await until(
          () => !c.group.busy,
          'browser admin kicked native participant',
        );
        expect(c.group.media.stream, isNull);
        await expectLater(c.api.request('/meetings/$pairId'), throwsException);
      }
      await c.signOut();
      await tester.pumpWidget(const SizedBox.shrink());
      c.group.dispose();
      c.dispose();
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );
}
