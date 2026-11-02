import 'dart:async';
import 'dart:ui' as ui;
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:integration_test/integration_test.dart';
import 'package:pvp_desktop/core/controller.dart';
import 'package:pvp_desktop/core/media.dart';
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/core/native.dart';
import 'package:pvp_desktop/ui/app.dart';

// Exercise real Keychain/UserDefaults without touching a user's production session.
class TestNativeHost extends NativeHost {
  @override
  Future<String?> readSession(String origin) =>
      super.readSession('native-test:$origin');
  @override
  Future<void> saveSession(String origin, String? session) =>
      super.saveSession('native-test:$origin', session);
  @override
  Future<String?> readPreferences(String key) =>
      super.readPreferences('native-test.$key');
  @override
  Future<void> savePreferences(String key, String value) =>
      super.savePreferences('native-test.$key', value);
}

class SilentTestHost extends NativeHost {
  @override
  void onAction(Future<void> Function(String, Map<String, dynamic>) handler) {}
  @override
  Future<T?> invoke<T>(String method, [dynamic arguments]) async => null;
}

// Exercise production audio capture/routing with a controlled debug tone,
// without opening a camera or sending anyone's voice to the test peer.
class AudioOnlyMedia extends CallMedia {
  @override
  Map<String, dynamic> constraints(Preferences p, {bool camera = false}) => {
    ...super.constraints(p),
    'video': false,
  };
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  const username = String.fromEnvironment('PVP_NATIVE_USER');
  const peerName = String.fromEnvironment('PVP_PEER');
  const control = String.fromEnvironment('PVP_CONTROL');
  const password = 'native-test-passphrase-123';
  const audioTest = bool.fromEnvironment('PVP_TEST_AUDIO');
  Future<dynamic> command(String path) async {
    final client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 10);
    try {
      debugPrint('Native control: $path');
      final req = await client
          .getUrl(Uri.parse('$control/$path'))
          .timeout(const Duration(seconds: 10));
      final res = await req.close().timeout(const Duration(seconds: 45));
      final body = await res
          .transform(utf8.decoder)
          .join()
          .timeout(const Duration(seconds: 45));
      if (res.statusCode >= 400) {
        throw StateError('Control $path failed: $body');
      }
      debugPrint('Native control complete: $path');
      return jsonDecode(body);
    } finally {
      client.close();
    }
  }

  Future<void> until(
    WidgetTester tester,
    bool Function() predicate,
    String reason,
  ) async {
    debugPrint('Native waiting: $reason');
    final deadline = DateTime.now().add(const Duration(seconds: 40));
    while (!predicate() && DateTime.now().isBefore(deadline)) {
      await tester.pump(const Duration(milliseconds: 100));
    }
    expect(predicate(), isTrue, reason: reason);
    debugPrint('Native complete: $reason');
  }

  testWidgets(
    'native menu-bar lifecycle, friends, incoming and outgoing real WebRTC',
    (tester) async {
      expect(username, isNotEmpty, reason: 'Run scripts/test-native.mjs');
      final c = PvpController(
        host: TestNativeHost(),
        media: audioTest
            ? AudioOnlyMedia()
            : CallMedia(
                captureOverride: (_) => createLocalMediaStream('native-test'),
              ),
      );
      final screenshotKey = GlobalKey();
      await tester.pumpWidget(
        RepaintBoundary(
          key: screenshotKey,
          child: PvpApp(controller: c),
        ),
      );
      Future<void> screenshot(String name) async {
        await tester.pumpAndSettle();
        final boundary =
            screenshotKey.currentContext!.findRenderObject()
                as RenderRepaintBoundary;
        final image = await boundary.toImage(pixelRatio: 1.5);
        final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
        final client = HttpClient();
        try {
          final request = await client.postUrl(
            Uri.parse('$control/screenshot/$name'),
          );
          request.headers.contentType = ContentType.binary;
          request.add(bytes!.buffer.asUint8List());
          await (await request.close()).drain<void>();
        } finally {
          client.close();
          image.dispose();
        }
      }

      await c.initialize();
      await tester.pumpAndSettle();
      expect(find.text('Welcome back.'), findsOneWidget);
      await screenshot('native-sign-in');
      expect(
        await c.authenticate(username, password, 'Alex Morgan', true),
        isTrue,
        reason: c.message,
      );
      await until(
        tester,
        () => c.online,
        'Authenticated native socket connects',
      );
      expect(
        await c.host.readSession(c.api.address),
        c.api.session,
        reason: 'macOS Keychain round-trip',
      );
      expect(await c.addFriend(peerName), isTrue);
      await command('accept-request');
      await until(
        tester,
        () => c.accepted.length == 1,
        'Friend acceptance arrives live',
      );
      await c.setQuality(Quality.saver);
      if (audioTest) {
        await c.loadDevices();
        final input = c.devices.firstWhere(
          (d) =>
              d.kind == 'audioinput' &&
              d.deviceId != 'default' &&
              d.label.contains('MacBook Pro Microphone'),
        );
        await c.setDevice('audioinput', input.deviceId);
        final selected = await c.host.invoke<Map>('microphoneStatus');
        expect(
          selected?['deviceId'],
          input.deviceId,
          reason: '${c.message}; status: $selected',
        );
        expect(selected?['deviceDefault'], isFalse);
        await c.host.invoke('testAudioTone', true);
        addTearDown(() => c.host.invoke('testAudioTone', false));
      }
      expect(c.preferences.quality.videoKbps, 400);
      await screenshot('native-people');
      await screenshot('native-rooms');
      c.navigate('settings');
      await screenshot('native-settings');
      c.navigate('people');
      // A user can cancel while macOS is still resolving device permission.
      final pendingCapture = Completer<MediaStream>();
      final lateMedia = CallMedia(
        captureOverride: (_) => pendingCapture.future,
      );
      await lateMedia.initialize();
      final acquisition = lateMedia.acquire(Preferences());
      await tester.pump();
      await lateMedia.stop();
      pendingCapture.complete(await createLocalMediaStream('late-capture'));
      await acquisition;
      expect(
        lateMedia.stream,
        isNull,
        reason: 'Canceled capture never reopens camera or attaches a stream',
      );
      await c.host.invoke('hide');
      await tester.pump(const Duration(milliseconds: 300));
      final hidden = await c.host.invoke<Map>('diagnostics');
      expect(hidden?['windowVisible'], isFalse);
      expect(hidden?['menuBarPresent'], isTrue);
      expect(
        c.online,
        isTrue,
        reason: 'Hiding the window keeps signaling alive',
      );

      await command('call');
      await until(
        tester,
        () => c.phase == 'incoming',
        'Calls arrive while the native window is hidden',
      );
      expect(
        (await c.host.invoke<Map>('diagnostics'))?['windowVisible'],
        isTrue,
      );
      expect(
        c.media.stream,
        isNull,
        reason: 'Incoming ringing does not request camera/mic',
      );
      await c.answer();
      expect(
        c.message,
        isEmpty,
        reason:
            'Answer must acquire a working microphone; permissions: ${await c.host.invoke<Map>('capturePermissionStatus')}',
      );
      await until(
        tester,
        () => c.phase == 'connected',
        'Browser-to-native WebRTC connects',
      );
      await until(
        tester,
        () => c.media.remote.videoWidth > 0,
        'Native video renderer receives real browser video',
      );
      await until(
        tester,
        () => c.media.evidence?.direct == true,
        'Native inspector observes the selected direct media path',
      );
      await until(
        tester,
        () => c.media.bandwidthSupported,
        'Browser supports native receive limits',
      );
      await until(
        tester,
        () => c.media.bandwidthMeter.rate != null,
        'Native reports live upload/download bandwidth',
      );
      c.media.connectionCaps.receive.camera = 64;
      await c.media.updateBandwidth(c.preferences.quality);
      await command('verify-bandwidth-low');
      c.media.connectionCaps.receive.screen = 8000;
      await c.media.updateBandwidth(c.preferences.quality);
      await command('verify-bandwidth-low');
      c.media.connectionCaps.receive.camera = null;
      c.media.connectionCaps.receive.screen = null;
      await c.media.updateBandwidth(c.preferences.quality);
      await command('verify-bandwidth-auto');
      final sharingConnection = c.media.connection;
      await command('share');
      await until(
        tester,
        () => c.media.remote.videoWidth == 960,
        'Native receives browser screen frames',
      );
      expect(c.media.connection, same(sharingConnection));
      await command('stop-share');
      await until(
        tester,
        () => c.media.remote.videoWidth == 640,
        'Native receives restored browser camera',
      );
      final stats = await c.media.connection!.getStats();
      final observed = c.media.evidence!;
      final matching = stats
          .where(
            (s) =>
                s.type == 'candidate-pair' &&
                s.id == observed.data['selectedPairId'],
          )
          .toList();
      expect(matching, hasLength(1));
      for (final side in ['local', 'remote']) {
        final id = matching.single.values['${side}CandidateId'];
        final actual = stats.firstWhere((s) => s.id == id);
        final endpoint = observed.data[side] as Map;
        final actualAddress = actual.values['address'] ?? actual.values['ip'];
        expect(
          endpoint['address'],
          actualAddress is String && actualAddress.isNotEmpty
              ? actualAddress
              : null,
        );
        expect(endpoint['port'], actual.values['port']);
      }
      expect(c.api.signalingSocket?['remote']['port'], c.api.origin.port);
      expect(c.api.signalingSocket?['local']['port'], greaterThan(0));
      await screenshot('native-room-call');
      await tester.tap(find.byTooltip('More'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Connection'));
      await tester.pumpAndSettle();
      expect(find.text('Connection info & bandwidth'), findsOneWidget);
      expect(
        find.textContaining('WebRTC statistics sampled at:'),
        findsOneWidget,
      );
      await screenshot('native-inspector');
      await tester.tap(find.byTooltip('Close inspector'));
      await tester.pumpAndSettle();
      expect(
        stats.any(
          (s) =>
              s.type == 'transport' &&
              s.values['dtlsState'] == 'connected' &&
              s.values['dtlsCipher'] != null &&
              s.values['srtpCipher'] != null,
        ),
        isTrue,
        reason: 'Native DTLS and SRTP ciphers negotiated',
      );
      await until(
        tester,
        () => c.media.securityCode.isNotEmpty,
        'Native certificate verification code is available',
      );
      final verification = await command('verify');
      expect(
        verification['code'],
        c.media.securityCode,
        reason: 'Native and browser certificate codes match',
      );
      expect(
        stats.any(
          (s) =>
              s.type == 'inbound-rtp' &&
              (s.values['kind'] == 'audio' ||
                  s.values['mediaType'] == 'audio') &&
              (s.values['bytesReceived'] as num? ?? 0) > 0,
        ),
        isTrue,
      );
      if (audioTest) {
        final audio = await command('verify-audio');
        expect(
          audio['energy'],
          greaterThan(0.001),
          reason: 'Browser hears the native synthetic tone, not only video/RTP',
        );
        await until(
          tester,
          () => c.media.microphoneLevel > 0.005,
          'Native microphone meter sees input',
        );
        c.media.toggleMic();
        await tester.pump(const Duration(seconds: 1));
        final before = await command('audio-stats');
        await tester.pump(const Duration(seconds: 1));
        final after = await command('audio-stats');
        expect(
          (after['energy'] as num) - (before['energy'] as num),
          lessThan(0.0001),
          reason: 'Mute stops audible audio at the browser',
        );
        final trackId = c.media.stream!.getAudioTracks().single.id;
        final deviceId = c.preferences.microphone;
        await c.setDevice('audioinput', '');
        expect(
          (await c.host.invoke<Map>('microphoneStatus'))?['deviceDefault'],
          isTrue,
        );
        await c.setDevice('audioinput', deviceId);
        expect(
          c.media.stream!.getAudioTracks().single.id,
          trackId,
          reason: 'Routing changes preserve the sender',
        );
        expect(
          c.media.stream!.getAudioTracks().single.enabled,
          isFalse,
          reason: 'Routing preserves mute',
        );
        c.media.toggleMic();
        final resumed = await command('verify-audio');
        expect(
          resumed['energy'],
          greaterThan(after['energy'] + 0.001),
          reason: 'Unmute resumes native sound',
        );
      }
      expect(
        stats
            .where((s) => s.type.endsWith('candidate'))
            .any((s) => s.values['candidateType'] == 'relay'),
        isFalse,
      );
      debugPrint('Native ending first real call');
      await c.endCall().timeout(const Duration(seconds: 20));
      await until(
        tester,
        () => !c.busy && c.media.connection == null,
        'Hangup releases native media',
      );
      await command('wait-ended');

      await c.startCall(c.accepted.first);
      await command('answer');
      await until(
        tester,
        () => c.phase == 'connected',
        'Native-to-browser WebRTC connects',
      );
      await until(
        tester,
        () => c.media.remote.videoWidth > 0,
        'Native offer negotiates browser video',
      );
      if (audioTest) {
        final audio = await command('verify-audio');
        expect(
          audio['energy'],
          greaterThan(0.001),
          reason: 'Native caller sends audible audio too',
        );
        expect(
          c.media.stream!.getAudioTracks().single.enabled,
          isTrue,
          reason: 'A new call starts unmuted',
        );
      }
      await command('hangup');
      await until(
        tester,
        () => !c.busy && c.media.stream == null,
        'Remote hangup stops native media',
      );

      await c.host.invoke('hide');
      await c.reconnect();
      await until(
        tester,
        () => c.online,
        'Reconnect restores hidden app availability',
      );
      // Widget pumping needs a visible macOS surface. Hidden-window ringing
      // and reconnection have already been asserted above.
      await c.host.invoke('show');
      await tester.pumpAndSettle();
      await c.signOut();
      expect(await c.host.readSession(c.api.address), isNull);
      expect(await c.authenticate(username, password, '', false), isTrue);
      expect(
        c.preferences.quality.preset,
        'saver',
        reason: 'Preferences survive sign-out and restart',
      );
      final nativePeer = PvpController(
        host: SilentTestHost(),
        address: c.api.address,
        media: CallMedia(
          captureOverride: (_) => createLocalMediaStream('second-native-test'),
        ),
      );
      final nativeCaller = PvpController(
        host: SilentTestHost(),
        address: c.api.address,
        media: CallMedia(
          captureOverride: (_) => createLocalMediaStream('native-data-test'),
          peerCreated: (pc) async {
            await pc.createDataChannel(
              'encrypted-native-test',
              RTCDataChannelInit(),
            );
          },
        ),
      );
      debugPrint('Native initializing second native peer');
      await nativePeer.initialize().timeout(const Duration(seconds: 20));
      debugPrint('Native initializing second native caller');
      await nativeCaller.initialize().timeout(const Duration(seconds: 20));
      try {
        expect(
          await nativePeer.authenticate(
            'second_$username',
            password,
            'Second native',
            true,
          ),
          isTrue,
        );
        expect(
          await nativeCaller.authenticate(
            'caller_$username',
            password,
            'Native caller',
            true,
          ),
          isTrue,
        );
        await until(
          tester,
          () => nativePeer.online && nativeCaller.online,
          'Two native clients are available',
        );
        expect(await nativeCaller.addFriend('second_$username'), isTrue);
        await until(
          tester,
          () => nativePeer.requests.isNotEmpty,
          'Native friend invitation arrives',
        );
        await nativePeer.acceptFriend(nativePeer.requests.first);
        await nativeCaller.refresh();
        debugPrint(
          'Native caller starting with peer ${nativeCaller.accepted.first.id}',
        );
        await nativeCaller.startCall(nativeCaller.accepted.first);
        debugPrint(
          'Native caller start outcome: phase=${nativeCaller.phase} '
          'message=${nativeCaller.message}',
        );
        expect(nativeCaller.phase, 'calling', reason: nativeCaller.message);
        await until(
          tester,
          () => nativePeer.phase == 'incoming',
          'Native-to-native call rings',
        );
        await nativePeer.answer();
        await until(
          tester,
          () =>
              nativeCaller.phase == 'connected' &&
              nativePeer.phase == 'connected',
          'Native-to-native encrypted transport connects',
        );
        await until(
          tester,
          () =>
              nativeCaller.media.securityCode.isNotEmpty &&
              nativePeer.media.securityCode.isNotEmpty,
          'Native peer certificate codes are available',
        );
        expect(nativeCaller.media.securityCode, nativePeer.media.securityCode);
        for (final peer in [nativeCaller, nativePeer]) {
          final stats = await peer.media.connection!.getStats();
          expect(
            stats.any(
              (s) =>
                  s.type == 'transport' &&
                  s.values['dtlsState'] == 'connected' &&
                  s.values['dtlsCipher'] != null,
            ),
            isTrue,
          );
          expect(
            stats
                .where((s) => s.type.endsWith('candidate'))
                .any((s) => s.values['candidateType'] == 'relay'),
            isFalse,
          );
        }
        debugPrint('Native ending native-to-native call');
        await nativeCaller.endCall().timeout(const Duration(seconds: 20));
        await until(
          tester,
          () => !nativePeer.busy,
          'Native hangup reaches the other native client',
        );
      } finally {
        await nativeCaller.signOut();
        await nativePeer.signOut();
        nativeCaller.dispose();
        nativePeer.dispose();
      }
      await c.signOut();
      await c.host.invoke('show');
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    },
  );
}
