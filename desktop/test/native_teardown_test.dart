import 'dart:async';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:pvp_desktop/core/controller.dart';
import 'package:pvp_desktop/core/group_calls.dart';
import 'package:pvp_desktop/core/media.dart';
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/core/native.dart';
import 'screenshare_test.dart' show Track, Stream;
import 'transport_proof_test.dart' show ProofPeer;
import 'connection_evidence_test.dart' show fixture;

class PendingStatsPeer extends ProofPeer {
  final statsReady = Completer<List<StatsReport>>();
  PendingStatsPeer() : super([]);
  @override
  Future<List<StatsReport>> getStats([MediaStreamTrack? track]) =>
      statsReady.future;
}

class RingFailureHost extends NativeHost {
  final bool hang;
  bool ringingStopCalled = false;
  RingFailureHost({required this.hang});
  @override
  Future<T?> invoke<T>(String method, [dynamic arguments]) async {
    if (method == 'stopRinging') {
      ringingStopCalled = true;
      if (hang) return Completer<T?>().future;
      throw PlatformException(code: 'ringing-unavailable');
    }
    return null;
  }
}

class ClosingPeer implements RTCPeerConnection {
  final released = Completer<void>();
  bool closeCalled = false;
  @override
  Future<void> close() {
    closeCalled = true;
    return released.future;
  }

  @override
  Future<void> dispose() async {}
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  for (final hang in [false, true]) {
    test(
      'direct teardown stops capture when stopRinging ${hang ? 'never resolves' : 'throws'}',
      () async {
        final host = RingFailureHost(hang: hang);
        final mic = Track('audio', 'mic'), camera = Track('video', 'camera');
        final media = CallMedia()..stream = Stream('capture', [mic, camera]);
        final c = PvpController(host: host, media: media)
          ..phase = 'connected'
          ..callId = 'call';
        await c
            .endCall(error: 'Certificate mismatch')
            .timeout(const Duration(seconds: 1));
        expect(host.ringingStopCalled, isTrue);
        expect(mic.enabled, isFalse);
        expect(camera.enabled, isFalse);
        expect(mic.stopped && camera.stopped, isTrue);
        expect(c.phase, 'idle');
        expect(c.message, 'Certificate mismatch');
        c.dispose();
        c.group.dispose();
      },
    );

    test(
      'group teardown stops capture when stopRinging ${hang ? 'never resolves' : 'throws'}',
      () async {
        final host = RingFailureHost(hang: hang);
        final mic = Track('audio', 'mic');
        final media = GroupMedia()..stream = Stream('capture', [mic]);
        final group = GroupCalls(
          host: host,
          media: media,
          user: () => const Person('self', 'self', 'Self'),
          preferences: () => Preferences(),
          send: (_) {},
          stopPreview: () async {},
          otherBusy: () => false,
        )..room = {'room_id': 'room', 'members': []};
        await group.leave().timeout(const Duration(seconds: 1));
        expect(host.ringingStopCalled, isTrue);
        expect(mic.enabled, isFalse);
        expect(mic.stopped, isTrue);
        expect(group.busy, isFalse);
        group.dispose();
      },
    );
  }

  test('a hung peer close cannot leave microphone or camera enabled', () async {
    final peer = ClosingPeer();
    final mic = Track('audio', 'mic'), camera = Track('video', 'camera');
    final media = CallMedia()
      ..stream = Stream('capture', [mic, camera])
      ..connection = peer;
    final stopped = media.stop();
    expect(mic.enabled || camera.enabled, isFalse);
    expect(peer.closeCalled, isTrue);
    expect(mic.stopped && camera.stopped, isTrue);
    peer.released.complete();
    await stopped;
    media.dispose();
  });

  test(
    'a hung first group peer does not delay closing other peer transports',
    () async {
      final first = ClosingPeer(), second = ClosingPeer();
      final mic = Track('audio', 'mic');
      final media = GroupMedia()..stream = Stream('capture', [mic]);
      media.links['first'] = GroupLink('first', first, 1)..code = 'old code';
      media.links['second'] = GroupLink('second', second, 1);
      final stopped = media.stop();
      expect(mic.enabled, isFalse);
      expect(first.closeCalled && second.closeCalled, isTrue);
      expect(media.links, isEmpty);
      first.released.complete();
      second.released.complete();
      await stopped;
      media.dispose();
    },
  );
  test(
    'definite failure stops capture before another peer returns stats',
    () async {
      final reports = fixture();
      reports.last['dtlsState'] = 'failed';
      final rejected = ProofPeer(reports), delayed = PendingStatsPeer();
      final mic = Track('audio', 'mic');
      final media = GroupMedia()..stream = Stream('capture', [mic]);
      media.links['rejected'] = GroupLink('rejected', rejected, 1)
        ..ready = true
        ..status = 'Connected';
      media.links['delayed'] = GroupLink('delayed', delayed, 1)
        ..ready = true
        ..status = 'Connected';
      final group =
          GroupCalls(
              host: RingFailureHost(hang: true),
              media: media,
              user: () => const Person('self', 'self', 'Self'),
              preferences: () => Preferences(),
              send: (_) {},
              stopPreview: () async {},
              otherBusy: () => false,
            )
            ..room = {
              'room_id': 'room',
              'members': [
                {'id': 'self', 'joined': true},
                {'id': 'rejected', 'joined': true},
                {'id': 'delayed', 'joined': true},
              ],
            };
      final sampling = group.sample();
      await Future<void>.delayed(Duration.zero);
      expect(mic.enabled, isFalse);
      expect(mic.stopped, isTrue);
      expect(rejected.closed && delayed.closed, isTrue);
      expect(group.message, contains('encrypted transport'));
      delayed.statsReady.complete([]);
      await sampling;
      group.dispose();
    },
  );
}
