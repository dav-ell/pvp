import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:pvp_desktop/core/group_calls.dart';
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/core/native.dart';
import 'connection_evidence_test.dart' show fixture;

class ProofPeer implements RTCPeerConnection {
  final List<Map<String, dynamic>> reports;
  bool closed = false;
  ProofPeer(this.reports);
  @override
  RTCIceConnectionState get iceConnectionState =>
      RTCIceConnectionState.RTCIceConnectionStateConnected;
  @override
  Future<List<StatsReport>> getStats([MediaStreamTrack? track]) async =>
      reports.map((r) => StatsReport(r['id'], r['type'], 1, r)).toList();
  @override
  Future<List<RTCRtpSender>> getSenders() async => [];
  @override
  Future<void> close() async {
    closed = true;
  }

  @override
  Future<void> dispose() async {}
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class ProofHost extends NativeHost {
  @override
  Future<T?> invoke<T>(String method, [dynamic arguments]) async => null;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  for (final rejection in ['missing', 'relay', 'certificate', 'dtls']) {
    test(
      'selected transport $rejection evidence has the appropriate call outcome',
      () async {
        final reports = fixture();
        String fingerprint(String byte) => List.filled(32, byte).join(':');
        String sdp(String byte) =>
            'v=0\r\n'
            'a=fingerprint:sha-256 ${fingerprint(byte)}\r\n'
            'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n';
        if (rejection == 'relay') {
          reports[1]['candidateType'] = 'relay';
        } else if (rejection == 'certificate') {
          reports.last['remoteCertificateId'] = 'rc';
          reports.add({
            'id': 'rc',
            'type': 'certificate',
            'fingerprintAlgorithm': 'sha-256',
            'fingerprint': fingerprint('CC'),
          });
        } else if (rejection == 'dtls') {
          reports.last['dtlsState'] = 'failed';
        }
        final media = GroupMedia(), peer = ProofPeer(reports);
        final sent = <Map<String, dynamic>>[];
        final group = GroupCalls(
          host: ProofHost(),
          media: media,
          user: () => const Person('self', 'self', 'Self'),
          preferences: () => Preferences(),
          send: sent.add,
          stopPreview: () async {},
          otherBusy: () => false,
        );
        group.room = {
          'room_id': 'room',
          'members': [
            {'id': 'self', 'joined': true},
            {'id': 'peer', 'joined': true},
          ],
        };
        final link = GroupLink('peer', peer, 1)
          ..ready = true
          ..status = 'Connected'
          ..localSdp = sdp('AA')
          ..remoteSdp = sdp('BB')
          ..code = 'comparison only';
        media.links['peer'] = link;
        await group.sample();
        if (rejection == 'missing') {
          expect(group.joined, true);
          expect(peer.closed, false);
          expect(link.evidence!.encryptionConfirmed, false);
          expect(sent.where((s) => s['type'] == 'room-leave'), isEmpty);
        } else {
          expect(group.joined, false);
          expect(peer.closed, true);
          expect(link.code, '');
          expect(sent.last['type'], 'room-leave');
          expect(group.message, isNotEmpty);
        }
        await group.cleanup();
        group.dispose();
      },
    );
  }
}
