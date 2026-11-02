import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/api.dart';
import 'package:pvp_desktop/core/security.dart';

String sdp(String byte) =>
    'v=0\r\na=fingerprint:sha-256 ${List.filled(32, byte).join(':')}\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n';
void main() {
  test(
    'requires DTLS certificates and refuses plaintext, SDES and relay downgrade',
    () {
      requireEncryptedSdp(sdp('AB'));
      for (final bad in [
        sdp('AB').replaceAll('UDP/TLS/RTP/SAVPF', 'RTP/AVP'),
        'v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n',
        '${sdp('AB')}a=crypto:1 inline:key\r\n',
        '${sdp('AB')}a=candidate:1 1 udp 1 1.2.3.4 9 typ\tRELAY\r\n',
      ]) {
        expect(() => requireEncryptedSdp(bad), throwsStateError);
      }
      expect(
        safetyCode(sdp('AA'), sdp('BB')),
        safetyCode(sdp('BB'), sdp('AA')),
      );
      expect(
        safetyCode(sdp('AA'), sdp('BB')),
        isNot(safetyCode(sdp('AA'), sdp('CC'))),
      );
      expect(safetyCode(sdp('AA'), sdp('BB')), 'afcb 10d4 611b 6ade 7c81 8747');
      final padded =
          '${sdp('AA')}'
          'a=fingerprint:sha-256 ${List.filled(32, 'BB').join(':')}\r\n';
      expect(
        () => safetyCode(padded, padded),
        throwsStateError,
        reason: 'unused fingerprints cannot make endpoint unions coincide',
      );
      expect(() => safetyCode(padded, sdp('CC')), throwsStateError);
      expect(
        () => safetyCode(
          '${sdp('AA')}a=fingerprint:sha-256 ${List.filled(32, 'BB').join(':')}\r\n',
          'v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n',
        ),
        throwsStateError,
      );
      expect(
        () => safetyCode(
          sdp('AA'),
          sdp('BB').replaceFirst('UDP/TLS/RTP/SAVPF', 'RTP/AVP'),
        ),
        throwsStateError,
      );
      expect(
        () => requireCandidate({
          'candidate': 'candidate:1 1 udp 1 127.0.0.1 9 typ host',
          'sdpMLineIndex': 1000000,
        }),
        throwsStateError,
      );
    },
  );
  test(
    'a redirected WebSocket handshake never forwards session cookies',
    () async {
      final first = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final target = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      var leaked = false;
      target.listen((req) {
        leaked = true;
        req.response.statusCode = 400;
        req.response.close();
      });
      first.listen((req) {
        req.response.statusCode = 302;
        req.response.headers.set(
          'location',
          'http://127.0.0.1:${target.port}/api/ws',
        );
        req.response.close();
      });
      final api = PvpApi('http://127.0.0.1:${first.port}')
        ..session = List.filled(64, 'a').join();
      try {
        await expectLater(api.connect(), throwsA(isA<WebSocketException>()));
        expect(leaked, isFalse);
      } finally {
        api.dispose();
        await first.close(force: true);
        await target.close(force: true);
      }
    },
  );
}
