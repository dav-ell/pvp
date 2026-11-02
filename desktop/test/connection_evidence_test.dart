import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/connection_evidence.dart';

List<Map<String, dynamic>> fixture() => [
  {
    'id': 'l',
    'type': 'local-candidate',
    'address': '192.0.2.10',
    'port': 50000,
    'protocol': 'udp',
    'candidateType': 'host',
  },
  {
    'id': 'r',
    'type': 'remote-candidate',
    'address': '198.51.100.20',
    'port': 60000,
    'protocol': 'udp',
    'candidateType': 'srflx',
  },
  {
    'id': 'p',
    'type': 'candidate-pair',
    'localCandidateId': 'l',
    'remoteCandidateId': 'r',
    'state': 'succeeded',
    'nominated': true,
    'bytesSent': 12345,
    'bytesReceived': 23456,
  },
  {
    'id': 'other',
    'type': 'candidate-pair',
    'state': 'succeeded',
    'nominated': true,
  },
  {
    'id': 't',
    'type': 'transport',
    'selectedCandidatePairId': 'p',
    'dtlsState': 'connected',
  },
];
ConnectionEvidence inspect(
  List<Map<String, dynamic>> stats, {
  String state = 'connected',
}) => ConnectionEvidence.fromReports(
  stats,
  connectionState: state,
  iceState: state,
);

void main() {
  test('selected transport drives endpoint evidence and path changes', () {
    final stats = fixture(), first = inspect(stats);
    expect(first.direct, true);
    expect(first.data['bytesSent'], 12345);
    expect(endpointLabel(first.remote), '198.51.100.20:60000');
    stats.last['selectedCandidatePairId'] = 'other';
    expect(inspect(stats).data['selectedPairId'], 'other');
    expect(inspect(stats).direct, false);
  });
  test('ambiguous, missing, disconnected and relayed paths are not direct', () {
    final multiple = fixture();
    multiple.add({...multiple.last, 'id': 'extra'});
    expect(inspect(multiple).data['selectedPairId'], null);
    final stats = fixture()..removeLast();
    expect(inspect(stats).data['selectedPairId'], null);
    stats.removeLast();
    // A unique nominated pair still does not prove it was selected.
    expect(inspect(stats).direct, false);
    stats.add({
      'id': 'selected',
      'type': 'transport',
      'selectedCandidatePairId': 'p',
    });
    expect(inspect(stats).direct, true);
    stats[1]['candidateType'] = 'relay';
    expect(inspect(stats).relayed, true);
    expect(inspect(stats).direct, false);
    stats[1]['candidateType'] = 'srflx';
    expect(inspect(stats, state: 'disconnected').direct, false);
    stats.removeAt(1);
    expect(inspect(stats).direct, false);
    expect(inspect([]).data['bytesReceived'], null);
  });
  test(
    'encryption proof binds both selected certificates to negotiated SDP',
    () {
      String fingerprint(String byte) => List.filled(32, byte).join(':');
      String sdp(String byte) =>
          'v=0\r\n'
          'a=fingerprint:sha-256 ${fingerprint(byte)}\r\n'
          'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n';
      final reports = fixture();
      reports.last.addAll({
        'localCertificateId': 'lc',
        'remoteCertificateId': 'rc',
        'dtlsState': 'connected',
        'dtlsCipher': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'srtpCipher': 'AEAD_AES_128_GCM',
      });
      reports.addAll([
        {
          'id': 'lc',
          'type': 'certificate',
          'fingerprintAlgorithm': 'sha-256',
          'fingerprint': fingerprint('AA'),
        },
        {
          'id': 'rc',
          'type': 'certificate',
          'fingerprintAlgorithm': 'sha-256',
          'fingerprint': fingerprint('BB'),
        },
      ]);
      ConnectionEvidence proof({DateTime? at}) =>
          ConnectionEvidence.fromReports(
            reports,
            connectionState: 'connected',
            iceState: 'connected',
            localSdp: sdp('AA'),
            remoteSdp: sdp('BB'),
            sampledAt: at,
          );
      expect(proof().encryptionConfirmed, true);
      expect(proof().trustSummary, contains('Encrypted direct'));
      expect(proof().certificateStatus, contains('match negotiation'));
      reports.firstWhere((r) => r['id'] == 't').remove('dtlsCipher');
      expect(proof().encryptionConfirmed, false);
      for (final blank in ['', '   ']) {
        reports.firstWhere((r) => r['id'] == 't')['dtlsCipher'] = blank;
        expect(proof().encryptionConfirmed, false);
      }
      reports.firstWhere((r) => r['id'] == 't')['dtlsCipher'] =
          'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256';
      reports.last['fingerprint'] = fingerprint('CC');
      expect(proof().certificateMismatch, true);
      expect(proof().encryptionConfirmed, false);
      reports.last['fingerprint'] = fingerprint('BB');
      reports.last['fingerprintAlgorithm'] = 'sha-1';
      expect(proof().certificateMismatch, false);
      expect(proof().encryptionConfirmed, false);
      reports.last['fingerprintAlgorithm'] = 'sha-256';
      reports.firstWhere((r) => r['id'] == 't').remove('srtpCipher');
      expect(proof().encryptionConfirmed, false);
      reports.firstWhere((r) => r['id'] == 't')['srtpCipher'] =
          'SRTP_AES_CM_128_HMAC_SHA1_80';
      expect(proof().encryptionConfirmed, true);
      for (final profile in [
        'SRTP_AES128_CM_HMAC_SHA1_80',
        'SRTP_AES128_CM_HMAC_SHA1_32',
      ]) {
        reports.firstWhere((r) => r['id'] == 't')['srtpCipher'] = profile;
        expect(proof().encryptionConfirmed, isTrue, reason: profile);
      }
      for (final profile in [
        'SRTP_NULL_HMAC_SHA1_80',
        'SRTP_NULL_HMAC_SHA1_32',
        'SRTP_NULL_SHA1_80',
        'SRTP_NULL_SHA1_32',
        'NULL',
        'PLAINTEXT',
      ]) {
        reports.firstWhere((r) => r['id'] == 't')['srtpCipher'] = profile;
        expect(proof().transportFailed, isTrue, reason: profile);
      }
      reports.firstWhere((r) => r['id'] == 't')['srtpCipher'] = 'UNKNOWN';
      expect(proof().transportFailed, isFalse);
      expect(proof().encryptionConfirmed, isFalse);
      reports.firstWhere((r) => r['id'] == 't')['srtpCipher'] =
          'SRTP_AES128_CM_HMAC_SHA1_80';
      reports.add({
        'id': 'irrelevant',
        'type': 'transport',
        'dtlsState': 'failed',
      });
      expect(proof().transportFailed, false);
      expect(
        proof(
          at: DateTime.now().subtract(const Duration(seconds: 5)),
        ).trustSummary,
        'Connection proof unavailable',
      );
      reports.firstWhere((r) => r['id'] == 't')['dtlsState'] = 'failed';
      expect(proof().transportFailed, true);
    },
  );
  test(
    'capture command accepts real tuples and rejects hidden addresses and injection',
    () {
      expect(
        captureCommand(inspect(fixture()).remote),
        "sudo tcpdump -i pktap,all -nn -tttt 'udp and host 198.51.100.20 and port 60000'",
      );
      expect(
        captureCommand({
          'address': '2001:db8::1',
          'port': 443,
          'protocol': 'tcp',
        }),
        contains('tcp and host 2001:db8::1 and port 443'),
      );
      for (final address in [
        '',
        'peer.local',
        "198.51.100.20'; echo malicious",
        '999.1.2.3',
      ]) {
        expect(
          captureCommand({'address': address, 'port': 1234, 'protocol': 'udp'}),
          null,
        );
      }
      final hiddenStats = fixture();
      hiddenStats[1]['address'] = '';
      final hidden = inspect(hiddenStats);
      expect(endpointLabel(hidden.remote), 'Address unavailable:60000');
      expect(
        mediaCaptureCommand(hidden),
        contains('host 192.0.2.10 and port 50000'),
      );
      expect(
        captureCommand({
          'address': '127.0.0.1',
          'port': 65536,
          'protocol': 'tcp',
        }),
        null,
      );
    },
  );
  for (final state in [
    'healthy',
    'relay',
    'certificate',
    'dtls',
    'missing-pair',
  ]) {
    test('multiple selected transports preserve definite $state evidence', () {
      String fingerprint(String byte) => List.filled(32, byte).join(':');
      String sdp(String byte) =>
          'v=0\r\n'
          'a=fingerprint:sha-256 ${fingerprint(byte)}\r\n'
          'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n';
      final reports = fixture();
      final firstTransport = reports.last;
      firstTransport.addAll({
        'localCertificateId': 'lc',
        'remoteCertificateId': 'rc',
        'dtlsCipher': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'srtpCipher': 'AEAD_AES_128_GCM',
      });
      reports.addAll([
        {...reports[0], 'id': 'l2'},
        {
          ...reports[1],
          'id': 'r2',
          'candidateType': state == 'relay' ? 'relay' : 'srflx',
        },
        {
          ...reports[2],
          'id': 'p2',
          'localCandidateId': 'l2',
          'remoteCandidateId': 'r2',
        },
        {
          ...firstTransport,
          'id': 't2',
          'selectedCandidatePairId': state == 'missing-pair'
              ? 'not-reported'
              : 'p2',
          'dtlsState': ['dtls', 'missing-pair'].contains(state)
              ? 'failed'
              : 'connected',
          'remoteCertificateId': state == 'certificate' ? 'rc-bad' : 'rc',
        },
        {
          'id': 'lc',
          'type': 'certificate',
          'fingerprintAlgorithm': 'sha-256',
          'fingerprint': fingerprint('AA'),
        },
        {
          'id': 'rc',
          'type': 'certificate',
          'fingerprintAlgorithm': 'sha-256',
          'fingerprint': fingerprint('BB'),
        },
        {
          'id': 'rc-bad',
          'type': 'certificate',
          'fingerprintAlgorithm': 'sha-256',
          'fingerprint': fingerprint('CC'),
        },
      ]);
      final proof = ConnectionEvidence.fromReports(
        reports,
        connectionState: 'connected',
        iceState: 'connected',
        localSdp: sdp('AA'),
        remoteSdp: sdp('BB'),
      );
      expect(proof.data['selectedTransportCount'], 2);
      expect(proof.data['selectedPairId'], null);
      expect(proof.direct, false);
      expect(proof.encryptionConfirmed, false);
      expect(proof.relayed, state == 'relay');
      expect(proof.certificateMismatch, state == 'certificate');
      expect(
        proof.transportFailed,
        ['certificate', 'dtls', 'missing-pair'].contains(state),
      );
      if (state == 'healthy') {
        expect(proof.data['certificateStatus'], 'unavailable');
        expect(proof.trustSummary, 'Connection proof unavailable');
      }
    });
  }
}
