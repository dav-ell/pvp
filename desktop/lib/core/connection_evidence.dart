import 'dart:io';
import 'security.dart';

// The model retains allowlisted observations, never SDP, credentials or media.
String? literalIp(Object? value) {
  if (value is! String ||
      value.length > 64 ||
      !RegExp(r'^[0-9a-fA-F:.]+$').hasMatch(value)) {
    return null;
  }
  return InternetAddress.tryParse(value)?.address;
}

String endpointLabel(Map<String, dynamic>? value) {
  if (value == null) return 'Address unavailable';
  final address = value['address'] as String? ?? 'Address unavailable';
  return '${address.contains(':') ? '[$address]' : address}:${value['port'] ?? 'port unavailable'}';
}

String? captureCommand(Map<String, dynamic>? value) {
  final ip = literalIp(value?['address']);
  final port = value?['port'];
  final protocol = value?['protocol'];
  if (ip == null ||
      port is! int ||
      port < 1 ||
      port > 65535 ||
      !['udp', 'tcp'].contains(protocol)) {
    return null;
  }
  return "sudo tcpdump -i pktap,all -nn -tttt '$protocol and host $ip and port $port'";
}

String? mediaCaptureCommand(ConnectionEvidence? evidence) =>
    captureCommand(evidence?.remote) ??
    (evidence?.local?['candidateType'] == 'host'
        ? captureCommand(evidence?.local)
        : null);

class ConnectionEvidence {
  final Map<String, dynamic> data;
  const ConnectionEvidence(this.data);
  bool get direct => data['direct'] == true;
  bool get relayed => data['relayed'] == true;
  bool get certificateMismatch => data['certificateStatus'] == 'mismatch';
  bool get transportFailed => data['encryptionStatus'] == 'failed';
  bool get transportConnected =>
      fresh &&
      data['dtlsState'] == 'connected' &&
      data['connectionState'] == 'connected';
  bool get encryptionConfirmed =>
      fresh && data['encryptionStatus'] == 'confirmed';
  bool get fresh {
    final sampled = DateTime.tryParse(data['sampledAt'] as String? ?? '');
    if (sampled == null) return false;
    final age = DateTime.now().toUtc().difference(sampled).inMilliseconds;
    return age >= 0 && age < 4000;
  }

  String get certificateStatus => fresh
      ? switch (data['certificateStatus']) {
          'matched' => 'Selected transport certificates match negotiation',
          'mismatch' => 'Selected transport certificate mismatch',
          _ => 'Selected transport certificate evidence unavailable',
        }
      : 'Selected transport certificate evidence unavailable';
  String get trustSummary {
    if (!fresh) return 'Connection proof unavailable';
    if (relayed) return 'Relayed connection rejected';
    if (certificateMismatch) return 'Certificate mismatch';
    if (transportFailed) return 'Encrypted transport failed';
    if (direct && encryptionConfirmed) {
      return 'Encrypted direct connection · certificates match';
    }
    if (encryptionConfirmed) return 'Encryption confirmed · route unavailable';
    return 'Connection proof unavailable';
  }

  Map<String, dynamic>? get local => data['local'] as Map<String, dynamic>?;
  Map<String, dynamic>? get remote => data['remote'] as Map<String, dynamic>?;

  static String? _text(Object? value) => value is String && value.isNotEmpty
      ? value.substring(0, value.length.clamp(0, 256))
      : null;
  static num? _number(Object? value) =>
      value is num && value.isFinite && value >= 0 ? value : null;

  static Map<String, dynamic>? endpoint(Map<String, dynamic>? candidate) {
    if (candidate == null) return null;
    final address = _text(candidate['address'] ?? candidate['ip']);
    final port = candidate['port'];
    return {
      'id': _text(candidate['id']),
      'address': address,
      'port': port is int && port > 0 && port <= 65535 ? port : null,
      'protocol': ['udp', 'tcp'].contains(candidate['protocol'])
          ? candidate['protocol']
          : null,
      'candidateType': _text(candidate['candidateType']),
      'url': _text(candidate['url']),
      'relatedAddress': _text(candidate['relatedAddress']),
      'relatedPort': _number(candidate['relatedPort']),
      'timestamp': _number(candidate['timestamp']),
      'source': 'WebRTC statistics',
    };
  }

  factory ConnectionEvidence.fromReports(
    List<Map<String, dynamic>> reports, {
    required String connectionState,
    required String iceState,
    List<String> configuredServers = const [],
    DateTime? sampledAt,
    String? localSdp,
    String? remoteSdp,
  }) {
    final byId = {for (final r in reports) r['id']: r};
    final transports = reports.where((r) => r['type'] == 'transport').toList();
    final selectors = transports
        .where((r) => r['selectedCandidatePairId'] != null)
        .toList();
    final selected = selectors.length == 1
        ? byId[selectors.first['selectedCandidatePairId']]
        : null;
    final pair = selected?['type'] == 'candidate-pair' ? selected : null;
    // A nominated/succeeded pair is not proof of the selected route.
    final transport = selectors.length == 1 && pair != null
        ? selectors.first
        : null;
    final local = endpoint(byId[pair?['localCandidateId']]);
    final remote = endpoint(byId[pair?['remoteCandidateId']]);
    String? fingerprint(Object? id) {
      final certificate = byId[id];
      if (certificate?['type'] != 'certificate' ||
          certificate?['fingerprintAlgorithm']?.toString().toLowerCase() !=
              'sha-256') {
        return null;
      }
      final value = certificate?['fingerprint'];
      if (value is! String ||
          !RegExp(
            r'^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$',
            caseSensitive: false,
          ).hasMatch(value)) {
        return null;
      }
      return value.replaceAll(':', '').toLowerCase();
    }

    final localFingerprint = fingerprint(transport?['localCertificateId']),
        remoteFingerprint = fingerprint(transport?['remoteCertificateId']);
    final localExpected = certificateFingerprints(localSdp ?? ''),
        remoteExpected = certificateFingerprints(remoteSdp ?? '');
    bool mismatchedCertificate(Map<String, dynamic> selectedTransport) {
      final local = fingerprint(selectedTransport['localCertificateId']),
          remote = fingerprint(selectedTransport['remoteCertificateId']);
      return (local != null &&
              localExpected.isNotEmpty &&
              !localExpected.contains(local)) ||
          (remote != null &&
              remoteExpected.isNotEmpty &&
              !remoteExpected.contains(remote));
    }

    // An ambiguous aggregate cannot prove a healthy path, but must not hide
    // definite failures on any explicitly selected transport.
    final certificateMismatch = selectors.any(mismatchedCertificate);
    final failedSelectedDtls = selectors.any(
      (t) => ['failed', 'closed'].contains(t['dtlsState']),
    );
    final selectedRelay = selectors.any((t) {
      final p = byId[t['selectedCandidatePairId']];
      if (p?['type'] != 'candidate-pair') return false;
      return [
        p?['localCandidateId'],
        p?['remoteCandidateId'],
      ].any((id) => byId[id]?['candidateType'] == 'relay');
    });
    final certificatesMatch =
        localFingerprint != null &&
        remoteFingerprint != null &&
        localExpected.contains(localFingerprint) &&
        remoteExpected.contains(remoteFingerprint);
    final dtlsState = _text(transport?['dtlsState']);
    final dtlsCipher = _text(transport?['dtlsCipher']);
    final srtpCipher = _text(transport?['srtpCipher']);
    const encryptedSrtpCiphers = {
      'AEAD_AES_128_GCM',
      'AEAD_AES_256_GCM',
      'AES_CM_128_HMAC_SHA1_80',
      'AES_CM_128_HMAC_SHA1_32',
      'AES128_CM_HMAC_SHA1_80',
      'AES128_CM_HMAC_SHA1_32',
    };
    const plaintextProfiles = {
      'NULL_HMAC_SHA1_80',
      'NULL_HMAC_SHA1_32',
      'NULL_SHA1_80',
      'NULL_SHA1_32',
      'NULL',
      'PLAINTEXT',
    };
    final selectedPlaintext = selectors.any(
      (t) => plaintextProfiles.contains(
        _text(
          t['srtpCipher'],
        )?.trim().toUpperCase().replaceFirst(RegExp(r'^SRTP_'), ''),
      ),
    );
    final encryptedSrtp = encryptedSrtpCiphers.contains(
      srtpCipher?.replaceFirst(RegExp(r'^SRTP_'), ''),
    );
    final encryptionStatus =
        certificateMismatch || failedSelectedDtls || selectedPlaintext
        ? 'failed'
        : connectionState == 'connected' &&
              dtlsState == 'connected' &&
              dtlsCipher != null &&
              dtlsCipher.trim().isNotEmpty &&
              encryptedSrtp &&
              certificatesMatch
        ? 'confirmed'
        : connectionState == 'new' || connectionState == 'connecting'
        ? 'waiting'
        : 'unavailable';
    const directTypes = ['host', 'srflx', 'prflx'];
    return ConnectionEvidence({
      'schemaVersion': 1,
      'sampledAt': (sampledAt ?? DateTime.now()).toUtc().toIso8601String(),
      'source': 'WebRTC statistics; not a packet capture',
      'connectionState': connectionState,
      'iceState': iceState,
      'selectedPairId': pair?['type'] == 'candidate-pair'
          ? _text(pair?['id'])
          : null,
      'selectedTransportCount': selectors.length,
      'selectionSource': selectors.length == 1 && pair != null
          ? 'transport.selectedCandidatePairId'
          : 'unavailable',
      'encryptionStatus': encryptionStatus,
      'certificateStatus': certificateMismatch
          ? 'mismatch'
          : certificatesMatch
          ? 'matched'
          : 'unavailable',
      'localCertificateFingerprint': localFingerprint,
      'remoteCertificateFingerprint': remoteFingerprint,
      'direct':
          connectionState == 'connected' &&
          pair?['state'] == 'succeeded' &&
          directTypes.contains(local?['candidateType']) &&
          directTypes.contains(remote?['candidateType']),
      'relayed': selectedRelay,
      'local': local,
      'remote': remote,
      for (final key in ['dtlsState', 'dtlsCipher', 'srtpCipher'])
        key: _text(transport?[key]),
      for (final key in [
        'bytesSent',
        'bytesReceived',
        'packetsSent',
        'packetsReceived',
      ])
        key: _number(pair?[key]),
      'rttSeconds': _number(pair?['currentRoundTripTime']),
      'configuredServers': configuredServers
          .where((s) => s.startsWith('stun:') || s.startsWith('stuns:'))
          .map(_text)
          .toList(),
      'candidates': reports
          .where(
            (r) => ['local-candidate', 'remote-candidate'].contains(r['type']),
          )
          .take(128)
          .map(
            (r) => {
              ...?endpoint(r),
              'side': r['type'] == 'local-candidate' ? 'local' : 'remote',
            },
          )
          .toList(),
      'pairs': reports
          .where((r) => r['type'] == 'candidate-pair')
          .take(128)
          .map(
            (r) => {
              'id': _text(r['id']),
              'state': _text(r['state']),
              'selected': selectors.any(
                (t) => t['selectedCandidatePairId'] == r['id'],
              ),
              'nominated': r['nominated'] == true,
              'local': endpoint(byId[r['localCandidateId']]),
              'remote': endpoint(byId[r['remoteCandidateId']]),
              for (final key in [
                'requestsSent',
                'requestsReceived',
                'responsesSent',
                'responsesReceived',
                'bytesSent',
                'bytesReceived',
                'timestamp',
              ])
                key: _number(r[key]),
            },
          )
          .toList(),
      'media': reports
          .where(
            (r) =>
                ['inbound-rtp', 'outbound-rtp'].contains(r['type']) &&
                r['isRemote'] != true,
          )
          .map(
            (r) => {
              'id': _text(r['id']),
              'direction': r['type'] == 'inbound-rtp' ? 'incoming' : 'outgoing',
              'kind': _text(r['kind'] ?? r['mediaType']),
              'packets': _number(r['packetsReceived'] ?? r['packetsSent']),
              'bytes': _number(r['bytesReceived'] ?? r['bytesSent']),
              'packetsLost': _number(r['packetsLost']),
              'timestamp': _number(r['timestamp']),
            },
          )
          .toList(),
    });
  }
}
