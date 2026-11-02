import 'dart:convert';
import 'package:crypto/crypto.dart';

bool isRelay(String text) =>
    RegExp(r'\btyp\s+relay\b', caseSensitive: false).hasMatch(text);

void requireEncryptedSdp(String sdp) {
  if (sdp.length > 48000 ||
      !sdp.startsWith('v=0') ||
      sdp.contains('\x00') ||
      isRelay(sdp)) {
    throw StateError('Invalid encrypted peer negotiation.');
  }
  bool inherited = false;
  final sections = <List<bool>>[];
  for (final line in sdp.split(RegExp(r'\r?\n')).map((s) => s.trim())) {
    if (line.length > 4096 || line.startsWith('a=crypto:')) {
      throw StateError('Unsupported peer encryption.');
    }
    if (line.startsWith('m=')) {
      final fields = line.substring(2).split(RegExp(r'\s+'));
      if (fields.length < 4 || sections.length >= 8) {
        throw StateError('Invalid media negotiation.');
      }
      final port = int.tryParse(fields[1]);
      final valid = ['audio', 'video'].contains(fields[0])
          ? fields[2] == 'UDP/TLS/RTP/SAVPF'
          : fields[0] == 'application' && fields[2] == 'UDP/DTLS/SCTP';
      if (!valid || port == null || port < 0 || port > 65535) {
        throw StateError('An encrypted WebRTC transport is required.');
      }
      sections.add([port != 0, inherited]);
    } else if (line.startsWith('a=fingerprint:')) {
      if (!RegExp(
        r'^a=fingerprint:sha-256 (?:[0-9a-f]{2}:){31}[0-9a-f]{2}$',
        caseSensitive: false,
      ).hasMatch(line)) {
        throw StateError('Invalid peer certificate.');
      }
      if (sections.isEmpty) {
        inherited = true;
      } else {
        sections.last[1] = true;
      }
    }
  }
  if (!sections.any((s) => s[0]) || sections.any((s) => s[0] && !s[1])) {
    throw StateError('Missing encrypted peer certificate.');
  }
}

void requireCandidate(Map<String, dynamic> c) {
  final text = c['candidate'], mid = c['sdpMid'], index = c['sdpMLineIndex'];
  if (text is! String ||
      text.length > 2048 ||
      text.contains(RegExp(r'[\r\n\x00]')) ||
      isRelay(text) ||
      !RegExp(
        r'^candidate:\S+ [12] (?:udp|tcp) \d+ \S+ \d+ typ (?:host|srflx|prflx)(?:\s|$)',
        caseSensitive: false,
      ).hasMatch(text) ||
      (mid != null && (mid is! String || mid.length > 64)) ||
      (index != null && (index is! int || index < 0 || index >= 8)) ||
      (mid == null && index == null)) {
    throw StateError('Invalid direct peer candidate.');
  }
}

String safetyCode(String local, String remote) {
  // Validate each endpoint independently before deriving the established code.
  requireEncryptedSdp(local);
  requireEncryptedSdp(remote);
  final localValues = certificateFingerprints(local),
      remoteValues = certificateFingerprints(remote);
  if (localValues.length != 1 || remoteValues.length != 1) {
    throw StateError(
      'A comparison code requires one certificate per endpoint.',
    );
  }
  final values = {...localValues, ...remoteValues}.toList()..sort();
  if (values.length < 2) throw StateError('Missing peer certificates.');
  final digest = sha256
      .convert(utf8.encode('PVP-call-v1\n${values.join('\n')}'))
      .toString()
      .substring(0, 24);
  return RegExp(r'.{4}').allMatches(digest).map((m) => m[0]).join(' ');
}

Set<String> certificateFingerprints(String sdp) {
  final pattern = RegExp(
    r'^a=fingerprint:sha-256 ((?:[0-9a-f]{2}:){31}[0-9a-f]{2})\r?$',
    multiLine: true,
    caseSensitive: false,
  );
  return pattern
      .allMatches(sdp)
      .map((m) => m[1]!.replaceAll(':', '').toLowerCase())
      .toSet();
}
