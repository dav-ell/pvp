import 'dart:convert';

class Person {
  final String id, username, name;
  final String status;
  final bool online;
  final String? voiceRoom;
  final int voiceParticipants;
  bool get isGuest => username.startsWith('~');
  const Person(
    this.id,
    this.username,
    this.name, {
    this.status = 'accepted',
    this.online = false,
    this.voiceRoom,
    this.voiceParticipants = 0,
  });
  factory Person.fromJson(Map<String, dynamic> j) => Person(
    j['id'],
    j['username'],
    j['display_name'],
    status: j['status'] ?? 'accepted',
    online: j['online'] ?? false,
    voiceRoom: j['voice_room']?['room_id'],
    voiceParticipants: j['voice_room']?['participants'] ?? 0,
  );
  String get initials => name
      .trim()
      .split(RegExp(r'\s+'))
      .take(2)
      .map((s) => s[0])
      .join()
      .toUpperCase();
}

class Quality {
  final String preset;
  final int height, fps, videoKbps, audioKbps;
  const Quality(
    this.preset,
    this.height,
    this.fps,
    this.videoKbps,
    this.audioKbps,
  );
  static const saver = Quality('saver', 360, 15, 400, 24);
  static const balanced = Quality('balanced', 720, 30, 1800, 64);
  static const studio = Quality('studio', 1080, 30, 4000, 96);
  static const presets = [saver, balanced, studio];
  factory Quality.fromJson(Map<String, dynamic> j) => Quality(
    j['preset'] ?? 'custom',
    [360, 480, 720, 1080].contains(j['height']) ? j['height'] : 720,
    [15, 24, 30, 60].contains(j['fps']) ? j['fps'] : 30,
    (j['videoKbps'] as num? ?? 1800).toInt().clamp(128, 8000),
    [24, 48, 64, 96].contains(j['audioKbps']) ? j['audioKbps'] : 64,
  );
  Map<String, dynamic> toJson() => {
    'preset': preset,
    'height': height,
    'fps': fps,
    'videoKbps': videoKbps,
    'audioKbps': audioKbps,
  };
  String get label => '${height}p · $fps fps';
  String get bandwidth =>
      '${((videoKbps + audioKbps) / 1000).toStringAsFixed(2)} Mbps';
  // Rough outbound payload estimate; transport overhead adds a little more.
  double get megabytesPerMinute => (videoKbps + audioKbps) * 60 / 8000;
}

class Preferences {
  Quality quality;
  String camera, microphone, speaker;
  bool ring, echoCancellation, showControlLabels;
  Preferences({
    this.quality = Quality.balanced,
    this.camera = '',
    this.microphone = '',
    this.speaker = '',
    this.ring = true,
    this.echoCancellation = true,
    this.showControlLabels = false,
  });
  factory Preferences.decode(String? value) {
    try {
      final j = jsonDecode(value ?? '{}') as Map<String, dynamic>;
      return Preferences(
        quality: j['quality'] is Map
            ? Quality.fromJson(Map<String, dynamic>.from(j['quality']))
            : Quality.balanced,
        camera: j['camera'] ?? '',
        microphone: j['microphone'] ?? '',
        speaker: j['speaker'] ?? '',
        ring: j['ring'] ?? true,
        echoCancellation: j['echoCancellation'] != false,
        showControlLabels: j['showControlLabels'] == true,
      );
    } catch (_) {
      return Preferences();
    }
  }
  String encode() => jsonEncode({
    'quality': quality.toJson(),
    'camera': camera,
    'microphone': microphone,
    'speaker': speaker,
    'ring': ring,
    'echoCancellation': echoCancellation,
    'showControlLabels': showControlLabels,
  });
}

class ApiException implements Exception {
  final int status;
  final String message;
  const ApiException(this.status, this.message);
  @override
  String toString() => message;
}

Uri serviceUri(String address) {
  final u = Uri.parse(address.trim());
  if (u.userInfo.isNotEmpty ||
      u.hasQuery ||
      u.hasFragment ||
      (u.path.isNotEmpty && u.path != '/') ||
      u.host.isEmpty ||
      !(u.scheme == 'https' ||
          (u.scheme == 'http' &&
              ['localhost', '127.0.0.1', '::1'].contains(u.host)))) {
    throw const FormatException(
      'Use an HTTPS service address, or HTTP on localhost.',
    );
  }
  return u.replace(path: '');
}
