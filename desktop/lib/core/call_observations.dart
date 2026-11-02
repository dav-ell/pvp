// Local scalar observations only. A reminder never changes track/sender state.
class MutedSpeechObservation {
  DateTime? _started, _lastNotice, _visibleUntil;
  bool visible({DateTime? now}) =>
      _visibleUntil != null && (now ?? DateTime.now()).isBefore(_visibleUntil!);
  void sample({
    required bool muted,
    required bool hasAudioTrack,
    required bool receivingSamples,
    required double level,
    DateTime? now,
  }) {
    final at = now ?? DateTime.now();
    if (!muted ||
        !hasAudioTrack ||
        !receivingSamples ||
        !level.isFinite ||
        level < .04) {
      _started = null;
      if (!muted || !hasAudioTrack) _visibleUntil = null;
      return;
    }
    _started ??= at;
    if (at.difference(_started!).inMilliseconds >= 700 &&
        (_lastNotice == null || at.difference(_lastNotice!).inSeconds >= 20)) {
      _lastNotice = at;
      _visibleUntil = at.add(const Duration(seconds: 5));
    }
  }

  void reset() {
    _started = null;
    _lastNotice = null;
    _visibleUntil = null;
  }
}

class OutgoingMediaStats {
  DateTime? _sampledAt;
  bool _hasOutboundRows = false;
  Map<String, num> _previousVideo = {}, _previousAudio = {};
  String dimensions = '';
  double? videoKbps, audioKbps;
  void sample(List<Map<String, dynamic>> reports, {DateTime? now}) {
    final at = now ?? DateTime.now();
    final rows = reports
        .where((r) => r['type'] == 'outbound-rtp' && r['isRemote'] != true)
        .toList();
    _hasOutboundRows = rows.isNotEmpty;
    Map<String, num> counters(String kind) => {
      for (final r in rows)
        if ((r['kind'] ?? r['mediaType']) == kind &&
            r['bytesSent'] is num &&
            (r['bytesSent'] as num).isFinite &&
            (r['bytesSent'] as num) >= 0)
          '${r['id']}': r['bytesSent'] as num,
    };
    final elapsed = _sampledAt == null
        ? 0
        : at.difference(_sampledAt!).inMilliseconds;
    double? rate(Map<String, num> next, Map<String, num> previous) {
      if (elapsed <= 0 ||
          elapsed >= 4000 ||
          next.isEmpty ||
          next.length != previous.length ||
          next.keys.any(
            (id) => !previous.containsKey(id) || next[id]! < previous[id]!,
          )) {
        return null;
      }
      final bytes = next.entries.fold<num>(
        0,
        (sum, entry) => sum + entry.value - previous[entry.key]!,
      );
      return bytes * 8 / elapsed;
    }

    final video = counters('video'), audio = counters('audio');
    videoKbps = rate(video, _previousVideo);
    audioKbps = rate(audio, _previousAudio);
    _previousVideo = video;
    _previousAudio = audio;
    _sampledAt = at;
    final formats = <String>{};
    for (final row in rows) {
      if ((row['kind'] ?? row['mediaType']) != 'video') continue;
      final width = row['frameWidth'],
          height = row['frameHeight'],
          fps = row['framesPerSecond'];
      if (width is! num ||
          height is! num ||
          !width.isFinite ||
          !height.isFinite ||
          width <= 0 ||
          height <= 0) {
        continue;
      }
      formats.add(
        '${width.round()} × ${height.round()}'
        '${fps is num && fps.isFinite && fps >= 0 ? ' · ${fps.round()} fps' : ''}',
      );
    }
    dimensions = formats.join(' / ');
  }

  bool fresh({DateTime? now}) {
    if (_sampledAt == null || !_hasOutboundRows) return false;
    final age = (now ?? DateTime.now()).difference(_sampledAt!).inMilliseconds;
    return age >= 0 && age < 4000;
  }

  static String formatRate(double? value) => value == null
      ? 'unavailable'
      : value >= 1000
      ? '${(value / 1000).toStringAsFixed(2)} Mbps'
      : '${value.round()} Kbps';
  String summary({required bool videoEnabled, DateTime? now}) {
    if (!fresh(now: now)) return 'Actual sent media unavailable';
    final picture = videoEnabled
        ? dimensions.isEmpty
              ? 'Sent video size unavailable'
              : 'Sent $dimensions'
        : 'Camera off';
    return '$picture · video ${formatRate(videoKbps)}'
        ' · audio ${formatRate(audioKbps)}';
  }
}
