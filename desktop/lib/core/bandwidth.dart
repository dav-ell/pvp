class BandwidthRate {
  final double up, down;
  final DateTime at;
  BandwidthRate(this.up, this.down, this.at);
}

class BandwidthMeter {
  Map<String, dynamic>? _previous;
  BandwidthRate? rate;
  void sample(List<Map<String, dynamic>> reports, {DateTime? now}) {
    final at = now ?? DateTime.now();
    var rows = reports
        .where(
          (r) =>
              r['type'] == 'transport' &&
              r['bytesSent'] is num &&
              r['bytesReceived'] is num,
        )
        .toList();
    if (rows.isEmpty) {
      rows = reports
          .where(
            (r) =>
                r['type'] == 'candidate-pair' &&
                r['state'] == 'succeeded' &&
                (r['selected'] == true || r['nominated'] == true) &&
                r['bytesSent'] is num &&
                r['bytesReceived'] is num,
          )
          .toList();
    }
    final ids = rows.map((r) => '${r['id']}').toList()..sort();
    final sent = rows.fold<double>(
      0,
      (n, r) => n + (r['bytesSent'] as num).toDouble(),
    );
    final received = rows.fold<double>(
      0,
      (n, r) => n + (r['bytesReceived'] as num).toDouble(),
    );
    final prev = _previous;
    final elapsed = prev == null
        ? 0
        : at.difference(prev['at'] as DateTime).inMilliseconds;
    rate =
        rows.isNotEmpty &&
            prev != null &&
            prev['key'] == ids.join('/') &&
            elapsed > 0 &&
            elapsed < 4000 &&
            sent >= prev['sent'] &&
            received >= prev['received']
        ? BandwidthRate(
            (sent - prev['sent']) * 8 / elapsed,
            (received - prev['received']) * 8 / elapsed,
            at,
          )
        : null;
    _previous = rows.isEmpty
        ? null
        : {'key': ids.join('/'), 'sent': sent, 'received': received, 'at': at};
  }
}

String bandwidthLabel(Iterable<BandwidthRate?> rates, {DateTime? now}) {
  final values = rates.toList(), at = now ?? DateTime.now();
  if (values.isEmpty ||
      values.any(
        (r) => r == null || at.difference(r.at).inMilliseconds >= 4000,
      )) {
    return 'Your bandwidth · measuring…';
  }
  final up = values.fold<double>(0, (n, r) => n + r!.up);
  final down = values.fold<double>(0, (n, r) => n + r!.down);
  String fmt(double n) =>
      n >= 1000 ? '${(n / 1000).toStringAsFixed(2)} Mbps' : '${n.round()} Kbps';
  return 'You · ↓ ${fmt(down)} · ↑ ${fmt(up)} · ~${((up + down) * 60 / 8000).toStringAsFixed(1)} MB/min';
}

class StreamCaps {
  int? camera, screen;
  Map<String, dynamic> toJson() => {'camera': camera, 'screen': screen};
  bool get explicit => camera != null || screen != null;
  static StreamCaps? parse(dynamic value) {
    if (value is! Map) return null;
    for (final key in ['camera', 'screen']) {
      if (!value.containsKey(key)) return null;
      final n = value[key];
      if (n != null && (n is! int || n < 32 || n > 8000)) return null;
    }
    return StreamCaps()
      ..camera = value['camera']
      ..screen = value['screen'];
  }
}

class ConnectionCaps {
  final receive = StreamCaps(), send = StreamCaps();
}

int videoCap(
  int automatic,
  StreamCaps sent,
  StreamCaps requested,
  bool sharing,
) {
  final remote = sharing ? requested.screen : requested.camera;
  final local = (sharing ? sent.screen : sent.camera) ?? remote ?? automatic;
  return remote != null && remote < local ? remote : local;
}
