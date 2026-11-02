import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/bandwidth.dart';

void main() {
  List<Map<String, dynamic>> reports(
    int sent,
    int received, [
    String id = 't',
  ]) => [
    {
      'id': id,
      'type': 'transport',
      'bytesSent': sent,
      'bytesReceived': received,
    },
    {
      'id': 'p',
      'type': 'candidate-pair',
      'state': 'succeeded',
      'nominated': true,
      'bytesSent': sent,
      'bytesReceived': received,
    },
  ];
  test('transport rates include both directions once and expire', () {
    final m = BandwidthMeter(), start = DateTime(2026);
    m.sample(reports(100, 200), now: start);
    expect(m.rate, isNull);
    m.sample(reports(1100, 2200), now: start.add(const Duration(seconds: 1)));
    expect(m.rate!.up, 8);
    expect(m.rate!.down, 16);
    expect(
      bandwidthLabel([
        m.rate,
        m.rate,
      ], now: start.add(const Duration(seconds: 1))),
      contains('↓ 32 Kbps · ↑ 16 Kbps · ~0.4 MB/min'),
    );
    expect(
      bandwidthLabel([m.rate], now: start.add(const Duration(seconds: 5))),
      contains('measuring'),
    );
    m.sample(reports(0, 0), now: start.add(const Duration(seconds: 2)));
    expect(m.rate, isNull);
    m.sample(
      reports(100, 200, 'other'),
      now: start.add(const Duration(seconds: 3)),
    );
    expect(m.rate, isNull);
  });
  test('remote caps validate and apply to the correct source', () {
    expect(StreamCaps.parse({'camera': -1, 'screen': null}), isNull);
    expect(StreamCaps.parse({'camera': '64', 'screen': null}), isNull);
    expect(StreamCaps.parse({'camera': 64}), isNull);
    final caps = StreamCaps.parse({'camera': 64, 'screen': 8000})!;
    final requested = StreamCaps.parse({'camera': 400, 'screen': 4000})!;
    expect(videoCap(1800, caps, requested, false), 64);
    expect(videoCap(1800, caps, requested, true), 4000);
    expect(videoCap(1800, StreamCaps(), StreamCaps(), false), 1800);
  });
}
