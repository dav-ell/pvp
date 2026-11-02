import 'motion.dart';
import 'package:flutter/material.dart';
import '../core/bandwidth.dart';

class BandwidthControls extends StatelessWidget {
  final ConnectionCaps caps;
  final bool supported;
  final Future<void> Function() change;
  const BandwidthControls({
    super.key,
    required this.caps,
    required this.supported,
    required this.change,
  });
  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      const Text(
        'Video bandwidth for this connection',
        style: TextStyle(fontWeight: FontWeight.w600),
      ),
      const Text(
        'Separate camera and screen share limits, for this call. Audio and network overhead are additional. High limits do not guarantee higher quality.',
      ),
      for (final direction in ['receive', 'send'])
        for (final source in ['camera', 'screen'])
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 8),
            child: _control(context, direction, source),
          ),
      Text(
        supported
            ? 'Receive limits supported by this participant.'
            : 'Waiting for receive-limit support. Older clients may not honor receive limits.',
      ),
    ],
  );
  Widget _control(BuildContext context, String direction, String source) {
    final values = direction == 'receive' ? caps.receive : caps.send;
    final value = source == 'camera' ? values.camera : values.screen;
    final label =
        '${direction == 'receive' ? 'Receive their' : 'Send your'} ${source == 'camera' ? 'camera' : 'screen share'}';
    final choices = <int?, String>{
      null: 'Automatic',
      64: 'Super low · 64 Kbps',
      400: 'Low · 400 Kbps',
      1800: 'Balanced · 1.8 Mbps',
      4000: 'High · 4 Mbps',
      8000: 'Super high · 8 Mbps',
    };
    if (value != null && !choices.containsKey(value)) {
      choices[value] = '$value Kbps';
    }
    return Row(
      children: [
        Expanded(
          child: DropdownButtonFormField<int>(
            initialValue: value,
            hint: const Text('Automatic'),
            key: ValueKey('$direction/$source/$value'),
            decoration: InputDecoration(labelText: label),
            items: choices.entries
                .map(
                  (e) =>
                      DropdownMenuItem<int>(value: e.key, child: Text(e.value)),
                )
                .toList(),
            onChanged: (n) async {
              if (source == 'camera') {
                values.camera = n;
              } else {
                values.screen = n;
              }
              await change();
            },
          ),
        ),
        TextButton(
          onPressed: () async {
            var text = '${value ?? 400}';
            final n = await showPvpDialog<int>(
              context: context,
              builder: (context) => AlertDialog(
                title: Text('$label · Kbps'),
                content: TextFormField(
                  initialValue: text,
                  onChanged: (v) => text = v,
                  keyboardType: TextInputType.number,
                  autofocus: true,
                  decoration: const InputDecoration(helperText: '32–8000 Kbps'),
                ),
                actions: [
                  TextButton(
                    onPressed: () => Navigator.pop(context),
                    child: const Text('Cancel'),
                  ),
                  FilledButton(
                    onPressed: () {
                      final n = int.tryParse(text);
                      if (n != null && n >= 32 && n <= 8000) {
                        Navigator.pop(context, n);
                      }
                    },
                    child: const Text('Apply'),
                  ),
                ],
              ),
            );
            if (n == null) return;
            if (source == 'camera') {
              values.camera = n;
            } else {
              values.screen = n;
            }
            await change();
          },
          child: const Text('Custom'),
        ),
      ],
    );
  }
}
