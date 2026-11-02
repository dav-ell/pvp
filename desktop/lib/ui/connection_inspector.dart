import 'polish.dart';
import 'bandwidth_controls.dart';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../core/controller.dart';
import '../core/connection_evidence.dart';

class ConnectionInspector extends StatelessWidget {
  final PvpController c;
  const ConnectionInspector({super.key, required this.c});

  Map<String, dynamic> report() => {
    'schemaVersion': 1,
    'exportedAt': DateTime.now().toUtc().toIso8601String(),
    'client': 'PVP for Mac',
    'notice':
        'App-reported observations, not an independent packet capture. Contains network addresses. No credentials or media.',
    'signaling': {
      'service': c.api.address,
      'connected': c.online,
      'socket': c.online ? c.api.signalingSocket : null,
    },
    'media': c.busy ? c.media.evidence?.data : null,
    'events': c.busy ? c.media.networkEvents : [],
  };

  @override
  Widget build(BuildContext context) => Dialog(
    child: SizedBox(
      width: 900,
      height: 700,
      child: ListenableBuilder(
        listenable: c,
        builder: (context, _) {
          final evidence = c.busy ? c.media.evidence : null;
          final d = evidence?.data ?? <String, dynamic>{};
          final socket = c.online ? c.api.signalingSocket : null;
          final mediaCommand = mediaCaptureCommand(evidence);
          final signalingCommand = captureCommand(
            socket?['remote'] as Map<String, dynamic>?,
          );
          return Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Expanded(
                      child: Text(
                        'Connection info & bandwidth',
                        style: TextStyle(
                          fontSize: 23,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                    IconButton(
                      tooltip: 'Close inspector',
                      onPressed: () => Navigator.pop(context),
                      icon: const PvpIcon(Icons.close),
                    ),
                  ],
                ),
                const Text(
                  'Live observations from this device. Independently verify the endpoints with tcpdump.',
                ),
                const SizedBox(height: 16),
                Expanded(
                  child: SingleChildScrollView(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        if (c.busy) ...[
                          _text(c.media.bandwidth),
                          BandwidthControls(
                            caps: c.media.connectionCaps,
                            supported: c.media.bandwidthSupported,
                            change: () => c.perform(
                              () => c.media.updateBandwidth(
                                c.preferences.quality,
                              ),
                            ),
                          ),
                        ],
                        _heading(
                          evidence?.direct == true
                              ? 'Direct media path · WebRTC reported'
                              : c.busy
                              ? 'Media path not yet verified'
                              : 'Call ended · media observations cleared',
                        ),
                        _path(
                          'Your media endpoint',
                          evidence?.local,
                          'Peer media endpoint',
                          evidence?.remote,
                          '${d['connectionState'] ?? 'unavailable'} · ${evidence?.local?['protocol'] ?? 'protocol unavailable'}',
                        ),
                        _text(
                          'Selected pair: ${d['selectedPairId'] ?? 'unavailable'} · ${d['selectionSource'] ?? 'unavailable'}',
                        ),
                        _text(
                          'WebRTC statistics sampled at: ${d['sampledAt'] ?? 'unavailable'}',
                        ),
                        _text(
                          'Sent ${d['bytesSent'] ?? 'unavailable'} bytes · received ${d['bytesReceived'] ?? 'unavailable'} bytes',
                        ),
                        _text(
                          'DTLS ${d['dtlsState'] ?? 'unavailable'} · ${d['dtlsCipher'] ?? 'cipher unavailable'} · SRTP ${d['srtpCipher'] ?? 'cipher unavailable'}',
                        ),
                        _text(
                          'Relay policy: disabled. Observed relay: ${evidence == null
                              ? 'unavailable'
                              : evidence.relayed
                              ? 'yes — rejected'
                              : evidence.direct
                              ? 'none in selected pair'
                              : 'path not verified'}.',
                        ),
                        _heading('Signaling · control connection'),
                        _text(
                          '${c.api.address} · ${c.online ? 'connected' : 'disconnected'}',
                        ),
                        _path(
                          'Local signaling socket',
                          socket?['local'] as Map<String, dynamic>?,
                          'Service signaling socket',
                          socket?['remote'] as Map<String, dynamic>?,
                          'TCP · live dart:io socket',
                        ),
                        _text(
                          'Socket established at: ${socket?['sampledAt'] ?? 'unavailable'}. Signaling stays open for presence and call control.',
                        ),
                        _heading('STUN discovery and ICE checks'),
                        _text(
                          'Configured STUN URLs (configuration, not captured packets): ${(d['configuredServers'] as List? ?? []).join(', ')}',
                        ),
                        for (final candidate in d['candidates'] as List? ?? [])
                          _text(
                            '${candidate['side']} · ${candidate['candidateType'] ?? 'type unavailable'} · ${endpointLabel(Map<String, dynamic>.from(candidate))} · ${candidate['protocol'] ?? 'protocol unavailable'}${candidate['url'] == null ? '' : ' · reported server: ${candidate['url']}'}',
                          ),
                        for (final pair in d['pairs'] as List? ?? [])
                          _text(
                            '${pair['selected'] ? 'SELECTED' : 'TESTED'} · ${pair['state'] ?? 'unavailable'} · ${endpointLabel(pair['local'] as Map<String, dynamic>?)} ↔ ${endpointLabel(pair['remote'] as Map<String, dynamic>?)}\nSTUN checks sent ${pair['requestsSent'] ?? 'unavailable'}, received ${pair['requestsReceived'] ?? 'unavailable'}; responses sent ${pair['responsesSent'] ?? 'unavailable'}, received ${pair['responsesReceived'] ?? 'unavailable'}',
                          ),
                        _text(
                          'These are WebRTC observations and counters, not individual captured datagrams. Hidden fields remain unavailable.',
                        ),
                        _heading('Incoming and outgoing media'),
                        for (final row in d['media'] as List? ?? [])
                          _text(
                            '${row['direction']} ${row['kind'] ?? 'media'} · ${row['packets'] ?? 'unavailable'} RTP packets · ${row['bytes'] ?? 'unavailable'} bytes${row['packetsLost'] == null ? '' : ' · lost ${row['packetsLost']}'}',
                          ),
                        _heading('Verify independently'),
                        _text(
                          'Run these commands in Terminal. tcpdump may request administrator authentication; PVP does not run it. Stop with Control-C. The filter matches both directions at the observed remote endpoint, or the local host socket if the peer IP is hidden.',
                        ),
                        if (mediaCommand != null)
                          _command('Media', mediaCommand)
                        else
                          _text(
                            'Media filter unavailable: waiting for a literal peer IP, port and protocol.',
                          ),
                        if (signalingCommand != null)
                          _command('Signaling', signalingCommand),
                        _text(
                          'Local capture shows addresses before router NAT. A public mapped local address/port can differ from the socket on your Mac. Select the relevant interface if a VPN hides traffic; use tcpdump -D to list interfaces. Counter totals may differ because RTP statistics and captures count different layers.',
                        ),
                        _heading('Timeline · events, not packets'),
                        for (final event
                            in c.busy
                                ? c.media.networkEvents.reversed
                                : <Map<String, String>>[])
                          _text(
                            '${event['at']} · ${event['source']}\n${event['detail']}',
                          ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                Row(
                  children: [
                    const Expanded(
                      child: Text(
                        'Reports contain IP addresses. Kept in memory; export only when you choose.',
                        style: TextStyle(fontSize: 12),
                      ),
                    ),
                    TextButton.icon(
                      onPressed: () async {
                        try {
                          await c.host.invoke(
                            'saveConnectionReport',
                            const JsonEncoder.withIndent(
                              '  ',
                            ).convert(report()),
                          );
                        } catch (e) {
                          if (context.mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                content: Text(
                                  'Could not save the connection report.',
                                ),
                              ),
                            );
                          }
                        }
                      },
                      icon: const PvpIcon(Icons.save_alt),
                      label: const Text('Save report'),
                    ),
                  ],
                ),
              ],
            ),
          );
        },
      ),
    ),
  );

  Widget _heading(String value) => Padding(
    padding: const EdgeInsets.only(top: 18, bottom: 8),
    child: Text(
      value,
      style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
    ),
  );
  Widget _text(String value) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 4),
    child: SelectableText(
      value,
      style: const TextStyle(fontSize: 12, height: 1.5),
    ),
  );
  Widget _endpoint(String label, Map<String, dynamic>? value) => Expanded(
    child: Builder(
      builder: (context) => Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surfaceContainerLow,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(label, style: const TextStyle(fontSize: 11)),
            const SizedBox(height: 8),
            SelectableText(
              endpointLabel(value),
              style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
            ),
            _text(value?['candidateType'] as String? ?? 'Socket endpoint'),
          ],
        ),
      ),
    ),
  );
  Widget _path(
    String left,
    Map<String, dynamic>? local,
    String right,
    Map<String, dynamic>? remote,
    String status,
  ) => Column(
    children: [
      Row(
        children: [
          _endpoint(left, local),
          const Padding(
            padding: EdgeInsets.all(12),
            child: PvpIcon(Icons.swap_horiz),
          ),
          _endpoint(right, remote),
        ],
      ),
      _text(status),
    ],
  );
  Widget _command(String label, String value) => Row(
    children: [
      Expanded(child: _text('$label\n$value')),
      IconButton(
        tooltip: 'Copy $label tcpdump command',
        onPressed: () => Clipboard.setData(ClipboardData(text: value)),
        icon: const PvpIcon(Icons.copy),
      ),
    ],
  );
}
