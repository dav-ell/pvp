import 'package:flutter/material.dart';
import '../core/controller.dart';
import 'brand_tokens.dart';
import 'polish.dart';

/// Targets and observations are deliberately separate. Missing stats stay unknown.
class CallDetailsBar extends StatelessWidget {
  final PvpController c;
  final bool group;
  const CallDetailsBar({super.key, required this.c, this.group = false});

  Future<void> proof(BuildContext context) => showDialog<void>(
    context: context,
    builder: (context) => ListenableBuilder(
      listenable: c,
      builder: (context, _) {
        final peers = group
            ? c.group.links.values
                  .map(
                    (link) => (
                      name:
                          c.group.members
                                  .where((m) => m['id'] == link.id)
                                  .firstOrNull?['display_name']
                              as String? ??
                          'Participant',
                      evidence: link.evidence,
                      code: link.code,
                    ),
                  )
                  .toList()
            : [
                (
                  name: c.peer?.name ?? 'Your peer',
                  evidence: c.media.evidence,
                  code: c.media.securityCode,
                ),
              ];
        return AlertDialog(
          title: const Text('Connection proof'),
          content: SizedBox(
            width: 520,
            child: SingleChildScrollView(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Text(
                    'These observations come from the active WebRTC transport. Encryption, a direct route, and a person’s identity are separate claims.',
                    style: TextStyle(height: 1.6),
                  ),
                  const SizedBox(height: 18),
                  if (peers.isEmpty)
                    const Text(
                      'Waiting for a peer connection. No encrypted connection has been confirmed yet.',
                    ),
                  for (final peer in peers) ...[
                    Text(
                      peer.name,
                      style: const TextStyle(fontWeight: FontWeight.w600),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      peer.evidence?.trustSummary ??
                          'Connection evidence unavailable',
                    ),
                    Text(
                      peer.evidence?.certificateStatus ??
                          'Certificate evidence unavailable',
                      style: const TextStyle(fontSize: 12),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      'DTLS: ${peer.evidence?.data['dtlsState'] ?? 'unavailable'} · SRTP: ${peer.evidence?.data['srtpCipher'] ?? 'unavailable'}',
                      style: const TextStyle(fontSize: 12),
                    ),
                    const SizedBox(height: 10),
                    const Text(
                      'Comparison code',
                      style: TextStyle(fontSize: 11),
                    ),
                    SelectableText(
                      peer.code.isEmpty ? 'Not available yet' : peer.code,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 15,
                      ),
                    ),
                    const Divider(height: 25),
                  ],
                  const Text(
                    'Compare the matching code with this participant through a separate trusted channel. A matching code binds the current peer certificates; PVP has not independently verified the person. The code can change when the peer connection is replaced.',
                    style: TextStyle(fontSize: 12, height: 1.6),
                  ),
                  const SizedBox(height: 12),
                  const Text(
                    'Direct calls expose your IP address to peers. Other participants can record outside the app.',
                    style: TextStyle(fontSize: 12, height: 1.6),
                  ),
                ],
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Back to room'),
            ),
          ],
        );
      },
    ),
  );

  @override
  Widget build(BuildContext context) {
    final media = group ? c.group.media : c.media;
    final quality = c.preferences.quality;
    final preset = switch (quality.preset) {
      'saver' => 'Data saver',
      'studio' => 'High quality',
      'balanced' => 'Balanced',
      _ => 'Custom',
    };
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Column(
        children: [
          Wrap(
            alignment: WrapAlignment.center,
            crossAxisAlignment: WrapCrossAlignment.center,
            spacing: 13,
            runSpacing: 4,
            children: [
              Text(
                '$preset · target ${quality.label}',
                style: const TextStyle(
                  color: PvpBrandColors.stageMuted,
                  fontSize: 11,
                ),
              ),
              TextButton.icon(
                onPressed: () => proof(context),
                style: TextButton.styleFrom(
                  foregroundColor: PvpBrandColors.accent,
                  padding: const EdgeInsets.symmetric(horizontal: 8),
                  minimumSize: const Size(40, 32),
                ),
                icon: const PvpGlyph('link', size: 14),
                label: Text(
                  group
                      ? 'Connection proof · ${c.group.links.length} peers'
                      : c.media.evidence?.trustSummary ??
                            'Connection proof unavailable',
                  style: const TextStyle(fontSize: 11),
                ),
              ),
            ],
          ),
          Text(
            media.outgoingSummary,
            textAlign: TextAlign.center,
            style: const TextStyle(
              color: PvpBrandColors.stageMuted,
              fontSize: 10,
            ),
          ),
          Text(
            media.limitsSummary,
            textAlign: TextAlign.center,
            style: const TextStyle(
              color: PvpBrandColors.stageMuted,
              fontSize: 10,
            ),
          ),
          if (group &&
              c.group.links.values.any((link) => link.forwardedBytes > 0))
            const Text(
              'RTP figures describe your media; forwarded video from others is additional.',
              textAlign: TextAlign.center,
              style: TextStyle(color: PvpBrandColors.stageMuted, fontSize: 10),
            ),
          if (media.microphoneNotice.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 5),
              child: Text(
                media.microphoneNotice,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  color: PvpBrandColors.accent,
                  fontSize: 12,
                ),
              ),
            ),
          if (media.mutedSpeechDetected && (!group || !c.group.moderatorMuted))
            const Padding(
              padding: EdgeInsets.only(top: 6),
              child: Text(
                'Your microphone is muted.',
                style: TextStyle(color: PvpBrandColors.accent, fontSize: 12),
              ),
            ),
        ],
      ),
    );
  }
}
