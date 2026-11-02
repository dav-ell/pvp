import 'polish.dart';
import 'brand_tokens.dart';
import 'call_details.dart';
import 'app.dart' show audioVideoDialog;
import 'package:flutter/services.dart';
import 'bandwidth_controls.dart';
import '../core/bandwidth.dart';
import 'meeting_chat.dart';
import 'meetings.dart';
import 'motion.dart';
import 'dart:convert';
import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import '../core/controller.dart';
import '../core/connection_evidence.dart';

Future<void> groupPicker(
  BuildContext context,
  PvpController c, {
  bool adding = false,
}) async {
  final selected = <String>{};
  final friends = c.accepted
      .where((f) => !c.group.members.any((m) => m['id'] == f.id))
      .toList();
  final ids = await showPvpDialog<List<String>>(
    context: context,
    builder: (context) => StatefulBuilder(
      builder: (context, setState) => AlertDialog(
        title: Text(adding ? 'Invite friends' : 'Start a group call'),
        content: SizedBox(
          width: 440,
          height: 360,
          child: Column(
            children: [
              const Text(
                'Up to 16 people. Invitations show the participants before opening your microphone. Turn on video later if you want.',
              ),
              const SizedBox(height: 12),
              Expanded(
                child: ListView(
                  children: [
                    for (final f in friends)
                      CheckboxListTile(
                        value: selected.contains(f.id),
                        title: Text(f.name),
                        subtitle: Text('@${f.username}'),
                        onChanged: (v) => setState(() {
                          if (v == true) {
                            if (selected.length <
                                (adding ? 16 - c.group.members.length : 15)) {
                              selected.add(f.id);
                            }
                          } else {
                            selected.remove(f.id);
                          }
                        }),
                      ),
                  ],
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: selected.isEmpty
                ? null
                : () => Navigator.pop(context, selected.toList()),
            child: Text(adding ? 'Invite' : 'Start call'),
          ),
        ],
      ),
    ),
  );
  if (ids == null) return;
  await c.perform(() async {
    if (adding) {
      for (final id in ids) {
        c.group.send({
          'type': 'room-invite',
          'room_id': c.group.id,
          'peer_id': id,
        });
      }
    } else {
      await c.group.start(ids);
    }
  });
}

class GroupCallView extends StatelessWidget {
  final PvpController c;
  final VoidCallback? onBack;
  const GroupCallView({super.key, required this.c, this.onBack});
  Future<void> maximize(BuildContext context, String id, String name) async {
    final g = c.group;
    g.focus(id);
    try {
      await showPvpDialog<void>(
        context: context,
        useSafeArea: false,
        builder: (context) => Dialog.fullscreen(
          child: Scaffold(
            backgroundColor: PvpBrandColors.stage,
            appBar: AppBar(
              title: Text(name),
              leading: IconButton(
                tooltip: 'Restore',
                icon: const PvpIcon(Icons.fullscreen_exit),
                onPressed: () => Navigator.pop(context),
              ),
            ),
            body: ListenableBuilder(
              listenable: g,
              builder: (context, _) => tile(
                context,
                name,
                id == c.user?.id ? g.media.local : g.links[id]?.renderer,
                mirror: id == c.user?.id && !g.media.screenSharing,
                paused: id == c.user?.id
                    ? g.media.cameraOff
                    : g.links[id]?.state['paused'] == true,
              ),
            ),
          ),
        ),
      );
    } finally {
      g.focus(null);
    }
  }

  Future<void> share(BuildContext context) async {
    final g = c.group;
    if (g.media.screenChanging) return;
    await c.perform(() async {
      if (g.media.screenSharing) {
        await g.media.stopScreenShare();
        return;
      }
      final id = g.id;
      if (await c.host.invoke<bool>('screenCapturePermission') == false) {
        await c.host.invoke('openScreenPrivacy');
        throw StateError(
          'Allow PVP in Screen Recording settings, then try again.',
        );
      }
      final sources = await desktopCapturer.getSources(
        types: [SourceType.Screen, SourceType.Window],
      );
      if (!context.mounted || g.id != id || !g.joined) return;
      final source = await showPvpDialog<DesktopCapturerSource>(
        context: context,
        builder: (context) => SimpleDialog(
          title: const Text('Choose what to share'),
          children: [
            for (final s in sources)
              SimpleDialogOption(
                onPressed: () => Navigator.pop(context, s),
                child: Text(s.name),
              ),
            SimpleDialogOption(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel'),
            ),
          ],
        ),
      );
      if (source != null && g.id == id && g.joined) {
        await g.media.startScreenShare(
          source.id,
          source.name,
          c.preferences,
          sourceType: source.type,
        );
      }
    });
  }

  Future<void> inspect(BuildContext context, String id) async {
    final g = c.group;
    await showPvpDialog(
      context: context,
      builder: (context) => ListenableBuilder(
        listenable: g,
        builder: (context, _) {
          final link = g.links[id], e = link?.evidence?.data;
          final local = e?['local'] as Map?, remote = e?['remote'] as Map?;
          String endpoint(Map? m) =>
              '${m?['address'] ?? 'Address unavailable'}:${m?['port'] ?? 'port unavailable'}';
          return AlertDialog(
            title: const Text('Connection info & bandwidth'),
            content: SizedBox(
              width: 580,
              child: SingleChildScrollView(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      link?.evidence?.direct == true &&
                              link?.status.toLowerCase() == 'connected' &&
                              DateTime.now()
                                      .difference(
                                        DateTime.tryParse(
                                              e?['sampledAt'] ?? '',
                                            ) ??
                                            DateTime(1970),
                                      )
                                      .inSeconds <
                                  4
                          ? 'Direct peer connection'
                          : 'Route unverified',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    Text(bandwidthLabel([link?.meter.rate])),
                    if (link != null)
                      BandwidthControls(
                        caps: link.caps,
                        supported: link.bandwidthSupported,
                        change: () => c.perform(() async {
                          await g.updateBandwidth();
                        }),
                      ),
                    const Text('Connection details reported by WebRTC.'),
                    const SizedBox(height: 20),
                    for (final row in <String, String>{
                      'Observed': '${e?['sampledAt'] ?? 'Unavailable'}',
                      'Local endpoint': endpoint(local),
                      'Remote endpoint': endpoint(remote),
                      'Encryption': '${e?['dtlsState'] ?? 'Unavailable'}',
                      'DTLS cipher': '${e?['dtlsCipher'] ?? 'Unavailable'}',
                      'SRTP cipher': '${e?['srtpCipher'] ?? 'Unavailable'}',
                      'Bytes sent / received':
                          '${e?['bytesSent'] ?? '—'} / ${e?['bytesReceived'] ?? '—'}',
                      'Certificate code': link?.code ?? 'Unavailable',
                      'Video forwarded': '${link?.forwardedBytes ?? 0} bytes',
                    }.entries)
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 8),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              row.key,
                              style: Theme.of(context).textTheme.labelMedium,
                            ),
                            const SizedBox(height: 4),
                            SelectableText(row.value),
                          ],
                        ),
                      ),
                    const Divider(height: 24),
                    ExpansionTile(
                      tilePadding: EdgeInsets.zero,
                      title: const Text('Packet capture command'),
                      subtitle: const Text('For advanced troubleshooting'),
                      children: [
                        SelectableText(
                          mediaCaptureCommand(link?.evidence) ??
                              'Capture filter unavailable.',
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 12,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('Close'),
              ),
              FilledButton(
                onPressed: () => c.perform(() async {
                  await g.sample();
                  await c.host.invoke(
                    'saveConnectionReport',
                    jsonEncode(g.report()),
                  );
                }),
                child: const Text('Export all peers'),
              ),
            ],
          );
        },
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final g = c.group;
    if (!g.joined) {
      return Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 560),
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const PvpSignal(
                  child: SizedBox(
                    width: 72,
                    height: 72,
                    child: PvpIcon(
                      Icons.people_outline,
                      size: 36,
                      color: PvpMotion.signal,
                    ),
                  ),
                ),
                const SizedBox(height: 24),
                Text(
                  g.room == null
                      ? 'Preparing group call…'
                      : 'Group call invitation',
                  style: Theme.of(context).textTheme.headlineMedium,
                ),
                const SizedBox(height: 20),
                Text(
                  g.members
                      .map(
                        (m) =>
                            '${m['display_name']}${m['joined'] == true ? '' : ' (invited)'}',
                      )
                      .join(', '),
                ),
                const SizedBox(height: 16),
                const Text(
                  'Joining authorizes encrypted connections to these participants, including people outside your friends list. Peers can see your network address.',
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 24),
                if (g.message.isNotEmpty) Text(g.message),
                Wrap(
                  spacing: 12,
                  children: [
                    OutlinedButton(
                      onPressed: () => g.leave(),
                      child: const Text('Decline'),
                    ),
                    FilledButton(
                      onPressed: g.pending || g.room == null
                          ? null
                          : () => c.perform(g.join),
                      child: const Text('Join call'),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      );
    }
    final labels = c.preferences.showControlLabels,
        solo = g.participants.length == 1;
    final connected = g.links.values
        .where(
          (l) =>
              l.pc.connectionState ==
              RTCPeerConnectionState.RTCPeerConnectionStateConnected,
        )
        .length;
    final status = solo
        ? 'Waiting for others'
        : connected < g.participants.length - 1
        ? 'Connecting…'
        : g.awaitingApproval
        ? (g.self?['hand_raised'] == true
              ? 'Hand raised · Waiting for an admin'
              : 'Raise your hand to speak')
        : g.speakingRequired &&
              g.self?['speaking_allowed'] == true &&
              g.media.muted
        ? 'You can unmute and speak now'
        : g.moderatorMuted
        ? 'Muted by admin'
        : g.listening
        ? 'Listening'
        : '';
    return Container(
      color: pvpCanvas,
      padding: const EdgeInsets.fromLTRB(20, 12, 20, 12),
      child: Column(
        children: [
          Row(
            children: [
              if (onBack != null)
                IconButton(
                  tooltip: 'Back to app',
                  onPressed: onBack,
                  icon: const PvpGlyph('chevron-left'),
                ),
              Expanded(
                child: Text(
                  g.personalRoom
                      ? 'Your drop-in call'
                      : g.room?['name'] ??
                            (g.room?['voice'] == true
                                ? 'Drop-in call'
                                : 'Group call'),
                  style: const TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.w600,
                  ),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              TextButton.icon(
                onPressed: () => people(context),
                icon: const PvpGlyph('users-round', size: 19),
                label: Text('${g.participants.length}'),
              ),
              IconButton(
                tooltip: 'Invite',
                onPressed: () => invite(context),
                icon: const PvpGlyph('link'),
              ),
            ],
          ),
          if (status.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(
                status,
                style: const TextStyle(
                  color: PvpBrandColors.stageMuted,
                  fontSize: 14,
                ),
              ),
            ),
          if (g.media.screenSharing)
            Container(
              margin: const EdgeInsets.only(top: 12),
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
              decoration: BoxDecoration(
                color: PvpBrandColors.stageSurface,
                border: Border.all(color: PvpBrandColors.stageMuted),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Row(
                children: [
                  const PvpGlyph('screen-share', size: 20),
                  const SizedBox(width: 10),
                  const Expanded(child: Text('Sharing screen')),
                  TextButton(
                    onPressed: () => c.perform(g.media.stopScreenShare),
                    child: const Text('Stop sharing'),
                  ),
                ],
              ),
            ),
          Expanded(
            child: LayoutBuilder(
              builder: (context, size) {
                final others = g.participants
                    .where((m) => m['id'] != c.user?.id)
                    .toList();
                Widget self() => tile(
                  context,
                  '${c.user?.name ?? 'You'}${solo ? '' : ' · You'}',
                  g.media.local,
                  mirror: !g.media.screenSharing,
                  paused: g.media.cameraOff && !g.media.screenSharing,
                  speaking: !g.media.muted && g.media.microphoneLevel > .025,
                  muted: g.media.muted,
                  maximize: () => maximize(context, c.user!.id, 'Your screen'),
                );
                Widget remote(Map<String, dynamic> m) => KeyedSubtree(
                  key: ValueKey(m['id']),
                  child: PvpArrival(
                    identity: m['id'],
                    child: tile(
                      context,
                      m['display_name'],
                      g.links[m['id']]?.renderer,
                      speaking: g.links[m['id']]?.speaking ?? false,
                      paused: g.links[m['id']]?.state['paused'] != false,
                      muted:
                          m['moderator_muted'] == true ||
                          g.links[m['id']]?.state['muted'] == true,
                      listening: g.links[m['id']]?.state['listening'] == true,
                      maximize: () =>
                          maximize(context, m['id'], m['display_name']),
                    ),
                  ),
                );
                if (solo) {
                  return Padding(
                    padding: const EdgeInsets.symmetric(vertical: 20),
                    child: SingleChildScrollView(
                      child: SizedBox(
                        height: math.max(
                          size.maxHeight - 40,
                          MediaQuery.textScalerOf(context).scale(30) + 100,
                        ),
                        child: self(),
                      ),
                    ),
                  );
                }
                if (others.length == 1 &&
                    (!g.media.cameraOff ||
                        g.media.screenSharing ||
                        g.links[others.first['id']]?.state['paused'] ==
                            false)) {
                  return Stack(
                    fit: StackFit.expand,
                    children: [
                      remote(others.first),
                      ExpandableSelfPreview(
                        key: const ValueKey('room-self-preview'),
                        child: self(),
                      ),
                    ],
                  );
                }
                if (others.length == 1 &&
                    g.media.cameraOff &&
                    g.links[others.first['id']]?.state['paused'] != false) {
                  return SingleChildScrollView(
                    child: SizedBox(
                      height: math.max(
                        size.maxHeight,
                        MediaQuery.textScalerOf(context).scale(30) + 156,
                      ),
                      child: Column(
                        children: [
                          Expanded(child: remote(others.first)),
                          SizedBox(
                            height: 56,
                            child: Row(
                              children: [
                                Text(
                                  '${c.user?.name ?? 'You'} · You',
                                  style: const TextStyle(
                                    color: pvpMuted,
                                    fontSize: 13,
                                  ),
                                ),
                                const Spacer(),
                                PvpGlyph(
                                  g.listening
                                      ? 'headphones'
                                      : g.media.muted
                                      ? 'mic-off'
                                      : 'mic',
                                  size: 17,
                                  color: pvpMuted,
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                  );
                }
                final count = others.length + 1;
                var columns = size.maxWidth < 600
                    ? 1
                    : count <= 4
                    ? 2
                    : count <= 9
                    ? 3
                    : 4;
                return Center(
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 1440),
                    child: GridView.count(
                      shrinkWrap: true,
                      crossAxisCount: columns,
                      childAspectRatio:
                          16 /
                          (10 *
                              MediaQuery.textScalerOf(
                                context,
                              ).scale(1).clamp(1, 1.6)),
                      crossAxisSpacing: 14,
                      mainAxisSpacing: 14,
                      children: [
                        for (final m in others) remote(m),
                        KeyedSubtree(key: ValueKey(c.user?.id), child: self()),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),
          if (solo)
            Padding(
              padding: const EdgeInsets.only(bottom: 18),
              child: OutlinedButton.icon(
                onPressed: () => invite(context),
                icon: const PvpGlyph('link', size: 18),
                label: const Text('Invite'),
              ),
            ),
          if (g.message.isNotEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 10),
              child: Text(
                g.message,
                style: const TextStyle(color: Color(0xffffd5a2)),
              ),
            ),
          CallDetailsBar(c: c, group: true),
          CallDock(
            children: [
              CallAction(
                glyph: g.listening
                    ? 'mic'
                    : g.media.muted
                    ? 'mic-off'
                    : 'mic',
                label: g.moderatorMuted
                    ? 'Muted'
                    : g.listening
                    ? 'Use mic'
                    : g.media.muted
                    ? 'Unmute'
                    : 'Mute',
                semanticLabel: g.awaitingApproval
                    ? 'Microphone, waiting for approval'
                    : g.moderatorMuted
                    ? 'Microphone, muted by admin'
                    : g.listening
                    ? 'Use mic'
                    : 'Microphone',
                toggled: g.listening ? null : !g.media.muted,
                active: !g.media.muted,
                showLabel: labels,
                alwaysLabel: g.moderatorMuted || g.listening,
                add: g.listening,
                busy: g.microphoneOpening,
                onPressed: g.moderatorMuted
                    ? null
                    : g.listening
                    ? g.enableMicrophone
                    : g.toggleMic,
              ),
              if (g.speakingRequired)
                CallAction(
                  glyph: 'hand',
                  label: g.self?['speaking_allowed'] == true
                      ? 'Finish speaking'
                      : g.self?['hand_raised'] == true
                      ? 'Lower hand'
                      : 'Raise hand',
                  alwaysLabel: true,
                  active: g.self?['hand_raised'] == true,
                  busy: c.working,
                  onPressed: c.working
                      ? null
                      : () async {
                          final ok = await c.perform(() async {
                            await c.api.request(
                              '/meetings/${g.room!['meeting_id']}/hand',
                              method: 'POST',
                              data: {
                                'raised':
                                    g.self?['hand_raised'] != true &&
                                    g.self?['speaking_allowed'] != true,
                              },
                            );
                          });
                          if (!ok && context.mounted) {
                            ScaffoldMessenger.of(
                              context,
                            ).showSnackBar(SnackBar(content: Text(c.message)));
                          }
                        },
                ),
              CallAction(
                glyph: g.media.cameraOff ? 'video-off' : 'video',
                label: g.media.cameraOff ? 'Turn camera on' : 'Turn camera off',
                semanticLabel: 'Camera',
                toggled: !g.media.cameraOff,
                active: !g.media.cameraOff,
                showLabel: labels,
                busy: g.media.cameraChanging,
                onPressed: () => c.perform(() async {
                  await g.media.toggleVideo(c.preferences);
                  g.broadcast();
                }),
              ),
              if (MediaQuery.sizeOf(context).width > 600) ...[
                CallAction(
                  glyph: g.media.screenSharing
                      ? 'screen-share-off'
                      : 'screen-share',
                  label: g.media.screenSharing
                      ? 'Stop sharing'
                      : 'Share screen',
                  active: g.media.screenSharing,
                  toggled: g.media.screenSharing,
                  showLabel: labels,
                  busy: g.media.screenChanging,
                  onPressed: () => share(context),
                ),
                AnimatedBuilder(
                  animation: g.chat,
                  builder: (context, _) => CallAction(
                    glyph: 'message-circle',
                    label: 'Chat',
                    showLabel: labels,
                    badge: g.chat.unread,
                    onPressed: () => meetingChatDialog(context, c),
                  ),
                ),
                CallAction(
                  glyph: 'users-round',
                  label: 'People',
                  badge: g.participants
                      .where((m) => m['hand_raised'] == true)
                      .length,
                  showLabel: labels,
                  onPressed: () => people(context),
                ),
              ],
              AnimatedBuilder(
                animation: g.chat,
                builder: (context, _) => CallAction(
                  glyph: 'ellipsis',
                  label: 'More',
                  showLabel: labels,
                  badge: MediaQuery.sizeOf(context).width <= 600
                      ? g.chat.unread +
                            g.participants
                                .where((m) => m['hand_raised'] == true)
                                .length
                      : 0,
                  onPressed: () => more(context),
                ),
              ),
              CallAction(
                glyph: 'phone-off',
                label: 'Leave',
                semanticLabel: 'Leave call',
                danger: true,
                alwaysLabel: true,
                onPressed: () => g.leave(),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Future<void> invite(BuildContext context) async {
    final g = c.group;
    if (g.room?['meeting_id'] != null || g.room?['voice'] == true) {
      final uri = c.api.origin.replace(
        path: '/',
        fragment: g.room?['meeting_id'] != null
            ? 'meeting=${g.room!['meeting_id']}'
            : 'voice=${g.id}',
      );
      try {
        await Clipboard.setData(ClipboardData(text: uri.toString()));
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Row(
                children: [
                  PvpGlyph('check', size: 18),
                  SizedBox(width: 8),
                  Text('Link copied'),
                ],
              ),
              duration: Duration(milliseconds: 1400),
            ),
          );
        }
      } catch (_) {
        if (context.mounted) {
          await showPvpDialog(
            context: context,
            builder: (_) => AlertDialog(
              title: const Text('Invitation link'),
              content: SelectableText(uri.toString()),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Done'),
                ),
              ],
            ),
          );
        }
      }
    } else {
      await groupPicker(context, c, adding: true);
    }
  }

  Future<void> more(BuildContext context) => showPvpDialog(
    context: context,
    builder: (ctx) => ListenableBuilder(
      listenable: c,
      builder: (ctx, _) => ContextSheet(
        title: 'More',
        active: c.group.joined,
        children: [
          SheetAction(
            glyph: 'message-circle',
            label: 'Chat',
            onTap: () {
              Navigator.pop(ctx);
              meetingChatDialog(context, c);
            },
          ),
          SheetAction(
            glyph: 'users-round',
            label: 'People',
            onTap: () {
              Navigator.pop(ctx);
              people(context);
            },
          ),
          SheetAction(
            glyph: 'screen-share',
            label: c.group.media.screenSharing
                ? 'Stop sharing'
                : 'Share screen',
            onTap: () {
              Navigator.pop(ctx);
              share(context);
            },
          ),
          const Divider(),
          SheetAction(
            glyph: 'settings-2',
            label: 'Audio & video',
            onTap: () {
              Navigator.pop(ctx);
              audioVideoDialog(context, c);
            },
          ),
          SheetAction(
            glyph: 'wifi',
            label: 'Connection',
            onTap: () {
              Navigator.pop(ctx);
              people(context);
            },
          ),
          SwitchListTile(
            contentPadding: const EdgeInsets.symmetric(horizontal: 4),
            title: const Text(
              'Show control labels',
              style: TextStyle(fontSize: 15),
            ),
            value: c.preferences.showControlLabels,
            onChanged: c.setControlLabels,
          ),
        ],
      ),
    ),
  );
  Future<void> people(BuildContext context) => showPvpDialog(
    context: context,
    builder: (ctx) => ListenableBuilder(
      listenable: c.group,
      builder: (ctx, _) => ContextSheet(
        title: 'People',
        active: c.group.joined,
        children: [
          if (c.group.room?['meeting_id'] != null)
            meetingSpeakingSetting(ctx, c, {
              ...c.group.room!,
              'meeting_id': c.group.room!['meeting_id'],
            }),
          for (final m
              in [...c.group.members]..sort(
                (a, b) => (b['hand_raised'] == true ? 1 : 0).compareTo(
                  a['hand_raised'] == true ? 1 : 0,
                ),
              ))
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: CircleAvatar(
                backgroundColor: const Color(0xff514d72),
                child: Text(
                  (m['display_name'] as String)
                      .trim()
                      .split(RegExp(r'\s+'))
                      .take(2)
                      .map((n) => n.isEmpty ? '' : n[0])
                      .join(),
                  style: const TextStyle(fontSize: 13),
                ),
              ),
              title: Text(m['display_name']),
              subtitle: Text(
                '${m['joined'] == true ? 'In the call' : 'Invited'}${m['hand_raised'] == true
                    ? ' · Hand raised'
                    : m['speaking_allowed'] == true
                    ? ' · Can speak'
                    : m['moderator_muted'] == true
                    ? (c.group.room?['raise_hand_enabled'] == true && m['is_admin'] != true ? ' · Waiting for approval' : ' · Muted by admin')
                    : ''}${(m['id'] as String).startsWith('guest-') ? ' · Guest' : ''}',
                style: const TextStyle(fontSize: 12),
              ),
              trailing: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (m['id'] != c.user?.id &&
                      c.group.links.containsKey(m['id']))
                    IconButton(
                      tooltip: 'Connection details',
                      onPressed: () => inspect(context, m['id']),
                      icon: const PvpGlyph('wifi', size: 20),
                    ),
                  if (c.group.room?['meeting_id'] != null)
                    meetingMemberActions(ctx, c, {
                      'meeting_id': c.group.room!['meeting_id'],
                      'owner_id': c.group.room!['owner_id'],
                      'raise_hand_enabled': c.group.room!['raise_hand_enabled'],
                      'members': c.group.members,
                    }, m),
                ],
              ),
            ),
          const SizedBox(height: 12),
          SheetAction(
            glyph: 'link',
            label: 'Invite',
            onTap: () => invite(context),
          ),
        ],
      ),
    ),
  );

  Widget tile(
    BuildContext context,
    String name,
    RTCVideoRenderer? renderer, {
    bool mirror = false,
    bool paused = false,
    bool speaking = false,
    bool muted = false,
    bool listening = false,
    VoidCallback? inspect,
    VoidCallback? maximize,
    Widget? actions,
  }) => LayoutBuilder(
    builder: (context, constraints) {
      final hasVideo =
          renderer?.srcObject != null && !paused && renderer!.videoWidth > 0;
      final size = math.min(
        136.0,
        math.max(
          24.0,
          constraints.maxHeight -
              MediaQuery.textScalerOf(context).scale(30) -
              52,
        ),
      );
      return AnimatedContainer(
        duration: PvpMotion.duration(context, PvpMotion.travel),
        decoration: BoxDecoration(
          color: hasVideo ? PvpBrandColors.stageSurface : Colors.transparent,
          borderRadius: BorderRadius.circular(22),
          border: Border.all(
            color: hasVideo && speaking ? pvpAccent : Colors.transparent,
            width: 2,
          ),
        ),
        clipBehavior: Clip.antiAlias,
        child: Stack(
          children: [
            if (renderer?.srcObject != null)
              Positioned.fill(
                child: Offstage(
                  offstage: !hasVideo,
                  child: RTCVideoView(
                    renderer!,
                    mirror: mirror,
                    objectFit:
                        RTCVideoViewObjectFit.RTCVideoViewObjectFitContain,
                  ),
                ),
              ),
            if (!hasVideo)
              Center(
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      SpeakingAvatar(
                        name: name.split(' · ').first,
                        speaking: speaking,
                        size: size,
                      ),
                      const SizedBox(height: 18),
                      Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Flexible(
                            child: Text(
                              name,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 20,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                          ),
                          if (muted || listening) ...[
                            const SizedBox(width: 8),
                            Tooltip(
                              message: listening
                                  ? 'Listening'
                                  : 'Microphone muted',
                              child: PvpGlyph(
                                listening ? 'headphones' : 'mic-off',
                                size: 17,
                                color: pvpMuted,
                              ),
                            ),
                          ],
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            if (hasVideo)
              Positioned(
                left: 14,
                right: 12,
                bottom: 10,
                child: Row(
                  children: [
                    Expanded(
                      child: Text(
                        name,
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: hasVideo ? 14 : 18,
                          fontWeight: FontWeight.w500,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    if (muted || listening)
                      Tooltip(
                        message: listening ? 'Listening' : 'Microphone muted',
                        child: PvpGlyph(
                          listening ? 'headphones' : 'mic-off',
                          size: 17,
                          color: PvpBrandColors.stageMuted,
                        ),
                      ),
                    if (maximize != null && hasVideo)
                      IconButton(
                        tooltip: 'Expand',
                        onPressed: maximize,
                        icon: const PvpGlyph('maximize', size: 19),
                      ),
                  ],
                ),
              ),
          ],
        ),
      );
    },
  );
}
