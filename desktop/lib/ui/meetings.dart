import 'polish.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../core/controller.dart';
import '../core/meeting_links.dart';
import 'motion.dart';

Future<void> zoomDialog(BuildContext context, PvpController c) => showPvpDialog(
  context: context,
  builder: (_) => _ZoomDialog(c: c),
);

class _ZoomDialog extends StatefulWidget {
  final PvpController c;
  const _ZoomDialog({required this.c});
  @override
  State<_ZoomDialog> createState() => _ZoomDialogState();
}

class _ZoomDialogState extends State<_ZoomDialog> {
  final input = TextEditingController(), name = TextEditingController();
  Map<String, dynamic>? meeting;
  String error = '', copied = '';
  bool working = false;
  int generation = 0;
  @override
  void dispose() {
    input.dispose();
    name.dispose();
    super.dispose();
  }

  Future<void> open() async {
    if (working || input.text.trim().isEmpty) return;
    final attempt = ++generation;
    setState(() {
      working = true;
      error = '';
    });
    try {
      final result = await widget.c.api.request(
        '/zoom',
        method: 'POST',
        data: {'link': input.text.trim()},
      );
      if (mounted && attempt == generation) {
        setState(() => meeting = Map<String, dynamic>.from(result));
      }
    } catch (e) {
      if (mounted && attempt == generation) {
        setState(() => error = e.toString());
      }
    } finally {
      if (mounted) setState(() => working = false);
    }
  }

  Future<void> copy({bool message = false}) async {
    final url = meeting?['url'];
    if (url == null) return;
    await Clipboard.setData(
      ClipboardData(
        text: message
            ? 'We’re meeting on PVP from now on. Paste the same Zoom invitation into ${widget.c.api.address} and choose “Move your group to PVP”, or use our permanent PVP link: $url\nNo account needed. Everyone joins in PVP; Zoom passcodes and host roles don’t carry over.'
            : url,
      ),
    );
    if (mounted) {
      setState(
        () => copied = message
            ? 'Message copied. Send it by text or email.'
            : 'PVP link copied.',
      );
    }
  }

  Future<void> continueToMeeting() async {
    final result = meeting;
    if (result == null || working) return;
    final c = widget.c;
    if (c.busy) {
      setState(() => error = 'Finish your current call first.');
      return;
    }
    setState(() => working = true);
    if (c.user == null && !await c.startGuest(name.text)) {
      if (mounted) {
        setState(() {
          working = false;
          error = c.message;
        });
      }
      return;
    }
    if (!mounted) return;
    Navigator.of(context).pop();
    c.pendingMeetingLink = c.api.origin
        .resolve('/#meeting=${result['meeting_id']}')
        .toString();
    c.navigate('rooms');
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('Move your group to PVP'),
    content: SizedBox(
      width: 520,
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Paste your existing Zoom invitation to meet here with encrypted, direct P2P voice and video. Everyone pastes the same invitation to reach the same room.',
            ),
            const SizedBox(height: 12),
            const Text(
              'This opens a separate PVP meeting. Everyone needs to join here; people joining in Zoom stay in Zoom.',
            ),
            const SizedBox(height: 16),
            TextField(
              controller: input,
              minLines: 2,
              maxLines: 4,
              maxLength: 16384,
              decoration: const InputDecoration(
                labelText: 'Zoom link, full invitation, or meeting ID',
              ),
              onChanged: (_) => setState(() {
                generation++;
                meeting = null;
                error = '';
                copied = '';
              }),
            ),
            FilledButton(
              onPressed: working ? null : open,
              child: Text(working ? 'Opening…' : 'Create room from invitation'),
            ),
            if (error.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 12),
                child: Text(
                  error,
                  style: TextStyle(color: Theme.of(context).colorScheme.error),
                ),
              ),
            if (meeting != null) ...[
              const SizedBox(height: 20),
              Text(
                'Your reusable PVP invitation',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              SelectableText(meeting!['url']),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  OutlinedButton(
                    onPressed: copy,
                    child: const Text('Copy PVP link'),
                  ),
                  OutlinedButton(
                    onPressed: () => copy(message: true),
                    child: const Text('Copy message for your group'),
                  ),
                ],
              ),
              if (copied.isNotEmpty) Text(copied),
              if (widget.c.user == null)
                TextField(
                  controller: name,
                  maxLength: 60,
                  decoration: const InputDecoration(
                    labelText: 'Your name',
                    hintText: 'Guest',
                  ),
                ),
              const SizedBox(height: 12),
              FilledButton(
                onPressed: working ? null : continueToMeeting,
                child: const Text('Preview room'),
              ),
            ],
            const SizedBox(height: 20),
            const Text(
              'Anyone with the Zoom meeting ID or PVP link can join. Zoom passcodes, waiting rooms, and host roles do not carry over. Pasting first gives no admin rights. These rooms currently have no admin; create a regular PVP link for host controls.',
            ),
            const SizedBox(height: 12),
            const Text(
              'Direct connections share your network address with participants. Up to 16 people. Named personal links and registration links need the numbered join link from the invitation.',
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
    ],
  );
}

Widget meetingNetworkSetting(
  BuildContext context,
  PvpController c,
  Map<String, dynamic> meeting, {
  Future<void> Function()? onChanged,
}) {
  if (!meeting.containsKey('network_visible') || meeting['open_invite'] != true) {
    return const SizedBox.shrink();
  }
  if (meeting['owner_id'] != c.user?.id) {
    return meeting['network_visible'] == true
        ? const Padding(
            padding: EdgeInsets.symmetric(vertical: 12),
            child: Text(
              'This room shares its anonymous size on the public homepage. Names, links and addresses stay private.',
            ),
          )
        : const SizedBox.shrink();
  }
  return ExpansionTile(
    tilePadding: EdgeInsets.zero,
    title: const Text('Public room map'),
    children: [
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        title: const Text('Share anonymous room activity'),
        subtitle: const Text(
          'Show this room’s size on the homepage. No names, links, IPs or locations. Off by default.',
        ),
        value: meeting['network_visible'] == true,
        onChanged: c.working
            ? null
            : (visible) async {
                final ok = await c.perform(() async {
                  await c.api.request(
                    '/meetings/${meeting['meeting_id']}/network',
                    method: 'POST',
                    data: {'visible': visible},
                  );
                });
                if (ok) await onChanged?.call();
                if (!ok && context.mounted) {
                  ScaffoldMessenger.of(
                    context,
                  ).showSnackBar(SnackBar(content: Text(c.message)));
                }
              },
      ),
    ],
  );
}

Widget meetingSpeakingSetting(
  BuildContext context,
  PvpController c,
  Map<String, dynamic> meeting, {
  Future<void> Function()? onChanged,
}) {
  final admin = (meeting['members'] as List? ?? []).any(
    (m) => m['id'] == c.user?.id && m['is_admin'] == true,
  );
  if (!admin) return const SizedBox.shrink();
  return SwitchListTile(
    contentPadding: EdgeInsets.zero,
    title: const Text('Raise hand to speak'),
    subtitle: const Text(
      'Participants need admin approval before unmuting. Admins can speak freely.',
    ),
    value: meeting['raise_hand_enabled'] == true,
    onChanged: c.working
        ? null
        : (enabled) async {
            final ok = await c.perform(() async {
              await c.api.request(
                '/meetings/${meeting['meeting_id']}/speaking',
                method: 'POST',
                data: {'enabled': enabled},
              );
            });
            if (ok) await onChanged?.call();
            if (!ok && context.mounted) {
              ScaffoldMessenger.of(
                context,
              ).showSnackBar(SnackBar(content: Text(c.message)));
            }
          },
  );
}

Widget meetingMemberActions(
  BuildContext context,
  PvpController c,
  Map<String, dynamic> meeting,
  Map<String, dynamic> member, {
  Future<void> Function()? onChanged,
  Color? iconColor,
}) {
  final owner = meeting['owner_id'] == c.user?.id;
  final admin =
      owner ||
      (meeting['members'] as List).any(
        (p) => p['id'] == c.user?.id && p['is_admin'] == true,
      );
  if (!c.meetingModerationAvailable ||
      !admin ||
      member['id'] == meeting['owner_id'] ||
      member['id'] == c.user?.id) {
    return const SizedBox.shrink();
  }
  return PopupMenuButton<String>(
    tooltip: 'Manage ${member['display_name']}',
    icon: PvpIcon(Icons.more_vert, color: iconColor),
    enabled: !c.working,
    itemBuilder: (_) => [
      if (owner && !(member['id'] as String).startsWith('guest-'))
        PopupMenuItem(
          value: member['is_admin'] == true ? 'demote' : 'promote',
          child: Text(
            member['is_admin'] == true ? 'Remove admin' : 'Make admin',
          ),
        ),
      if (meeting['raise_hand_enabled'] == true &&
          member['is_admin'] != true) ...[
        if (member['hand_raised'] == true)
          const PopupMenuItem(value: 'speak', child: Text('Allow to speak')),
        if (member['speaking_allowed'] == true)
          const PopupMenuItem(
            value: 'stop-speaking',
            child: Text('End speaking turn'),
          ),
      ] else
        PopupMenuItem(
          value: member['moderator_muted'] == true ? 'allow' : 'mute',
          child: Text(
            member['moderator_muted'] == true ? 'Allow unmute' : 'Mute',
          ),
        ),
      const PopupMenuItem(value: 'kick', child: Text('Kick from meeting')),
    ],
    onSelected: (action) async {
      final account = c.user?.id, service = c.api;
      if (action == 'kick') {
        final confirmed = await showPvpDialog<bool>(
          context: context,
          builder: (ctx) => AlertDialog(
            title: Text('Kick ${member['display_name']}?'),
            content: Text(
              (member['id'] as String).startsWith('guest-')
                  ? 'This guest session will be blocked from rejoining.'
                  : 'They will need a new invitation from the owner to rejoin this meeting.',
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(ctx, false),
                child: const Text('Cancel'),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(ctx, true),
                child: const Text('Kick'),
              ),
            ],
          ),
        );
        if (confirmed != true) {
          return;
        }
      }
      if (c.user?.id != account || c.api != service) {
        return;
      }
      final ok = await c.perform(() async {
        final path =
            '/meetings/${meeting['meeting_id']}/members/${member['id']}';
        if (action == 'kick') {
          await service.request(path, method: 'DELETE');
        } else if (action == 'promote' || action == 'demote') {
          await service.request(
            '$path/admin',
            method: 'POST',
            data: {'admin': action == 'promote'},
          );
        } else if (action == 'speak' || action == 'stop-speaking') {
          await service.request(
            '$path/speak',
            method: 'POST',
            data: {'allowed': action == 'speak'},
          );
        } else {
          await service.request(
            '$path/mute',
            method: 'POST',
            data: {'muted': action == 'mute'},
          );
        }
      });
      if (ok && c.user?.id == account && c.api == service && context.mounted) {
        await onChanged?.call();
      }
      if (!ok && context.mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(c.message)));
      }
    },
  );
}

Future<void> meetingsDialog(
  BuildContext context,
  PvpController c, {
  String? id,
  bool create = false,
}) async {
  if (!c.meetingsAvailable) {
    c.message = 'Rooms require the updated PVP service.';
    return;
  }
  await showPvpDialog(
    context: context,
    builder: (_) => MeetingDialog(c: c, id: id, create: create),
  );
}

class MeetingLinkHost extends StatefulWidget {
  final PvpController c;
  final Widget child;
  const MeetingLinkHost({super.key, required this.c, required this.child});
  @override
  State<MeetingLinkHost> createState() => _MeetingLinkHostState();
}

class _MeetingLinkHostState extends State<MeetingLinkHost> {
  bool showing = false;
  @override
  void initState() {
    super.initState();
    widget.c.addListener(changed);
    changed();
  }

  void changed() {
    final c = widget.c;
    if (showing ||
        c.loading ||
        c.user == null ||
        !c.meetingsAvailable ||
        c.pendingMeetingLink == null) {
      return;
    }
    showing = true;
    final link = c.pendingMeetingLink!;
    c.pendingMeetingLink = null;
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      try {
        if (!mounted) {
          return;
        }
        final id = meetingIdFromLink(link, c.api.address);
        if (id == null) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text(
                'Use a meeting link for your selected PVP service.',
              ),
            ),
          );
          return;
        }
        await meetingsDialog(context, c, id: id);
      } finally {
        showing = false;
        if (mounted) changed();
      }
    });
  }

  @override
  void dispose() {
    widget.c.removeListener(changed);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => widget.child;
}

class MeetingDialog extends StatefulWidget {
  final PvpController c;
  final String? id;
  final bool create;
  const MeetingDialog({
    super.key,
    required this.c,
    this.id,
    this.create = false,
  });
  @override
  State<MeetingDialog> createState() => _MeetingDialogState();
}

class _MeetingDialogState extends State<MeetingDialog> {
  final name = TextEditingController(), paste = TextEditingController();
  final selected = <String>{};
  Map<String, dynamic>? meeting;
  String error = '';
  String? copiedMeeting;
  bool creating = false;
  bool loading = true, working = false, openInvite = false;
  int token = 0, joinAttempt = 0;
  PvpController get c => widget.c;
  @override
  void initState() {
    super.initState();
    if (widget.create) {
      loading = false;
      startCreate();
    } else {
      load(widget.id);
    }
  }

  Future<void> load([String? id]) async {
    final generation = ++token, account = c.user?.id, service = c.api;
    if (mounted) {
      setState(() {
        loading = true;
        error = '';
      });
    }
    try {
      dynamic data;
      if (id != null) {
        data = await c.api.request('/meetings/$id');
      } else {
        await c.refreshMeetings();
      }
      if (!mounted ||
          generation != token ||
          c.user?.id != account ||
          c.api != service) {
        return;
      }
      setState(() {
        creating = false;
        meeting = id != null ? Map<String, dynamic>.from(data) : null;
        loading = false;
        error = '';
      });
    } catch (e) {
      if (mounted && generation == token) {
        setState(() {
          loading = false;
          error = e.toString();
        });
      }
    }
  }

  Future<void> action(Future<void> Function() fn) async {
    if (working) return;
    setState(() {
      working = true;
      error = '';
    });
    try {
      await fn();
    } catch (e) {
      if (mounted) setState(() => error = e.toString());
    } finally {
      if (mounted) setState(() => working = false);
    }
  }

  @override
  void dispose() {
    token++;
    name.dispose();
    paste.dispose();
    super.dispose();
  }

  void startCreate() => setState(() {
    creating = true;
    meeting = null;
    error = '';
    name.clear();
    selected.clear();
    openInvite = c.user?.isGuest == true;
  });

  Future<void> openLink() => action(() async {
    final id = meetingIdFromLink(paste.text.trim(), c.api.address);
    if (id == null) {
      throw StateError('Use a PVP room link for this service.');
    }
    await load(id);
  });

  Future<void> create() => action(() async {
    final account = c.user?.id, service = c.api;
    final result = await service.request(
      '/meetings',
      method: 'POST',
      data: {
        'name': name.text.trim(),
        'open_invite': openInvite,
        'peer_ids': selected.toList(),
      },
    );
    if (mounted && c.user?.id == account && c.api == service) {
      await load(result['meeting_id']);
    }
  });

  Future<void> join(Map<String, dynamic> m, {bool listen = false}) async {
    final attempt = ++joinAttempt;
    if (listen && c.group.pending) {
      await c.group.leave();
      if (!mounted) return;
      setState(() => working = false);
    }
    return action(() async {
      final account = c.user?.id, service = c.api;
      await service.request('/meetings/${m['meeting_id']}');
      if (!mounted || c.user?.id != account || c.api != service) return;
      try {
        await c.group.startMeeting(m['meeting_id'], listen: listen);
        if (attempt == joinAttempt &&
            c.user?.id == account &&
            c.api == service) {
          c.rememberMeeting(m['meeting_id'], m['name']);
        }
      } catch (e) {
        if (attempt == joinAttempt) rethrow;
      }
      if (mounted && attempt == joinAttempt) Navigator.pop(context);
    });
  }

  Future<void> delete(Map<String, dynamic> m) => action(() async {
    final confirmed = await showPvpDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete room?'),
        content: const Text(
          'This invalidates the link for everyone and ends its active call.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      await c.api.request('/meetings/${m['meeting_id']}', method: 'DELETE');
      await load();
    }
  });

  Widget section(String title, String description, List<Widget> children) =>
      Container(
        width: double.infinity,
        padding: const EdgeInsets.all(18),
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surfaceContainerLowest,
          border: Border.all(
            color: Theme.of(context).colorScheme.outlineVariant,
          ),
          borderRadius: BorderRadius.circular(12),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 6),
            Text(description, style: Theme.of(context).textTheme.bodySmall),
            if (children.isNotEmpty) const SizedBox(height: 16),
            ...children,
          ],
        ),
      );

  Widget library() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Text(
        'A reusable link for every gathering.',
        style: Theme.of(context).textTheme.bodyMedium,
      ),
      const SizedBox(height: 16),
      if (c.meetings.isEmpty)
        section(
          'Your first room starts here',
          'Create a link to reuse anytime, or open a link someone shared with you.',
          [],
        )
      else ...[
        Text(
          'YOUR ROOMS · ${c.meetings.length}',
          style: Theme.of(context).textTheme.labelMedium,
        ),
        const SizedBox(height: 8),
        for (final item in c.meetings)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Material(
              color: Theme.of(context).colorScheme.surfaceContainerLowest,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
                side: BorderSide(
                  color: Theme.of(context).colorScheme.outlineVariant,
                ),
              ),
              clipBehavior: Clip.antiAlias,
              child: ListTile(
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 6,
                ),
                leading: PvpIcon(
                  item['open_invite'] == true ? Icons.link : Icons.lock_outline,
                ),
                title: Text(
                  item['name'],
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                subtitle: Text(
                  '${item['open_invite'] == true ? 'Anyone with the link' : 'Private'}${(item['participants'] as List?)?.isNotEmpty == true ? ' · ${(item['participants'] as List).length} here' : ''}',
                ),
                trailing: const PvpIcon(Icons.chevron_right),
                onTap: working ? null : () => load(item['meeting_id']),
              ),
            ),
          ),
      ],
      const SizedBox(height: 16),
      section(
        'Have a room invitation?',
        'Open the room preview before choosing how to join.',
        [
          TextField(
            controller: paste,
            onChanged: (_) => setState(() {}),
            onSubmitted: (_) => openLink(),
            decoration: const InputDecoration(
              labelText: 'Room invitation',
              hintText: 'Paste a PVP room link',
            ),
          ),
          const SizedBox(height: 12),
          Align(
            alignment: Alignment.centerRight,
            child: OutlinedButton.icon(
              onPressed: working || paste.text.trim().isEmpty ? null : openLink,
              icon: const PvpIcon(Icons.arrow_forward, size: 18),
              label: const Text('Open invitation'),
            ),
          ),
        ],
      ),
    ],
  );

  Widget creation() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      const Text('Create once. Use the same link whenever you meet.'),
      const SizedBox(height: 20),
      TextField(
        controller: name,
        autofocus: true,
        maxLength: 80,
        onChanged: (_) => setState(() {}),
        decoration: const InputDecoration(
          labelText: 'Room name',
          hintText: 'e.g. Friday catch-up',
        ),
      ),
      const SizedBox(height: 12),
      section('Who can join?', 'Choose how people access this meeting.', [
        RadioGroup<bool>(
          groupValue: openInvite,
          onChanged: (v) {
            if (!working && v != null) setState(() => openInvite = v);
          },
          child: Column(
            children: [
              RadioListTile<bool>(
                enabled: c.user?.isGuest != true,
                value: false,
                contentPadding: EdgeInsets.zero,
                title: const Text('Invited friends only'),
                subtitle: const Text('Only the people you add can join.'),
              ),
              RadioListTile<bool>(
                value: true,
                enabled: c.openMeetingsAvailable && !working,
                contentPadding: EdgeInsets.zero,
                title: const Text('Anyone with the link'),
                subtitle: const Text(
                  'Anyone with the link can join, including guests without accounts.',
                ),
              ),
            ],
          ),
        ),
      ]),
      const SizedBox(height: 16),
      section(
        'Invite friends · ${selected.length}/15',
        'You count as one of the 16 members. You can add friends later.',
        [
          if (c.accepted.isEmpty)
            const Text(
              'No friends to invite yet. You can still create your meeting.',
            ),
          for (final f in c.accepted)
            CheckboxListTile(
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              title: Text(f.name),
              subtitle: Text('@${f.username}'),
              value: selected.contains(f.id),
              onChanged:
                  working || (!selected.contains(f.id) && selected.length >= 15)
                  ? null
                  : (v) => setState(() {
                      if (v == true) {
                        selected.add(f.id);
                      } else {
                        selected.remove(f.id);
                      }
                    }),
            ),
        ],
      ),
      const SizedBox(height: 16),
      const Row(
        children: [
          PvpIcon(Icons.videocam_off_outlined, size: 18),
          SizedBox(width: 8),
          Expanded(
            child: Text(
              'Creating a link leaves your camera and microphone off.',
              style: TextStyle(fontSize: 12),
            ),
          ),
        ],
      ),
    ],
  );

  Widget details(Map<String, dynamic> m) {
    final members = m['members'] as List,
        participants = m['participants'] as List;
    final owner = m['owner_id'] == c.user?.id;
    final choices = c.accepted
        .where((f) => !members.any((p) => p['id'] == f.id))
        .toList();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (m['zoom'] == true)
          const Padding(
            padding: EdgeInsets.only(bottom: 16),
            child: Text(
              'A separate PVP meeting for this Zoom invitation. Zoom passcodes and host roles do not carry over. Anyone with the meeting ID or link can join. This room has no admin.',
            ),
          ),
        section(
          m['open_invite'] == true
              ? 'Anyone with the link'
              : 'Invited friends only',
          m['open_invite'] == true
              ? 'No account needed.'
              : 'Only invited friends can join.',
          [
            ExpansionTile(
              tilePadding: EdgeInsets.zero,
              leading: const PvpGlyph('link', size: 20),
              title: const Text('Room invitation'),
              children: [
                Padding(
                  padding: const EdgeInsets.all(12),
                  child: SelectableText(
                    m['url'],
                    style: const TextStyle(fontSize: 13),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Align(
              alignment: Alignment.centerRight,
              child: OutlinedButton.icon(
                onPressed: () => action(() async {
                  await Clipboard.setData(ClipboardData(text: m['url']));
                  if (mounted) {
                    setState(() => copiedMeeting = m['meeting_id']);
                    Future<void>.delayed(
                      const Duration(milliseconds: 1400),
                      () {
                        if (mounted && copiedMeeting == m['meeting_id']) {
                          setState(() => copiedMeeting = null);
                        }
                      },
                    );
                  }
                }),
                icon: PvpGlyph(
                  copiedMeeting == m['meeting_id'] ? 'check' : 'copy',
                  size: 18,
                ),
                label: Text(
                  copiedMeeting == m['meeting_id'] ? 'Copied' : 'Copy link',
                ),
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        section(
          participants.isEmpty
              ? 'Be the first to join'
              : '${participants.length} here now',
          participants.isEmpty
              ? 'This meeting is ready whenever you are.'
              : participants.map((p) => p['display_name']).join(', '),
          [],
        ),
        const SizedBox(height: 16),
        meetingSpeakingSetting(
          context,
          c,
          m,
          onChanged: () => load(m['meeting_id']),
        ),
        meetingNetworkSetting(
          context,
          c,
          m,
          onChanged: () => load(m['meeting_id']),
        ),
        section(
          'Members · ${members.length}/16',
          owner
              ? 'Manage access from each member’s menu.'
              : 'Managed by the owner and admins.',
          [
            for (final member in members)
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: CircleAvatar(
                  child: Text(
                    (member['display_name'] as String).characters.firstOrNull
                            ?.toUpperCase() ??
                        '?',
                  ),
                ),
                title: Text(
                  '${member['display_name']}${member['id'] == c.user?.id ? ' · You' : ''}',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                subtitle: Text(
                  '${(member['id'] as String).startsWith('guest-') || (member['username'] as String).startsWith('~') ? 'Guest' : '@${member['username']}'}${member['id'] == m['owner_id']
                      ? ' · Owner'
                      : member['is_admin'] == true
                      ? ' · Admin'
                      : ''}${member['moderator_muted'] == true ? ' · Muted by admin' : ''}',
                ),
                trailing: meetingMemberActions(
                  context,
                  c,
                  m,
                  Map<String, dynamic>.from(member),
                  onChanged: () => load(m['meeting_id']),
                ),
              ),
            if (owner && choices.isNotEmpty) ...[
              const Divider(height: 24),
              for (final f in choices)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: Text(f.name),
                  subtitle: Text('@${f.username}'),
                  trailing: OutlinedButton(
                    onPressed: working || members.length >= 16
                        ? null
                        : () => action(() async {
                            await c.api.request(
                              '/meetings/${m['meeting_id']}/members',
                              method: 'POST',
                              data: {'peer_id': f.id},
                            );
                            await load(m['meeting_id']);
                          }),
                    child: const Text('Invite'),
                  ),
                ),
            ],
            if (owner && members.length >= 16)
              const Text(
                'This meeting is full. Remove a member to invite someone else.',
              ),
          ],
        ),
        const SizedBox(height: 16),
        const Text(
          'Your camera starts off. Listening requests no device access. Direct calls reveal your IP address to participants, including people joining later. Some networks cannot connect directly.',
          style: TextStyle(fontSize: 12),
        ),
        if (owner) ...[
          const Divider(height: 32),
          TextButton.icon(
            onPressed: working ? null : () => delete(m),
            style: TextButton.styleFrom(
              foregroundColor: Theme.of(context).colorScheme.error,
            ),
            icon: const PvpIcon(Icons.delete_outline, size: 18),
            label: const Text('Delete room'),
          ),
        ],
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final m = meeting;
    return ListenableBuilder(
      listenable: c,
      builder: (context, _) => Dialog(
        insetPadding: const EdgeInsets.all(24),
        clipBehavior: Clip.antiAlias,
        child: SizedBox(
          width: 640,
          height: (MediaQuery.sizeOf(context).height - 100).clamp(200.0, 720.0),
          child: Column(
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(24, 20, 16, 16),
                child: Row(
                  children: [
                    if (m != null || creating)
                      IconButton(
                        tooltip: 'All rooms',
                        onPressed: working ? null : () => load(),
                        icon: const PvpIcon(Icons.arrow_back),
                      ),
                    Expanded(
                      child: Text(
                        creating ? 'Create a room' : m?['name'] ?? 'Rooms',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: Theme.of(context).textTheme.headlineSmall,
                      ),
                    ),
                    IconButton(
                      tooltip: 'Close rooms',
                      onPressed: working ? null : () => Navigator.pop(context),
                      icon: const PvpIcon(Icons.close),
                    ),
                  ],
                ),
              ),
              const Divider(height: 1),
              Expanded(
                child: loading
                    ? const Center(child: CircularProgressIndicator())
                    : SingleChildScrollView(
                        padding: const EdgeInsets.all(24),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            if (error.isNotEmpty)
                              Container(
                                width: double.infinity,
                                margin: const EdgeInsets.only(bottom: 16),
                                padding: const EdgeInsets.all(12),
                                decoration: BoxDecoration(
                                  color: Theme.of(
                                    context,
                                  ).colorScheme.errorContainer,
                                  borderRadius: BorderRadius.circular(8),
                                ),
                                child: Text(
                                  error,
                                  style: TextStyle(
                                    color: Theme.of(
                                      context,
                                    ).colorScheme.onErrorContainer,
                                  ),
                                ),
                              ),
                            PvpArrival(
                              identity: creating
                                  ? 'create'
                                  : m?['meeting_id'] ?? 'library',
                              child: creating
                                  ? creation()
                                  : m != null
                                  ? details(m)
                                  : library(),
                            ),
                          ],
                        ),
                      ),
              ),
              const Divider(height: 1),
              Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(
                      working
                          ? (c.group.pending
                                ? 'Allow microphone access'
                                : 'Saving…')
                          : creating
                          ? 'Reusable invitation · Up to 16 people'
                          : m != null && c.busy
                          ? 'A call is already in progress'
                          : 'Same room · Same invitation',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                    const SizedBox(height: 10),
                    if (creating)
                      FilledButton.icon(
                        onPressed: working || name.text.trim().isEmpty
                            ? null
                            : create,
                        icon: const PvpIcon(Icons.add_link, size: 18),
                        label: const Text('Create room'),
                      )
                    else if (m != null)
                      Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        children: [
                          if (working && c.group.pending)
                            TextButton(
                              onPressed: () async {
                                ++joinAttempt;
                                await c.group.leave();
                                if (mounted) setState(() => working = false);
                              },
                              child: const Text('Cancel'),
                            ),
                          FilledButton.icon(
                            onPressed:
                                loading ||
                                    c.phase != 'idle' ||
                                    c.group.joined ||
                                    (c.group.busy &&
                                        !(working && c.group.pending))
                                ? null
                                : () => join(m, listen: true),
                            icon: const PvpGlyph('headphones', size: 18),
                            label: const Text('Join to listen'),
                          ),
                          OutlinedButton.icon(
                            onPressed: working || loading || c.busy
                                ? null
                                : () => join(m),
                            icon: const PvpGlyph('mic', size: 18),
                            label: const Text('Join with microphone'),
                          ),
                        ],
                      )
                    else
                      FilledButton.icon(
                        onPressed: working || loading ? null : startCreate,
                        icon: const PvpIcon(Icons.add, size: 18),
                        label: const Text('Create room'),
                      ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
