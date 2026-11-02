import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_svg/flutter_svg.dart';
import '../core/controller.dart';
import '../core/meeting_links.dart';
import 'brand_tokens.dart';
import 'meetings.dart';
import 'polish.dart';

class RoomsView extends StatefulWidget {
  final PvpController c;
  const RoomsView({super.key, required this.c});
  @override
  State<RoomsView> createState() => _RoomsViewState();
}

class _RoomsViewState extends State<RoomsView> {
  final invitation = TextEditingController();
  String? linkError;
  PvpController get c => widget.c;
  @override
  void dispose() {
    invitation.dispose();
    super.dispose();
  }

  Future<void> openInvitation() async {
    final id = meetingIdFromLink(invitation.text.trim(), c.api.address);
    if (id == null) {
      setState(() => linkError = 'Use a PVP room link for this service.');
      return;
    }
    setState(() => linkError = null);
    await meetingsDialog(context, c, id: id);
  }

  Future<void> copy(Map<String, dynamic> room) async {
    final url =
        room['url'] as String? ??
        c.api.origin
            .replace(path: '/', fragment: 'meeting=${room['meeting_id']}')
            .toString();
    try {
      await Clipboard.setData(ClipboardData(text: url));
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(const SnackBar(content: Text('Room invitation copied')));
      }
    } catch (_) {
      if (mounted) {
        await showDialog<void>(
          context: context,
          builder: (context) => AlertDialog(
            title: const Text('Room invitation'),
            content: SelectableText(url),
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
  }

  Widget createButton() => FilledButton.icon(
    onPressed: c.working || !c.meetingsAvailable
        ? null
        : () => meetingsDialog(context, c, create: true),
    icon: const PvpGlyph('plus', size: 17),
    label: const Text('Create room'),
  );

  Widget roomRow(Map<String, dynamic> room, int index) {
    final recent = room['meeting_id'] == c.recentMeetingId;
    final people = room['participants'] as List? ?? const [];
    final info = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          room['name'] as String? ?? 'Your room',
          style: const TextStyle(
            fontFamily: 'InstrumentSerif',
            fontSize: 34,
            height: 1.15,
            letterSpacing: -.4,
          ),
        ),
        const SizedBox(height: 7),
        Text(
          people.isNotEmpty
              ? '${people.length} here now'
              : room['open_invite'] == true
              ? 'Anyone with the link'
              : 'Invited people only',
          style: TextStyle(
            fontSize: 11,
            color: people.isNotEmpty
                ? PvpBrandColors.success
                : PvpBrandColors.muted,
          ),
        ),
      ],
    );
    final actions = Wrap(
      spacing: 10,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        IconButton(
          tooltip: 'Copy invitation',
          onPressed: () => copy(room),
          icon: const PvpGlyph('copy', size: 18),
        ),
        FilledButton(
          onPressed: !c.meetingsAvailable || c.working
              ? null
              : () => meetingsDialog(context, c, id: room['meeting_id']),
          child: Text(recent ? 'Return to room' : 'Join room'),
        ),
      ],
    );
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 25),
      decoration: const BoxDecoration(
        border: Border(bottom: BorderSide(color: PvpBrandColors.line)),
      ),
      child: LayoutBuilder(
        builder: (context, size) {
          final narrow =
              size.maxWidth < 560 ||
              MediaQuery.textScalerOf(context).scale(1) > 1.5;
          return Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(
                width: 42,
                child: Padding(
                  padding: const EdgeInsets.only(top: 10),
                  child: Text(
                    '${index + 1}'.padLeft(2, '0'),
                    style: const TextStyle(
                      fontSize: 10,
                      color: PvpBrandColors.muted,
                    ),
                  ),
                ),
              ),
              Expanded(
                child: narrow
                    ? Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [info, const SizedBox(height: 18), actions],
                      )
                    : Row(
                        children: [
                          Expanded(child: info),
                          const SizedBox(width: 20),
                          actions,
                        ],
                      ),
              ),
            ],
          );
        },
      ),
    );
  }

  Widget welcome() => LayoutBuilder(
    builder: (context, size) {
      final narrow =
          size.maxWidth < 650 ||
          MediaQuery.textScalerOf(context).scale(1) > 1.4;
      final copy = Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'A PLACE TO RETURN TO',
            style: TextStyle(
              fontSize: 9,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.6,
              color: PvpBrandColors.muted,
            ),
          ),
          const SizedBox(height: 22),
          Text(
            'Good company.\nSame place.',
            style: TextStyle(
              fontFamily: 'InstrumentSerif',
              fontSize: narrow ? 59 : 78,
              height: 1.02,
              letterSpacing: -1.5,
              color: PvpBrandColors.ink,
            ),
          ),
          const SizedBox(height: 24),
          ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 285),
            child: const Text(
              'Make a little space for your people. One link to keep, whenever you want to catch up.',
              style: TextStyle(
                fontSize: 13,
                height: 1.9,
                color: PvpBrandColors.muted,
              ),
            ),
          ),
          const SizedBox(height: 28),
          createButton(),
        ],
      );
      final art = ExcludeSemantics(
        child: SvgPicture.asset(
          'assets/brand/room-scene.svg',
          fit: BoxFit.contain,
        ),
      );
      if (narrow) {
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            copy,
            SizedBox(height: 270, width: double.infinity, child: art),
          ],
        );
      }
      return Padding(
        padding: const EdgeInsets.symmetric(vertical: 24),
        child: Row(
          children: [
            Expanded(child: copy),
            Expanded(child: SizedBox(height: 425, child: art)),
          ],
        ),
      );
    },
  );

  Widget invitationRow() => Container(
    margin: const EdgeInsets.only(top: 30),
    padding: const EdgeInsets.symmetric(vertical: 26),
    decoration: const BoxDecoration(
      border: Border(top: BorderSide(color: PvpBrandColors.line)),
    ),
    child: LayoutBuilder(
      builder: (context, size) {
        final narrow =
            size.maxWidth < 650 ||
            MediaQuery.textScalerOf(context).scale(1) > 1.4;
        final input = TextField(
          controller: invitation,
          onSubmitted: (_) => openInvitation(),
          decoration: InputDecoration(
            hintText: 'Paste a PVP room link',
            errorText: linkError,
            isDense: true,
          ),
        );
        final button = OutlinedButton(
          onPressed: !c.meetingsAvailable ? null : openInvitation,
          child: const Text('Open room'),
        );
        const label = Text(
          'Already have an invitation?',
          style: TextStyle(fontSize: 12),
        );
        if (narrow) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              label,
              const SizedBox(height: 14),
              input,
              const SizedBox(height: 12),
              button,
            ],
          );
        }
        return Row(
          children: [
            const Expanded(child: label),
            Expanded(flex: 2, child: input),
            const SizedBox(width: 14),
            button,
          ],
        );
      },
    ),
  );

  @override
  Widget build(BuildContext context) {
    final rooms = [...c.meetings];
    rooms.sort(
      (a, b) => a['meeting_id'] == c.recentMeetingId
          ? -1
          : b['meeting_id'] == c.recentMeetingId
          ? 1
          : 0,
    );
    return ListView(
      key: const PageStorageKey('rooms-home'),
      children: [
        if (c.group.message.isNotEmpty && !c.group.busy)
          Padding(
            padding: const EdgeInsets.only(bottom: 20),
            child: Row(
              children: [
                Expanded(child: Text(c.group.message)),
                TextButton(
                  onPressed: () => setState(() => c.group.message = ''),
                  child: const Text('Dismiss'),
                ),
              ],
            ),
          ),
        LayoutBuilder(
          builder: (context, bounds) {
            final compact =
                bounds.maxWidth < 650 ||
                MediaQuery.textScalerOf(context).scale(1) > 1.4;
            final title = Text(
              'Your rooms.',
              style: rooms.isEmpty
                  ? const TextStyle(fontSize: 11, fontWeight: FontWeight.w600)
                  : TextStyle(
                      fontFamily: 'InstrumentSerif',
                      fontSize: compact ? 48 : 64,
                      height: 1.1,
                      letterSpacing: -1.5,
                    ),
            );
            if (compact && rooms.isNotEmpty) {
              return Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [title, const SizedBox(height: 18), createButton()],
              );
            }
            return Row(
              children: [
                Expanded(child: title),
                if (rooms.isNotEmpty) createButton(),
              ],
            );
          },
        ),
        if (!c.meetingsAvailable)
          const Padding(
            padding: EdgeInsets.symmetric(vertical: 20),
            child: Text(
              'Rooms are loading or unavailable. Check your connection or service settings.',
              style: TextStyle(color: PvpBrandColors.muted),
            ),
          ),
        if (rooms.isEmpty)
          welcome()
        else ...[
          const SizedBox(height: 12),
          const Text(
            'Pick up where you left off.',
            style: TextStyle(fontSize: 13, color: PvpBrandColors.muted),
          ),
          const SizedBox(height: 28),
          for (var i = 0; i < rooms.length; i++) roomRow(rooms[i], i),
        ],
        if (c.recentMeetingId != null &&
            !rooms.any((m) => m['meeting_id'] == c.recentMeetingId))
          Align(
            alignment: Alignment.centerLeft,
            child: TextButton(
              onPressed: !c.meetingsAvailable
                  ? null
                  : () => meetingsDialog(context, c, id: c.recentMeetingId),
              child: Text('Return to ${c.recentMeetingName ?? 'your room'}'),
            ),
          ),
        invitationRow(),
        Text(
          c.user?.isGuest == true
              ? 'Keep your link. Host controls belong to this session on this device.'
              : 'Your link stays the same. Come and go as you like.',
          style: const TextStyle(
            fontSize: 10,
            height: 1.7,
            color: PvpBrandColors.muted,
          ),
        ),
        const SizedBox(height: 8),
        Align(
          alignment: Alignment.centerLeft,
          child: TextButton(
            onPressed: () => zoomDialog(context, c),
            child: const Text(
              'Move a group from a Zoom invitation',
              style: TextStyle(fontSize: 10),
            ),
          ),
        ),
      ],
    );
  }
}
