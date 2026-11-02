import 'polish.dart';
import 'motion.dart';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../core/controller.dart';
import '../core/meeting_chat.dart';

bool chatImage(Uint8List b) =>
    b.length >= 12 &&
    b.length <= 10 * 1024 * 1024 &&
    ((b[0] == 137 && b[1] == 80 && b[2] == 78 && b[3] == 71) ||
        (b[0] == 255 && b[1] == 216 && b[2] == 255) ||
        (b[0] == 71 && b[1] == 73 && b[2] == 70 && b[3] == 56) ||
        (b[0] == 82 &&
            b[1] == 73 &&
            b[2] == 70 &&
            b[3] == 70 &&
            b[8] == 87 &&
            b[9] == 69 &&
            b[10] == 66 &&
            b[11] == 80));
Future<void> meetingChatDialog(BuildContext context, PvpController c) =>
    showPvpDialog(
      context: context,
      builder: (_) => _ChatDialog(c: c),
    );

class _ChatDialog extends StatefulWidget {
  final PvpController c;
  const _ChatDialog({required this.c});
  @override
  State<_ChatDialog> createState() => _ChatDialogState();
}

class _ChatDialogState extends State<_ChatDialog> {
  final text = TextEditingController();
  final scroll = ScrollController();
  int itemCount = 0;

  Future<void> send() => action(() async {
    if (text.text.trim().isEmpty || chat.ready.isEmpty) return;
    chat.text(text.text);
    text.clear();
    setState(() {});
  });
  bool picking = false;
  String error = '';
  PvpController get c => widget.c;
  MeetingChat get chat => c.group.chat;
  Future<void> action(Future<void> Function() fn) async {
    try {
      await fn();
      if (mounted) setState(() => error = '');
    } catch (e) {
      if (mounted) setState(() => error = e.toString());
    }
  }

  @override
  void initState() {
    super.initState();
    c.group.addListener(callChanged);
    chat.reading = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) chat.markReading(true);
    });
  }

  void callChanged() {
    if (!c.group.joined && mounted) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted &&
            !c.group.joined &&
            ModalRoute.of(context)?.isCurrent == true) {
          Navigator.of(context).pop();
        }
      });
    }
  }

  @override
  void dispose() {
    c.group.removeListener(callChanged);
    chat.reading = false;
    scroll.dispose();
    text.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: chat,
    builder: (context, _) {
      if (chat.items.length != itemCount) {
        final nearBottom =
            !scroll.hasClients || scroll.position.extentAfter < 80;
        itemCount = chat.items.length;
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (mounted && scroll.hasClients && nearBottom) {
            if (PvpMotion.reduced(context)) {
              scroll.jumpTo(scroll.position.maxScrollExtent);
              return;
            }
            scroll.animateTo(
              scroll.position.maxScrollExtent,
              duration: const Duration(milliseconds: 180),
              curve: Curves.easeOut,
            );
          }
        });
      }
      return Dialog(
        insetPadding: const EdgeInsets.all(20),
        backgroundColor: pvpSurface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
        child: SizedBox(
          width: 600,
          height: (MediaQuery.sizeOf(context).height - 40).clamp(200.0, 720.0),
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              children: [
                Row(
                  children: [
                    const Expanded(
                      child: Text(
                        'Chat',
                        style: TextStyle(
                          fontSize: 20,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                    const Tooltip(
                      message:
                          'Chat clears when you leave. Files up to 100 MiB; recipients accept before transfer.',
                      child: Padding(
                        padding: EdgeInsets.all(12),
                        child: PvpGlyph('info', size: 20, color: pvpMuted),
                      ),
                    ),
                    IconButton(
                      tooltip: 'Close chat',
                      onPressed: () => Navigator.pop(context),
                      icon: const PvpGlyph('x'),
                    ),
                  ],
                ),
                Align(
                  alignment: Alignment.centerLeft,
                  child: Text(
                    chat.ready.isEmpty
                        ? 'Waiting for others'
                        : '${chat.ready.length} connected',
                    style: const TextStyle(fontSize: 12, color: pvpMuted),
                  ),
                ),
                if (error.isNotEmpty)
                  Text(error, style: const TextStyle(color: Color(0xffffb4ab))),
                const SizedBox(height: 12),
                Expanded(
                  child: chat.items.isEmpty
                      ? const Center(
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              PvpIcon(Icons.chat_bubble_outline, size: 36),
                              SizedBox(height: 12),
                              Text('No messages yet'),
                            ],
                          ),
                        )
                      : ListView(
                          controller: scroll,
                          children: [
                            for (final item in chat.items)
                              PvpArrival(
                                key: ValueKey('${item.peer}:${item.id}'),
                                identity: item.id,
                                distance: 7,
                                child: Card(
                                  child: Padding(
                                    padding: const EdgeInsets.all(12),
                                    child: Column(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.start,
                                      children: [
                                        Text(
                                          item.author ?? 'Participant',
                                          style: const TextStyle(
                                            fontWeight: FontWeight.bold,
                                          ),
                                        ),
                                        if (item.text != null)
                                          SelectableText(item.text!),
                                        if (item.name != null) ...[
                                          Text(
                                            '${item.name} · ${(item.size / 1024).toStringAsFixed(1)} KiB',
                                          ),
                                          if (item.bytes != null &&
                                              chatImage(item.bytes!))
                                            Image.memory(
                                              item.bytes!,
                                              height: 160,
                                              cacheHeight: 320,
                                              cacheWidth: 320,
                                              errorBuilder: (_, _, _) =>
                                                  const Text(
                                                    'Image preview unavailable',
                                                  ),
                                            ),
                                          Wrap(
                                            spacing: 8,
                                            children: [
                                              if (item.bytes != null)
                                                TextButton(
                                                  onPressed: () =>
                                                      action(() async {
                                                        await c.host.invoke(
                                                          'saveChatAttachment',
                                                          {
                                                            'name': item.name,
                                                            'bytes': item.bytes,
                                                          },
                                                        );
                                                      }),
                                                  child: const Text(
                                                    'Save file',
                                                  ),
                                                ),
                                              if (item.peer != c.user?.id &&
                                                  item.status == 'Offered')
                                                TextButton(
                                                  onPressed: () =>
                                                      action(() async {
                                                        chat.accept(item);
                                                      }),
                                                  child: const Text(
                                                    'Accept file',
                                                  ),
                                                ),
                                              TextButton(
                                                onPressed: () =>
                                                    chat.cancel(item),
                                                child: Text(
                                                  item.bytes != null
                                                      ? 'Clear file'
                                                      : 'Cancel',
                                                ),
                                              ),
                                            ],
                                          ),
                                        ],
                                        Text(
                                          item.status,
                                          style: const TextStyle(
                                            fontSize: 11,
                                            color: Colors.grey,
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                ),
                              ),
                          ],
                        ),
                ),

                const SizedBox(height: 12),
                Row(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    IconButton(
                      tooltip: picking ? 'Choosing file…' : 'Attach file',
                      onPressed: picking || chat.ready.isEmpty
                          ? null
                          : () => action(() async {
                              setState(() => picking = true);
                              try {
                                final file = await c.host.invoke<Map>(
                                  'pickChatAttachment',
                                );
                                if (file != null && mounted) {
                                  chat.offer(
                                    file['name'] as String,
                                    file['bytes'] as Uint8List,
                                  );
                                }
                              } finally {
                                if (mounted) setState(() => picking = false);
                              }
                            }),
                      icon: const PvpGlyph('paperclip'),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: TextField(
                        controller: text,
                        onChanged: (_) => setState(() {}),
                        onSubmitted: (_) => send(),
                        textInputAction: TextInputAction.send,
                        maxLength: 4000,
                        minLines: 1,
                        maxLines: 3,
                        decoration: const InputDecoration(
                          hintText: 'Message everyone',
                          counterText: '',
                          contentPadding: EdgeInsets.all(14),
                        ),
                      ),
                    ),
                    const SizedBox(width: 8),
                    IconButton.filled(
                      tooltip: 'Send',
                      onPressed: text.text.trim().isEmpty || chat.ready.isEmpty
                          ? null
                          : send,
                      icon: const PvpGlyph('send'),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      );
    },
  );
}
