import 'polish.dart';
import 'brand_tokens.dart';
import 'rooms.dart';
import 'call_details.dart';
import 'icon_aliases.dart';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import '../core/controller.dart';
import '../core/models.dart';
import 'connection_inspector.dart';
import 'group_call.dart';
import 'meetings.dart';
import 'motion.dart';

const ink = PvpBrandColors.ink,
    green = PvpBrandColors.ink,
    cream = PvpBrandColors.paper,
    mutedInk = PvpBrandColors.muted,
    line = PvpBrandColors.line;

class PvpApp extends StatelessWidget {
  final PvpController controller;
  const PvpApp({super.key, required this.controller});
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'PVP',
    debugShowCheckedModeBanner: false,
    theme: ThemeData(
      useMaterial3: true,
      visualDensity: VisualDensity.standard,
      materialTapTargetSize: MaterialTapTargetSize.padded,
      brightness: Brightness.light,
      scaffoldBackgroundColor: cream,
      colorScheme: ColorScheme.fromSeed(
        seedColor: green,
        brightness: Brightness.light,
        primary: green,
        surface: PvpBrandColors.surface,
        secondary: PvpBrandColors.accent,
        error: PvpBrandColors.danger,
      ),
      fontFamily: 'Manrope',
      textTheme: const TextTheme(
        headlineLarge: TextStyle(
          fontFamily: 'InstrumentSerif',
          fontSize: 54,
          fontWeight: FontWeight.w400,
          letterSpacing: -1,
          color: ink,
        ),
        headlineMedium: TextStyle(
          fontFamily: 'InstrumentSerif',
          fontSize: 36,
          fontWeight: FontWeight.w400,
          letterSpacing: -.5,
          color: ink,
        ),
        titleMedium: TextStyle(
          fontSize: 16,
          fontWeight: FontWeight.w600,
          color: ink,
        ),
        bodyMedium: TextStyle(fontSize: 14, color: ink),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          minimumSize: const Size(44, 44),
          animationDuration: PvpMotion.response,
          backgroundColor: green,
          foregroundColor: Colors.white,
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 15),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          minimumSize: const Size(44, 44),
          animationDuration: PvpMotion.response,
          foregroundColor: ink,
          side: const BorderSide(color: line),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: PvpBrandColors.surface,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 14,
          vertical: 15,
        ),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: line),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: line),
        ),
      ),
    ),
    home: MeetingLinkHost(
      c: controller,
      child: ListenableBuilder(
        listenable: controller,
        builder: (context, _) {
          if (controller.loading) {
            return const Scaffold(
              body: Center(child: CircularProgressIndicator()),
            );
          }
          return Scaffold(
            body: Column(
              children: [
                if (controller.message.isNotEmpty)
                  Material(
                    color: const Color(0xfff2e6cf),
                    child: Padding(
                      padding: const EdgeInsets.only(left: 22),
                      child: Row(
                        children: [
                          const PvpIcon(Icons.info_outline, size: 19),
                          const SizedBox(width: 12),
                          Expanded(child: Text(controller.message)),
                          IconButton(
                            tooltip: 'Dismiss message',
                            onPressed: controller.dismissMessage,
                            icon: const PvpIcon(Icons.close),
                          ),
                        ],
                      ),
                    ),
                  ),
                Expanded(
                  child: controller.user == null
                      ? AuthView(c: controller)
                      : CallWorkspace(c: controller),
                ),
              ],
            ),
          );
        },
      ),
    ),
  );
}

class CallWorkspace extends StatefulWidget {
  final PvpController c;
  const CallWorkspace({super.key, required this.c});
  @override
  State<CallWorkspace> createState() => _CallWorkspaceState();
}

class _CallWorkspaceState extends State<CallWorkspace> {
  bool browsing = false;
  String? lastCall;
  PvpController get c => widget.c;
  @override
  Widget build(BuildContext context) {
    final busy = c.group.busy || c.busy,
        identity = c.group.busy ? 'group:${c.group.id}' : c.callId;
    if (lastCall != identity) {
      lastCall = identity;
      browsing = false;
    }
    final sharing = c.group.joined
        ? c.group.media.screenSharing
        : c.media.screenSharing;
    return Stack(
      children: [
        Offstage(
          offstage: busy && !browsing,
          child: HomeView(c: c),
        ),
        if (c.group.busy)
          Offstage(
            offstage: browsing,
            child: TickerMode(
              enabled: !browsing,
              child: Theme(
                data: pvpStageTheme(context),
                child: DefaultTextStyle.merge(
                  style: const TextStyle(color: PvpBrandColors.stageText),
                  child: GroupCallView(
                    c: c,
                    onBack: () => setState(() => browsing = true),
                  ),
                ),
              ),
            ),
          ),
        if (c.busy && !c.group.busy)
          Offstage(
            offstage: browsing,
            child: TickerMode(
              enabled: !browsing,
              child: Theme(
                data: pvpStageTheme(context),
                child: DefaultTextStyle.merge(
                  style: const TextStyle(color: PvpBrandColors.stageText),
                  child: CallView(
                    c: c,
                    onBack: () => setState(() => browsing = true),
                  ),
                ),
              ),
            ),
          ),
        if (busy && browsing)
          Positioned(
            left: 24,
            right: 24,
            bottom: 20,
            child: Center(
              child: FilledButton.icon(
                onPressed: () => setState(() => browsing = false),
                icon: PvpGlyph(
                  sharing ? 'screen-share' : 'phone-off',
                  size: 19,
                ),
                label: Text(
                  sharing
                      ? 'Sharing screen · Return to call'
                      : 'Return to call',
                ),
              ),
            ),
          ),
      ],
    );
  }
}

Future<void> audioVideoDialog(BuildContext context, PvpController c) async {
  await c.loadDevices();
  if (!context.mounted) return;
  await showPvpDialog<void>(
    context: context,
    builder: (ctx) => Theme(
      data: Theme.of(ctx).copyWith(
        brightness: Brightness.light,
        colorScheme: ColorScheme.fromSeed(
          seedColor: ink,
          brightness: Brightness.light,
          primary: ink,
          surface: PvpBrandColors.surface,
        ),
        textTheme: Theme.of(
          ctx,
        ).textTheme.apply(bodyColor: ink, displayColor: ink),
        iconTheme: const IconThemeData(color: ink),
      ),
      child: Dialog(
        backgroundColor: PvpBrandColors.surface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
        child: SizedBox(
          width: 560,
          height: (MediaQuery.sizeOf(ctx).height - 80).clamp(240.0, 700.0),
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              children: [
                Row(
                  children: [
                    const Expanded(
                      child: Text(
                        'Audio & video',
                        style: TextStyle(
                          fontSize: 20,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                    IconButton(
                      tooltip: 'Back to call',
                      onPressed: () => Navigator.pop(ctx),
                      icon: const PvpGlyph('x'),
                    ),
                  ],
                ),
                Expanded(
                  child: ListenableBuilder(
                    listenable: c,
                    builder: (_, _) => SettingsView(c: c, inCall: true),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    ),
  );
}

class Brand extends StatelessWidget {
  final bool light;
  const Brand({super.key, this.light = false});
  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      SizedBox(
        width: 28,
        height: 32,
        child: CustomPaint(painter: _RoomMark(light: light)),
      ),
      const SizedBox(width: 10),
      Text(
        'pvp',
        style: TextStyle(
          color: light ? PvpBrandColors.stageText : ink,
          fontSize: 28,
          fontWeight: FontWeight.w800,
          letterSpacing: -1.8,
        ),
      ),
    ],
  );
}

class _RoomMark extends CustomPainter {
  final bool light;
  const _RoomMark({this.light = false});
  @override
  void paint(Canvas canvas, Size size) {
    canvas.save();
    canvas.scale(size.width / 24, size.height / 24);
    final stroke = Paint()
      ..color = light ? PvpBrandColors.stageText : PvpBrandColors.ink
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1.65
      ..strokeCap = StrokeCap.round
      ..strokeJoin = StrokeJoin.round;
    canvas.drawPath(
      Path()
        ..moveTo(13, 3)
        ..lineTo(5, 3)
        ..quadraticBezierTo(3, 3, 3, 5)
        ..lineTo(3, 19)
        ..quadraticBezierTo(3, 21, 5, 21)
        ..lineTo(13, 21),
      stroke,
    );
    final door = Path()
      ..moveTo(13, 3)
      ..lineTo(13, 21)
      ..lineTo(21, 18)
      ..lineTo(21, 6)
      ..close();
    canvas.drawPath(door, Paint()..color = PvpBrandColors.accent);
    canvas.drawPath(door, stroke);
    canvas.drawCircle(
      const Offset(16.5, 12),
      .7,
      Paint()..color = PvpBrandColors.ink,
    );
    canvas.restore();
  }

  @override
  bool shouldRepaint(_RoomMark oldDelegate) => light != oldDelegate.light;
}

class Avatar extends StatelessWidget {
  final Person person;
  final double size;
  const Avatar(this.person, {super.key, this.size = 54});
  @override
  Widget build(BuildContext context) {
    const colors = [
      Color(0xffd9ccbc),
      Color(0xffc8aaa1),
      Color(0xffcbd2c3),
      Color(0xffd2c8dc),
    ];
    return Container(
      width: size,
      height: size,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color:
            colors[person.name.codeUnits.fold<int>(0, (a, b) => a + b) %
                colors.length],
        borderRadius: BorderRadius.circular(size / 2),
      ),
      child: Text(
        person.initials,
        style: TextStyle(
          fontSize: size * .33,
          fontWeight: FontWeight.w600,
          color: ink,
        ),
      ),
    );
  }
}

class CardSurface extends StatelessWidget {
  final Widget child;
  final EdgeInsets padding;
  const CardSurface({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(24),
  });
  @override
  Widget build(BuildContext context) => Container(
    padding: padding,
    decoration: BoxDecoration(
      color: PvpBrandColors.surface,
      border: Border.all(color: line),
      borderRadius: BorderRadius.circular(20),
    ),
    child: child,
  );
}

class StretchOrScroll extends StatelessWidget {
  final Widget child;
  const StretchOrScroll({super.key, required this.child});
  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, bounds) => SingleChildScrollView(
      child: ConstrainedBox(
        constraints: BoxConstraints(minHeight: bounds.maxHeight),
        child: IntrinsicHeight(child: child),
      ),
    ),
  );
}

class AuthView extends StatefulWidget {
  final PvpController c;
  const AuthView({super.key, required this.c});
  @override
  State<AuthView> createState() => _AuthViewState();
}

class _AuthViewState extends State<AuthView> {
  final username = TextEditingController(),
      password = TextEditingController(),
      name = TextEditingController(),
      guestName = TextEditingController();
  bool register = false, obscure = true;
  @override
  void dispose() {
    username.dispose();
    password.dispose();
    name.dispose();
    guestName.dispose();
    super.dispose();
  }

  Future<void> submit() async {
    await widget.c.authenticate(
      username.text,
      password.text,
      name.text,
      register,
    );
    if (widget.c.user != null) password.clear();
  }

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, bounds) => Row(
      children: [
        if (bounds.maxWidth >= 760)
          Expanded(
            flex: 5,
            child: Container(
              decoration: const BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [Color(0xff232428), Color(0xff111214)],
                ),
              ),
              padding: const EdgeInsets.all(44),
              child: StretchOrScroll(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Brand(light: true),
                    const Spacer(),
                    const Text(
                      'A room for\nyour people.',
                      style: TextStyle(
                        fontSize: 43,
                        height: 1.12,
                        color: Color(0xfff1f1df),
                        fontWeight: FontWeight.w500,
                        letterSpacing: -1.8,
                      ),
                    ),
                    const SizedBox(height: 22),
                    const Text(
                      'One familiar place for your group.\nVoice at the center. Camera optional.',
                      style: TextStyle(
                        fontSize: 16,
                        height: 1.7,
                        color: Color(0xffb5bac1),
                      ),
                    ),
                    const SizedBox(height: 42),
                    Row(
                      children: [
                        for (final p in [
                          const Person('1', '', 'You'),
                          const Person('2', '', 'Your people'),
                        ])
                          Padding(
                            padding: const EdgeInsets.only(right: 12),
                            child: Avatar(p, size: 64),
                          ),
                        const PvpIcon(
                          Icons.favorite_outline,
                          color: Color(0xffb5bac1),
                        ),
                      ],
                    ),
                    const Spacer(),
                    const Text(
                      'Made for your Mac. Always within reach.',
                      style: TextStyle(color: Color(0xffb5bac1), fontSize: 12),
                    ),
                  ],
                ),
              ),
            ),
          ),
        Expanded(
          flex: 6,
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(44),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 370),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Meet here again.',
                      style: Theme.of(context).textTheme.headlineLarge,
                    ),
                    const SizedBox(height: 12),
                    const Text(
                      'Create a room, share the invitation, and come back together. No account needed.',
                      style: TextStyle(color: mutedInk, height: 1.5),
                    ),
                    const SizedBox(height: 16),
                    TextField(
                      controller: guestName,
                      maxLength: 60,
                      decoration: const InputDecoration(
                        labelText: 'Your name',
                        hintText: 'Name for your rooms',
                      ),
                    ),
                    const SizedBox(height: 12),
                    SizedBox(
                      width: double.infinity,
                      child: FilledButton(
                        onPressed: widget.c.working
                            ? null
                            : () => widget.c.startGuest(guestName.text),
                        child: const Text('Continue as guest'),
                      ),
                    ),
                    const SizedBox(height: 24),
                    const Divider(),
                    const SizedBox(height: 16),
                    const Text(
                      'OPTIONAL ACCOUNT',
                      style: TextStyle(color: mutedInk, fontSize: 11),
                    ),
                    const SizedBox(height: 12),
                    Text(
                      register ? 'Find your people.' : 'Welcome back.',
                      style: Theme.of(context).textTheme.headlineLarge,
                    ),
                    const SizedBox(height: 12),
                    Text(
                      register
                          ? 'Create your account to start making connections.'
                          : 'Sign in and pick up where you left off.',
                      style: const TextStyle(color: mutedInk, height: 1.5),
                    ),
                    const SizedBox(height: 28),
                    SegmentedButton<bool>(
                      segments: const [
                        ButtonSegment(value: false, label: Text('Sign in')),
                        ButtonSegment(
                          value: true,
                          label: Text('Create account'),
                        ),
                      ],
                      selected: {register},
                      onSelectionChanged: widget.c.working
                          ? null
                          : (s) => setState(() {
                              register = s.first;
                            }),
                    ),
                    const SizedBox(height: 24),
                    if (register) ...[
                      TextField(
                        controller: name,
                        textCapitalization: TextCapitalization.words,
                        autofillHints: const [AutofillHints.name],
                        decoration: const InputDecoration(
                          labelText: 'Your name',
                        ),
                        onSubmitted: (_) => submit(),
                      ),
                      const SizedBox(height: 14),
                    ],
                    TextField(
                      controller: username,
                      autocorrect: false,
                      autofillHints: const [AutofillHints.username],
                      decoration: const InputDecoration(
                        labelText: 'Username',
                        prefixText: '@',
                      ),
                      onSubmitted: (_) => submit(),
                    ),
                    const SizedBox(height: 14),
                    TextField(
                      controller: password,
                      obscureText: obscure,
                      autofillHints: [
                        register
                            ? AutofillHints.newPassword
                            : AutofillHints.password,
                      ],
                      onSubmitted: (_) => submit(),
                      decoration: InputDecoration(
                        labelText: 'Password',
                        helperText: register ? 'At least 10 characters' : null,
                        suffixIcon: IconButton(
                          tooltip: obscure ? 'Show password' : 'Hide password',
                          onPressed: () => setState(() => obscure = !obscure),
                          icon: PvpIcon(
                            obscure
                                ? Icons.visibility_outlined
                                : Icons.visibility_off_outlined,
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(height: 24),
                    SizedBox(
                      width: double.infinity,
                      child: FilledButton(
                        onPressed: widget.c.working ? null : submit,
                        child: Text(
                          widget.c.working
                              ? 'Connecting…'
                              : register
                              ? 'Create account'
                              : 'Sign in',
                        ),
                      ),
                    ),
                    const SizedBox(height: 28),
                    Row(
                      children: [
                        const PvpIcon(
                          Icons.lock_outline,
                          color: mutedInk,
                          size: 15,
                        ),
                        const SizedBox(width: 8),
                        const Expanded(
                          child: Text(
                            'Direct calls expose your IP address to participants. Some networks cannot connect.',
                            style: TextStyle(fontSize: 12, color: mutedInk),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 24),
                    TextButton(
                      onPressed: widget.c.working
                          ? null
                          : () => zoomDialog(context, widget.c),
                      child: const Text(
                        'Move a group from a Zoom invitation',
                        style: TextStyle(fontSize: 11),
                      ),
                    ),
                    TextButton(
                      onPressed: widget.c.working
                          ? null
                          : () => serviceDialog(context, widget.c),
                      child: Text(
                        'Service: ${widget.c.api.origin.host}',
                        style: const TextStyle(fontSize: 12, color: mutedInk),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ],
    ),
  );
}

Future<void> serviceDialog(BuildContext context, PvpController c) async {
  final text = TextEditingController(text: c.api.address);
  final value = await showPvpDialog<String>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('Signaling service'),
      content: SizedBox(
        width: 400,
        child: TextField(
          controller: text,
          decoration: const InputDecoration(labelText: 'HTTPS address'),
          onSubmitted: (v) => Navigator.pop(context, v),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.pop(context, text.text),
          child: const Text('Connect'),
        ),
      ],
    ),
  );
  if (value != null) await c.setService(value);
  text.dispose();
}

class HomeView extends StatelessWidget {
  final PvpController c;
  const HomeView({super.key, required this.c});

  Widget destination(BuildContext context) => switch (c.page) {
    'people' =>
      c.user?.isGuest == true
          ? const Center(
              child: Text('Room invitations work without an account.'),
            )
          : PeopleView(c: c),
    'requests' => RequestsView(c: c),
    'history' => HistoryView(c: c),
    'settings' => SettingsView(c: c),
    _ => RoomsView(c: c),
  };

  void navigate(String value) {
    c.navigate(value);
    if (value == 'settings') c.refreshSystemSettings();
  }

  Widget navigation(String value, String label, String glyph) {
    final selected =
        c.page == value ||
        (value == 'people' && ['requests', 'history'].contains(c.page));
    return TextButton(
      onPressed: () => navigate(value),
      style: TextButton.styleFrom(
        foregroundColor: selected ? ink : mutedInk,
        backgroundColor: selected
            ? const Color(0xffe8eedf)
            : Colors.transparent,
        padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
      ),
      child: Text(
        label,
        style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
      ),
    );
  }

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, bounds) {
      final compact =
          bounds.maxWidth < 700 ||
          MediaQuery.textScalerOf(context).scale(1) > 1.5;
      return Column(
        children: [
          Container(
            padding: EdgeInsets.symmetric(
              horizontal: compact ? 20 : 42,
              vertical: 18,
            ),
            decoration: const BoxDecoration(
              border: Border(bottom: BorderSide(color: line)),
            ),
            child: Row(
              children: [
                const Brand(),
                const Spacer(),
                if (!compact) ...[
                  navigation('rooms', 'Rooms', 'app-window'),
                  const SizedBox(width: 6),
                  if (c.user?.isGuest != true)
                    navigation('people', 'People', 'users-round'),
                  const SizedBox(width: 6),
                  navigation('settings', 'Settings', 'settings-2'),
                  const Spacer(),
                ],
                if (!c.online)
                  IconButton(
                    tooltip: 'Reconnect',
                    onPressed: c.reconnect,
                    icon: const PvpGlyph('wifi', size: 18),
                  ),
                if (!compact) ...[
                  Avatar(c.user!, size: 28),
                  const SizedBox(width: 12),
                  Text(c.user!.name, style: const TextStyle(fontSize: 11)),
                  const SizedBox(width: 12),
                ],
                IconButton(
                  tooltip: 'Keep PVP in menu bar',
                  onPressed: () => c.host.invoke('hide'),
                  icon: const PvpGlyph('chevron-up', size: 18),
                ),
                PopupMenuButton<String>(
                  tooltip: 'Navigate PVP',
                  icon: const PvpGlyph('ellipsis', size: 20),
                  onSelected: (value) =>
                      value == 'signout' ? c.signOut() : navigate(value),
                  itemBuilder: (_) => [
                    if (compact) ...[
                      const PopupMenuItem(value: 'rooms', child: Text('Rooms')),
                      if (c.user?.isGuest != true)
                        const PopupMenuItem(
                          value: 'people',
                          child: Text('People'),
                        ),
                      const PopupMenuItem(
                        value: 'settings',
                        child: Text('Settings'),
                      ),
                    ],
                    const PopupMenuItem(
                      value: 'signout',
                      child: Text('Sign out'),
                    ),
                  ],
                ),
              ],
            ),
          ),
          Expanded(
            child: Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 1200),
                child: Padding(
                  padding: EdgeInsets.fromLTRB(
                    compact ? 22 : 48,
                    compact ? 28 : 48,
                    compact ? 22 : 48,
                    24,
                  ),
                  child: PvpArrival(
                    identity: c.page,
                    child: destination(context),
                  ),
                ),
              ),
            ),
          ),
        ],
      );
    },
  );
}

Future<void> addFriendDialog(BuildContext context, PvpController c) async {
  final field = TextEditingController();
  final value = await showPvpDialog<String>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('Bring a friend closer.'),
      content: SizedBox(
        width: 360,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Enter their PVP username. You can call each other once they accept your request.',
              style: TextStyle(color: mutedInk, height: 1.5),
            ),
            const SizedBox(height: 20),
            Autocomplete<String>(
              optionsBuilder: (value) async {
                final text = value.text.trim();
                final query = text.startsWith('@') ? text.substring(1) : text;
                if (query.length < 2) return const <String>[];
                await Future<void>.delayed(const Duration(milliseconds: 250));
                if (field.text != value.text) return const <String>[];
                try {
                  final users =
                      await c.api.request(
                            '/friends/search?q=${Uri.encodeQueryComponent(query)}',
                          )
                          as List;
                  return users.map((u) => u['username'] as String).toList();
                } catch (_) {
                  return const <String>[];
                }
              },
              onSelected: (value) => field.text = value,
              fieldViewBuilder: (context, controller, focusNode, onSubmitted) {
                return TextField(
                  controller: controller,
                  focusNode: focusNode,
                  autofocus: true,
                  autocorrect: false,
                  onChanged: (value) => field.text = value,
                  decoration: const InputDecoration(
                    labelText: 'Username',
                    prefixText: '@',
                  ),
                  onSubmitted: (v) => Navigator.pop(context, v),
                );
              },
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
          onPressed: () => Navigator.pop(context, field.text),
          child: const Text('Send request'),
        ),
      ],
    ),
  );
  if (value != null && value.trim().isNotEmpty) await c.addFriend(value);
  field.dispose();
}

class PeopleView extends StatefulWidget {
  final PvpController c;
  const PeopleView({super.key, required this.c});
  @override
  State<PeopleView> createState() => _PeopleViewState();
}

class _PeopleViewState extends State<PeopleView> {
  PvpController get c => widget.c;
  String query = '';
  bool onlineOnly = false;
  @override
  Widget build(BuildContext context) => SingleChildScrollView(
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('People', style: Theme.of(context).textTheme.headlineLarge),
            const SizedBox(height: 8),
            const Text(
              'People you can call directly. Your recurring groups live in Rooms.',
              style: TextStyle(color: mutedInk),
            ),
            const SizedBox(height: 18),
            PvpControls(
              spacing: 10,
              runSpacing: 10,
              children: [
                OutlinedButton.icon(
                  onPressed: c.working ? null : () => groupPicker(context, c),
                  icon: const PvpIcon(Icons.groups_outlined, size: 18),
                  label: const Text('Temporary group call'),
                ),
                TextButton(
                  onPressed: () => c.navigate('requests'),
                  child: const Text('Requests'),
                ),
                TextButton(
                  onPressed: () => c.navigate('history'),
                  child: const Text('Recent calls'),
                ),
                OutlinedButton.icon(
                  onPressed: c.online && c.group.voiceAvailable
                      ? () => c.perform(() => c.group.enterVoice())
                      : null,
                  icon: const PvpGlyph('headphones', size: 18),
                  label: const Text('Open drop-in call'),
                ),
                FilledButton.icon(
                  onPressed: c.working
                      ? null
                      : () => addFriendDialog(context, c),
                  icon: const PvpIcon(Icons.add, size: 18),
                  label: const Text('Add friend'),
                ),
              ],
            ),
          ],
        ),
        const SizedBox(height: 30),
        CardSurface(
          padding: const EdgeInsets.all(22),
          child: Row(
            children: [
              Container(
                width: 44,
                height: 44,
                decoration: BoxDecoration(
                  color: const Color(0xffeee7db),
                  borderRadius: BorderRadius.circular(13),
                ),
                child: const PvpIcon(
                  Icons.notifications_active_outlined,
                  color: green,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Stay a little closer.',
                      style: TextStyle(fontWeight: FontWeight.w600),
                    ),
                    const SizedBox(height: 5),
                    const Text(
                      'PVP keeps listening from your menu bar, even with this window closed.',
                      style: TextStyle(
                        fontSize: 12,
                        color: mutedInk,
                        height: 1.5,
                      ),
                    ),
                  ],
                ),
              ),
              if (c.notifications != 'enabled')
                TextButton(
                  onPressed: c.enableNotifications,
                  child: const Text('Enable alerts'),
                ),
            ],
          ),
        ),
        const SizedBox(height: 30),
        Row(
          children: [
            Text(
              'FRIENDS  ·  ${c.accepted.length}',
              style: const TextStyle(
                fontSize: 11,
                letterSpacing: 1.6,
                fontWeight: FontWeight.w600,
                color: mutedInk,
              ),
            ),
            const Spacer(),
            IconButton(
              tooltip: 'Refresh friends',
              onPressed: c.working ? null : () => c.perform(c.refresh),
              icon: const PvpIcon(Icons.refresh, size: 18),
            ),
          ],
        ),
        const SizedBox(height: 12),
        if (c.accepted.isEmpty)
          CardSurface(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const PvpIcon(Icons.people_outline, size: 40, color: green),
                const SizedBox(height: 20),
                const Text(
                  'Make room for your people.',
                  style: TextStyle(fontSize: 23, fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 10),
                SelectableText(
                  'Share your username: @${c.user!.username}',
                  style: const TextStyle(color: mutedInk),
                ),
                const SizedBox(height: 20),
                OutlinedButton(
                  onPressed: () => addFriendDialog(context, c),
                  child: const Text('Add your first friend'),
                ),
              ],
            ),
          ),
        Row(
          children: [
            TextButton(
              onPressed: () => setState(() => onlineOnly = false),
              child: Text(
                'All',
                style: TextStyle(color: onlineOnly ? mutedInk : ink),
              ),
            ),
            TextButton(
              onPressed: () => setState(() => onlineOnly = true),
              child: Text(
                'Online',
                style: TextStyle(color: onlineOnly ? ink : mutedInk),
              ),
            ),
          ],
        ),
        TextField(
          onChanged: (value) => setState(() => query = value.toLowerCase()),
          decoration: const InputDecoration(
            prefixIcon: PvpIcon(Icons.search),
            hintText: 'Search friends',
          ),
        ),
        const SizedBox(height: 16),
        for (final p in c.accepted.where(
          (p) =>
              (!onlineOnly || p.online) &&
              '${p.name} ${p.username}'.toLowerCase().contains(query),
        ))
          PvpArrival(
            key: ValueKey(p.id),
            identity: p.id,
            order: c.accepted.indexOf(p),
            distance: 7,
            child: friendCard(context, p),
          ),
        const SizedBox(height: 26),
        const Row(
          children: [
            PvpIcon(Icons.lock_outline, size: 14, color: mutedInk),
            SizedBox(width: 7),
            Expanded(
              child: Text(
                'Just you and your friend. End-to-end encrypted calls.',
                style: TextStyle(fontSize: 12, color: mutedInk),
              ),
            ),
          ],
        ),
      ],
    ),
  );
  Widget friendCard(BuildContext context, Person p) => Container(
    decoration: const BoxDecoration(
      border: Border(top: BorderSide(color: line)),
    ),
    child: ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
      leading: Avatar(p, size: 40),
      title: Text(p.name, style: const TextStyle(fontWeight: FontWeight.w600)),
      subtitle: Text(
        p.voiceRoom != null
            ? 'In voice · ${p.voiceParticipants}'
            : p.online
            ? 'Online'
            : 'Offline',
        style: TextStyle(color: p.online ? const Color(0xff23a559) : mutedInk),
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (p.voiceRoom != null)
            TextButton.icon(
              onPressed: c.online
                  ? () => c.perform(() => c.group.enterVoice(p.voiceRoom))
                  : null,
              icon: const PvpIcon(Icons.volume_up, size: 18),
              label: const Text('Join room'),
            ),
          IconButton(
            tooltip: 'Call',
            onPressed: c.online ? () => c.startCall(p) : null,
            icon: const PvpIcon(Icons.call_outlined),
          ),
          PopupMenuButton<String>(
            tooltip: 'Friend options',
            onSelected: (_) async {
              final remove = await showPvpDialog<bool>(
                context: context,
                builder: (context) => AlertDialog(
                  title: Text('Remove ${p.name}?'),
                  content: const Text(
                    'You will need a new accepted request to call again.',
                  ),
                  actions: [
                    TextButton(
                      onPressed: () => Navigator.pop(context, false),
                      child: const Text('Cancel'),
                    ),
                    TextButton(
                      onPressed: () => Navigator.pop(context, true),
                      child: const Text('Remove friend'),
                    ),
                  ],
                ),
              );
              if (remove == true) await c.removeFriend(p);
            },
            itemBuilder: (_) => [
              const PopupMenuItem(
                value: 'remove',
                child: Text('Remove friend'),
              ),
            ],
          ),
        ],
      ),
    ),
  );
}

class RequestsView extends StatelessWidget {
  final PvpController c;
  const RequestsView({super.key, required this.c});
  @override
  Widget build(BuildContext context) => ListView(
    children: [
      Text(
        'New connections.',
        style: Theme.of(context).textTheme.headlineLarge,
      ),
      const SizedBox(height: 10),
      const Text(
        'A call starts with a connection you both choose.',
        style: TextStyle(color: mutedInk),
      ),
      const SizedBox(height: 30),
      if (c.requests.isEmpty)
        const CardSurface(
          child: Text(
            'You’re all caught up. New friend requests will appear here.',
          ),
        ),
      for (final p in c.requests)
        Padding(
          padding: const EdgeInsets.only(bottom: 16),
          child: CardSurface(
            child: Row(
              children: [
                Avatar(p),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        p.name,
                        style: const TextStyle(fontWeight: FontWeight.w600),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        '@${p.username} · ${p.status == 'sent' ? 'Waiting for acceptance' : 'Wants to connect'}',
                        style: const TextStyle(color: mutedInk, fontSize: 12),
                      ),
                    ],
                  ),
                ),
                if (p.status == 'received')
                  FilledButton(
                    onPressed: c.working ? null : () => c.acceptFriend(p),
                    child: const Text('Accept'),
                  ),
                const SizedBox(width: 8),
                TextButton(
                  onPressed: c.working ? null : () => c.removeFriend(p),
                  child: Text(p.status == 'sent' ? 'Cancel' : 'Decline'),
                ),
              ],
            ),
          ),
        ),
    ],
  );
}

class HistoryView extends StatelessWidget {
  final PvpController c;
  const HistoryView({super.key, required this.c});
  @override
  Widget build(BuildContext context) => ListView(
    children: [
      Text('Pick up again.', style: Theme.of(context).textTheme.headlineLarge),
      const SizedBox(height: 10),
      const Text(
        'Your recent conversations, all in one place.',
        style: TextStyle(color: mutedInk),
      ),
      const SizedBox(height: 30),
      if (c.history.isEmpty)
        const CardSurface(child: Text('Your recent calls will appear here.')),
      for (final call in c.history)
        Padding(
          padding: const EdgeInsets.only(bottom: 12),
          child: CardSurface(
            padding: const EdgeInsets.all(18),
            child: Row(
              children: [
                PvpIcon(
                  call['outgoing'] ? Icons.call_made : Icons.call_received,
                  color: call['outcome'] == 'missed'
                      ? Colors.deepOrange
                      : green,
                  size: 22,
                ),
                const SizedBox(width: 18),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        call['display_name'],
                        style: const TextStyle(fontWeight: FontWeight.w600),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        '${call['outcome']} · ${_date(call['started'])}',
                        style: const TextStyle(fontSize: 12, color: mutedInk),
                      ),
                    ],
                  ),
                ),
                IconButton(
                  tooltip: 'Call again',
                  onPressed:
                      c.online && c.accepted.any((p) => p.id == call['peer_id'])
                      ? () => c.startCall(
                          c.accepted.firstWhere((p) => p.id == call['peer_id']),
                        )
                      : null,
                  icon: const PvpIcon(Icons.call_outlined),
                ),
              ],
            ),
          ),
        ),
    ],
  );
  String _date(int seconds) {
    final d = DateTime.fromMillisecondsSinceEpoch(seconds * 1000).toLocal();
    return '${d.month}/${d.day} · ${d.hour.toString().padLeft(2, '0')}:${d.minute.toString().padLeft(2, '0')}';
  }
}

class SettingsView extends StatefulWidget {
  final PvpController c;
  final bool inCall;
  const SettingsView({super.key, required this.c, this.inCall = false});
  @override
  State<SettingsView> createState() => _SettingsViewState();
}

class _SettingsViewState extends State<SettingsView> {
  double? bandwidth;
  bool? discoveryEnabled;
  bool discoverySaving = false;
  String? discoveryError;
  PvpController get c => widget.c;
  @override
  void initState() {
    super.initState();
    if (!widget.inCall && c.user?.isGuest != true) {
      c.api
          .request('/discovery')
          .then((value) {
            if (mounted) {
              setState(() => discoveryEnabled = value['enabled'] as bool);
            }
          })
          .catchError((Object error) {
            if (mounted) {
              setState(
                () => discoveryError =
                    'Could not load friend discovery settings.',
              );
            }
          });
    }
  }

  Future<void> saveDiscovery(bool enabled) async {
    setState(() {
      discoverySaving = true;
      discoveryError = null;
    });
    try {
      await c.api.request(
        '/discovery',
        method: 'POST',
        data: {'enabled': enabled},
      );
      if (mounted) setState(() => discoveryEnabled = enabled);
    } catch (_) {
      if (mounted) {
        setState(
          () => discoveryError = 'Could not save friend discovery settings.',
        );
      }
    } finally {
      if (mounted) setState(() => discoverySaving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final q = c.preferences.quality;
    final activeMedia = c.group.joined ? c.group.media : c.media;
    return ListView(
      children: [
        if (!widget.inCall) ...[
          Text('Settings', style: Theme.of(context).textTheme.headlineMedium),
          const SizedBox(height: 18),
        ],
        SwitchListTile(
          title: const Text('Show control labels'),
          secondary: const PvpGlyph('circle-question-mark', size: 22),
          value: c.preferences.showControlLabels,
          onChanged: c.setControlLabels,
        ),
        if (!widget.inCall && c.user?.isGuest != true)
          SwitchListTile(
            title: const Text('Show me in friend autocomplete'),
            subtitle: Text(
              discoveryError ??
                  'Saved to your account. Friends can still add your exact username.',
            ),
            value: discoveryEnabled ?? false,
            onChanged: discoveryEnabled == null || discoverySaving
                ? null
                : saveDiscovery,
          ),
        CardSurface(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'QUALITY & BANDWIDTH',
                style: TextStyle(
                  color: mutedInk,
                  letterSpacing: 1.4,
                  fontSize: 11,
                ),
              ),
              const SizedBox(height: 20),
              Row(
                children: [
                  for (final preset in Quality.presets)
                    Expanded(
                      child: Padding(
                        padding: const EdgeInsets.only(right: 8),
                        child: InkWell(
                          borderRadius: BorderRadius.circular(8),
                          onTap: c.working ? null : () => c.setQuality(preset),
                          child: Container(
                            padding: const EdgeInsets.all(14),
                            decoration: BoxDecoration(
                              color: q.preset == preset.preset
                                  ? const Color(0xfff7e4c8)
                                  : cream,
                              border: Border.all(
                                color: q.preset == preset.preset ? green : line,
                              ),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  switch (preset.preset) {
                                    'saver' => 'Data saver',
                                    'studio' => 'Studio',
                                    _ => 'Balanced',
                                  },
                                  style: const TextStyle(
                                    fontWeight: FontWeight.w600,
                                    fontSize: 13,
                                  ),
                                ),
                                const SizedBox(height: 8),
                                Text(
                                  preset.label,
                                  style: const TextStyle(
                                    color: mutedInk,
                                    fontSize: 11,
                                  ),
                                ),
                                const SizedBox(height: 4),
                                Text(
                                  preset.bandwidth,
                                  style: const TextStyle(
                                    color: mutedInk,
                                    fontSize: 11,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                      ),
                    ),
                ],
              ),
              const SizedBox(height: 22),
              Row(
                children: [
                  Expanded(
                    child: dropdown<int>(
                      'Resolution',
                      q.height,
                      [360, 480, 720, 1080],
                      (v) => c.setQuality(
                        Quality('custom', v, q.fps, q.videoKbps, q.audioKbps),
                      ),
                      format: (v) => '${v}p',
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: dropdown<int>(
                      'Frame rate',
                      q.fps,
                      [15, 24, 30, 60],
                      (v) => c.setQuality(
                        Quality(
                          'custom',
                          q.height,
                          v,
                          q.videoKbps,
                          q.audioKbps,
                        ),
                      ),
                      format: (v) => '$v fps',
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 24),
              Row(
                children: [
                  const Text(
                    'Video bandwidth cap',
                    style: TextStyle(fontSize: 13),
                  ),
                  const Spacer(),
                  Text(
                    '${(bandwidth ?? q.videoKbps).round()} kbps',
                    style: const TextStyle(
                      fontWeight: FontWeight.w600,
                      fontSize: 13,
                    ),
                  ),
                ],
              ),
              Slider(
                value: (bandwidth ?? q.videoKbps).toDouble(),
                min: 128,
                max: 8000,
                divisions: 123,
                onChanged: c.working
                    ? null
                    : (v) => setState(() => bandwidth = v),
                onChangeEnd: (v) async {
                  await c.setQuality(
                    Quality('custom', q.height, q.fps, v.round(), q.audioKbps),
                  );
                  if (mounted) setState(() => bandwidth = null);
                },
              ),
              dropdown<int>(
                'Audio bandwidth cap',
                q.audioKbps,
                [24, 48, 64, 96],
                (v) => c.setQuality(
                  Quality('custom', q.height, q.fps, q.videoKbps, v),
                ),
                format: (v) => '$v kbps',
              ),
              const SizedBox(height: 18),
              Text(
                'Up to ${q.bandwidth} outbound · about ${q.megabytesPerMinute.round()} MB per minute, plus network overhead. Actual usage adapts to your connection.',
                style: const TextStyle(
                  color: mutedInk,
                  fontSize: 12,
                  height: 1.6,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 20),
        if (!widget.inCall) ...[
          CardSurface(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'YOUR MAC',
                  style: TextStyle(
                    color: mutedInk,
                    letterSpacing: 1.4,
                    fontSize: 11,
                  ),
                ),
                const SizedBox(height: 12),
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text(
                    'Launch at login',
                    style: TextStyle(fontSize: 14),
                  ),
                  subtitle: Text(
                    c.loginStatus == 'requiresApproval'
                        ? 'Approve PVP in System Settings → Login Items.'
                        : 'Be available when you sign in to your Mac.',
                    style: const TextStyle(fontSize: 12, color: mutedInk),
                  ),
                  value:
                      c.loginStatus == 'enabled' ||
                      c.loginStatus == 'requiresApproval',
                  onChanged: c.working ? null : c.setLogin,
                ),
                if (c.loginStatus == 'requiresApproval')
                  TextButton(
                    onPressed: () => c.host.invoke('openLoginSettings'),
                    child: const Text('Open Login Items'),
                  ),
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text(
                    'Incoming call sound',
                    style: TextStyle(fontSize: 14),
                  ),
                  subtitle: const Text(
                    'A gentle ring when a friend calls.',
                    style: TextStyle(color: mutedInk, fontSize: 12),
                  ),
                  value: c.preferences.ring,
                  onChanged: c.setRing,
                ),
                const Divider(color: line),
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text(
                    'macOS call alerts',
                    style: TextStyle(fontSize: 14),
                  ),
                  subtitle: Text(
                    c.notifications == 'enabled'
                        ? 'Enabled. Answer or decline from the notification.'
                        : c.notifications == 'denied'
                        ? 'Allow PVP in System Settings → Notifications.'
                        : 'Get incoming-call notifications on your Mac.',
                    style: const TextStyle(color: mutedInk, fontSize: 12),
                  ),
                  trailing: c.notifications == 'enabled'
                      ? const PvpIcon(Icons.check_circle_outline, color: green)
                      : OutlinedButton(
                          onPressed: c.enableNotifications,
                          child: const Text('Enable'),
                        ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 20),
        ],
        CardSurface(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  const Text(
                    'CAMERA & AUDIO',
                    style: TextStyle(
                      color: mutedInk,
                      letterSpacing: 1.4,
                      fontSize: 11,
                    ),
                  ),
                  const Spacer(),
                  TextButton.icon(
                    onPressed: c.working ? null : c.loadDevices,
                    icon: const PvpIcon(Icons.refresh, size: 16),
                    label: const Text('Refresh devices'),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              device('videoinput', 'Camera', c.preferences.camera),
              const SizedBox(height: 14),
              device('audioinput', 'Microphone', c.preferences.microphone),
              const SizedBox(height: 8),
              const Text(
                'Muted sound detection uses an existing, already-consented microphone level on this device. It does not unmute or send audio.',
                style: TextStyle(color: mutedInk, fontSize: 11, height: 1.6),
              ),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text('Echo cancellation'),
                subtitle: const Text(
                  'Reduces speaker sound picked up by your microphone.',
                  style: TextStyle(color: mutedInk, fontSize: 12),
                ),
                value: c.preferences.echoCancellation,
                onChanged: c.working ? null : c.setEchoCancellation,
              ),
              const SizedBox(height: 14),
              device('audiooutput', 'Speakers', c.preferences.speaker),
              const SizedBox(height: 20),
              if (activeMedia.stream != null) ...[
                Text(
                  activeMedia.screenSharing
                      ? 'Sharing ${activeMedia.screenName} · ${activeMedia.microphoneStatus}'
                      : activeMedia.microphoneStatus,
                  style: const TextStyle(color: mutedInk, fontSize: 12),
                ),
                const SizedBox(height: 8),
                LinearProgressIndicator(
                  value: (activeMedia.microphoneLevel * 4).clamp(0, 1),
                  color: green,
                  backgroundColor: line,
                  minHeight: 5,
                ),
                const SizedBox(height: 16),
                SizedBox(
                  height: 200,
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(8),
                    child: RTCVideoView(
                      activeMedia.local,
                      mirror: true,
                      objectFit:
                          RTCVideoViewObjectFit.RTCVideoViewObjectFitContain,
                    ),
                  ),
                ),
                const SizedBox(height: 16),
              ],
              if (!widget.inCall)
                OutlinedButton.icon(
                  onPressed: c.working
                      ? null
                      : activeMedia.stream == null
                      ? c.preview
                      : c.stopPreview,
                  icon: PvpIcon(
                    activeMedia.stream == null
                        ? Icons.videocam_outlined
                        : Icons.stop_circle_outlined,
                  ),
                  label: Text(
                    activeMedia.stream == null
                        ? 'Test camera & microphone'
                        : 'Stop device test',
                  ),
                ),
              const SizedBox(height: 12),
              if (!widget.inCall)
                const Text(
                  'Devices stay off until you call or start a test.',
                  style: TextStyle(color: mutedInk, fontSize: 12, height: 1.6),
                ),
              Row(
                children: [
                  TextButton(
                    onPressed: () => c.host.invoke('openPrivacy', 'camera'),
                    child: const Text('Camera permissions'),
                  ),
                  TextButton(
                    onPressed: () => c.host.invoke('openPrivacy', 'microphone'),
                    child: const Text('Microphone permissions'),
                  ),
                ],
              ),
            ],
          ),
        ),
        if (!widget.inCall) ...[
          const SizedBox(height: 20),
          CardSurface(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'PVP FOR MAC',
                  style: TextStyle(
                    color: mutedInk,
                    letterSpacing: 1.4,
                    fontSize: 11,
                  ),
                ),
                const SizedBox(height: 14),
                Text(
                  'Connected to ${c.api.origin.host}',
                  style: const TextStyle(fontWeight: FontWeight.w500),
                ),
                const SizedBox(height: 10),
                const Text(
                  'Receive calls from your menu bar while your Mac is awake. Quit PVP to go offline.',
                  style: TextStyle(color: mutedInk, fontSize: 12, height: 1.7),
                ),
              ],
            ),
          ),
        ],
        const SizedBox(height: 24),
      ],
    );
  }

  Widget dropdown<T>(
    String label,
    T value,
    List<T> values,
    void Function(T) onChange, {
    String Function(T)? format,
  }) => DropdownButtonFormField<T>(
    initialValue: value,
    key: ValueKey('$label:$value'),
    isExpanded: true,
    decoration: InputDecoration(labelText: label),
    items: values
        .map(
          (v) => DropdownMenuItem(
            value: v,
            child: Text(
              format?.call(v) ?? '$v',
              overflow: TextOverflow.ellipsis,
            ),
          ),
        )
        .toList(),
    onChanged: c.working
        ? null
        : (v) {
            if (v != null) onChange(v);
          },
  );
  Widget device(String kind, String label, String chosen) {
    final items = c.devices.where((d) => d.kind == kind).toList();
    final ids = [
      '',
      ...items.map((d) => d.deviceId).where((s) => s.isNotEmpty).toSet(),
    ];
    if (!ids.contains(chosen)) ids.add(chosen);
    return dropdown<String>(
      label,
      chosen,
      ids,
      (id) => c.setDevice(kind, id),
      format: (id) {
        if (id.isEmpty) return 'System default';
        final match = items.where((d) => d.deviceId == id);
        return match.isEmpty
            ? 'Saved device (unavailable)'
            : match.first.label.isEmpty
            ? label
            : match.first.label;
      },
    );
  }
}

class CallView extends StatelessWidget {
  final PvpController c;
  final VoidCallback? onBack;
  const CallView({super.key, required this.c, this.onBack});
  @override
  Widget build(BuildContext context) {
    final incoming = c.phase == 'incoming';
    final connected = c.phase == 'connected';
    final person = c.peer;
    final elapsed = c.media.connectedAt == null
        ? Duration.zero
        : DateTime.now().difference(c.media.connectedAt!);
    return Container(
      color: pvpCanvas,
      padding: const EdgeInsets.fromLTRB(24, 20, 24, 24),
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
                  person?.name ?? 'Call',
                  style: const TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              if (connected)
                Text(
                  '${elapsed.inMinutes}:${(elapsed.inSeconds % 60).toString().padLeft(2, '0')}',
                  style: const TextStyle(color: pvpMuted, fontSize: 13),
                ),
              IconButton(
                tooltip: 'More',
                icon: const PvpGlyph('ellipsis'),
                onPressed: () => showPvpDialog(
                  context: context,
                  builder: (ctx) => ListenableBuilder(
                    listenable: c,
                    builder: (ctx, _) => ContextSheet(
                      title: 'More',
                      active: c.busy,
                      children: [
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
                            showPvpDialog(
                              context: context,
                              builder: (_) => ConnectionInspector(c: c),
                            );
                          },
                        ),
                        SwitchListTile(
                          title: const Text('Show control labels'),
                          contentPadding: EdgeInsets.zero,
                          value: c.preferences.showControlLabels,
                          onChanged: c.setControlLabels,
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),
          Expanded(
            child: ClipRRect(
              borderRadius: BorderRadius.circular(22),
              child: Container(
                color: pvpSurface,
                child: Stack(
                  children: [
                    if (c.media.remote.srcObject != null)
                      Positioned.fill(
                        child: RTCVideoView(
                          c.media.remote,
                          objectFit: RTCVideoViewObjectFit
                              .RTCVideoViewObjectFitContain,
                        ),
                      ),
                    if (!connected || c.media.remote.videoWidth == 0)
                      Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            if (person != null)
                              PvpSignal(
                                active: !connected,
                                child: SpeakingAvatar(
                                  name: person.name,
                                  size: 136,
                                ),
                              ),
                            const SizedBox(height: 24),
                            Text(
                              person?.name ?? 'Your friend',
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 32,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                            const SizedBox(height: 12),
                            Text(
                              switch (c.phase) {
                                'incoming' => 'Incoming voice call',
                                'preparing' => 'Getting your microphone ready…',
                                'calling' => 'Ringing…',
                                'connected' => 'Connected',
                                _ => 'Connecting…',
                              },
                              style: const TextStyle(
                                color: Color(0xffb5bac1),
                                fontSize: 15,
                              ),
                            ),
                            if (c.phase != 'incoming' && !connected) ...[
                              const SizedBox(height: 24),
                              const SizedBox(
                                width: 20,
                                height: 20,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: Color(0xffb5bac1),
                                ),
                              ),
                            ],
                          ],
                        ),
                      ),
                    if (c.media.local.srcObject != null &&
                        (!c.media.cameraOff || c.media.screenSharing))
                      Positioned.fill(
                        child: ExpandableSelfPreview(
                          key: const ValueKey('direct-self-preview'),
                          child: RTCVideoView(
                            c.media.local,
                            mirror: !c.media.screenSharing,
                            objectFit: RTCVideoViewObjectFit
                                .RTCVideoViewObjectFitContain,
                          ),
                        ),
                      ),
                    if (connected)
                      Positioned(
                        left: 20,
                        bottom: 20,
                        child: Text(
                          person?.name ?? '',
                          style: const TextStyle(
                            color: Colors.white,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                  ],
                ),
              ),
            ),
          ),
          if (connected) CallDetailsBar(c: c),
          const SizedBox(height: 14),
          if (incoming)
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                OutlinedButton.icon(
                  style: OutlinedButton.styleFrom(
                    foregroundColor: Colors.white,
                    side: const BorderSide(color: Color(0xff577b64)),
                  ),
                  onPressed: c.decline,
                  icon: const PvpIcon(Icons.call_end),
                  label: const Text('Decline'),
                ),
                const SizedBox(width: 16),
                FilledButton.icon(
                  style: FilledButton.styleFrom(
                    backgroundColor: PvpBrandColors.accent,
                    foregroundColor: ink,
                  ),
                  onPressed: c.answer,
                  icon: const PvpIcon(Icons.call_outlined),
                  label: const Text('Answer'),
                ),
              ],
            )
          else
            CallDock(
              children: [
                control(
                  c.media.muted
                      ? Icons.mic_off_outlined
                      : Icons.mic_none_outlined,
                  c.media.muted ? 'Unmute' : 'Mute',
                  c.media.toggleMic,
                  selected: c.media.muted,
                ),
                control(
                  c.media.cameraOff
                      ? Icons.videocam_off_outlined
                      : Icons.videocam_outlined,
                  c.media.screenSharing
                      ? (c.media.cameraOff ? 'Resume sharing' : 'Pause sharing')
                      : (c.media.cameraOff
                            ? 'Turn camera on'
                            : 'Turn camera off'),
                  () => c.perform(() => c.media.toggleVideo(c.preferences)),
                  selected: c.media.cameraOff,
                ),
                if (connected) ...[
                  control(
                    c.media.screenSharing
                        ? Icons.stop_screen_share_outlined
                        : Icons.screen_share_outlined,
                    c.media.screenChanging
                        ? 'Changing sharing…'
                        : c.media.screenSharing
                        ? 'Stop sharing'
                        : 'Share screen',
                    () async {
                      if (c.media.screenChanging || c.working) return;
                      if (c.media.screenSharing) {
                        await c.perform(c.media.stopScreenShare);
                        return;
                      }
                      await c.perform(() async {
                        final call = c.callId;
                        final permission = await c.host.invoke<bool>(
                          'screenCapturePermission',
                        );
                        if (permission == false) {
                          c.message =
                              'Allow PVP in System Settings → Privacy & Security → Screen Recording, then try again.';
                          await c.host.invoke('openScreenPrivacy');
                          return;
                        }
                        final sources = await desktopCapturer.getSources(
                          types: [SourceType.Screen, SourceType.Window],
                        );
                        if (!context.mounted ||
                            c.callId != call ||
                            c.phase != 'connected') {
                          return;
                        }
                        final source =
                            await showPvpDialog<DesktopCapturerSource>(
                              context: context,
                              builder: (context) => SimpleDialog(
                                title: const Text('Choose what to share'),
                                children: [
                                  for (final source in sources)
                                    SimpleDialogOption(
                                      onPressed: () =>
                                          Navigator.pop(context, source),
                                      child: ListTile(
                                        leading: PvpIcon(
                                          source.type == SourceType.Screen
                                              ? Icons.desktop_mac
                                              : Icons.window,
                                        ),
                                        title: Text(source.name),
                                      ),
                                    ),
                                  SimpleDialogOption(
                                    onPressed: () => Navigator.pop(context),
                                    child: const Text('Cancel'),
                                  ),
                                ],
                              ),
                            );
                        if (source != null &&
                            c.callId == call &&
                            c.phase == 'connected') {
                          await c.media.startScreenShare(
                            source.id,
                            source.name,
                            c.preferences,
                            sourceType: source.type,
                          );
                        }
                      });
                    },
                    selected: c.media.screenSharing,
                  ),
                ],
                control(Icons.call_end, 'End call', c.endCall, danger: true),
              ],
            ),
          if (connected && c.media.screenSharing)
            Padding(
              padding: const EdgeInsets.only(top: 14),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const PvpGlyph('screen-share', size: 18),
                  const SizedBox(width: 8),
                  const Text('Sharing screen'),
                  TextButton(
                    onPressed: () => c.perform(c.media.stopScreenShare),
                    child: const Text('Stop sharing'),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }

  Widget control(
    IconData icon,
    String label,
    VoidCallback callback, {
    bool selected = false,
    bool danger = false,
  }) => CallAction(
    glyph: pvpIconAliases[icon] ?? 'circle-question-mark',
    label: danger ? 'Leave' : label,
    semanticLabel: danger
        ? 'End call'
        : label.contains('camera')
        ? 'Camera'
        : label == 'Mute' || label == 'Unmute'
        ? 'Microphone'
        : label,
    active:
        !danger &&
            (label == 'Mute' || label == 'Unmute' || label.contains('camera'))
        ? !selected
        : selected,
    danger: danger,
    showLabel: c.preferences.showControlLabels,
    alwaysLabel: danger,
    toggled: danger
        ? null
        : (label == 'Mute' || label == 'Unmute' || label.contains('camera'))
        ? !selected
        : selected,
    onPressed: callback,
  );
}
