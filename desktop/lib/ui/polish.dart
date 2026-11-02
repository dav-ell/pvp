import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'icon_aliases.dart';
import 'motion.dart';
import 'brand_tokens.dart';

const pvpCanvas = PvpBrandColors.stage,
    pvpSurface = PvpBrandColors.stageSurface,
    pvpAccent = PvpBrandColors.accent,
    pvpMuted = PvpBrandColors.stageMuted;

ThemeData pvpStageTheme(BuildContext context) => Theme.of(context).copyWith(
  brightness: Brightness.dark,
  scaffoldBackgroundColor: pvpCanvas,
  colorScheme: ColorScheme.fromSeed(
    seedColor: pvpAccent,
    brightness: Brightness.dark,
    primary: pvpAccent,
    surface: pvpSurface,
    onSurface: PvpBrandColors.stageText,
    onPrimary: PvpBrandColors.ink,
  ),
  textTheme: Theme.of(context).textTheme.apply(
    bodyColor: PvpBrandColors.stageText,
    displayColor: PvpBrandColors.stageText,
  ),
  iconTheme: const IconThemeData(color: PvpBrandColors.stageText),
  inputDecorationTheme: Theme.of(context).inputDecorationTheme.copyWith(
    fillColor: pvpSurface,
    labelStyle: const TextStyle(color: pvpMuted),
    hintStyle: const TextStyle(color: pvpMuted),
    helperStyle: const TextStyle(color: pvpMuted),
    enabledBorder: OutlineInputBorder(
      borderRadius: BorderRadius.circular(10),
      borderSide: const BorderSide(color: Color(0xff626466)),
    ),
    focusedBorder: OutlineInputBorder(
      borderRadius: BorderRadius.circular(10),
      borderSide: const BorderSide(color: pvpAccent, width: 2),
    ),
  ),
  dialogTheme: const DialogThemeData(
    backgroundColor: pvpSurface,
    surfaceTintColor: Colors.transparent,
    titleTextStyle: TextStyle(
      color: PvpBrandColors.stageText,
      fontSize: 22,
      fontWeight: FontWeight.w600,
    ),
    contentTextStyle: TextStyle(color: PvpBrandColors.stageText, fontSize: 14),
  ),
  filledButtonTheme: FilledButtonThemeData(
    style: Theme.of(context).filledButtonTheme.style?.copyWith(
      backgroundColor: const WidgetStatePropertyAll(pvpAccent),
      foregroundColor: const WidgetStatePropertyAll(PvpBrandColors.ink),
    ),
  ),
  outlinedButtonTheme: OutlinedButtonThemeData(
    style: Theme.of(context).outlinedButtonTheme.style?.copyWith(
      foregroundColor: const WidgetStatePropertyAll(PvpBrandColors.stageText),
      side: const WidgetStatePropertyAll(BorderSide(color: pvpMuted)),
    ),
  ),
);

/// A stable video child whose size changes without replacing the renderer.
class ExpandableSelfPreview extends StatefulWidget {
  final Widget child;
  const ExpandableSelfPreview({super.key, required this.child});
  @override
  State<ExpandableSelfPreview> createState() => _ExpandableSelfPreviewState();
}

class _ExpandableSelfPreviewState extends State<ExpandableSelfPreview> {
  bool expanded = false;
  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, bounds) {
      final width = expanded
          ? (bounds.maxWidth * .55).clamp(150.0, 420.0)
          : (bounds.maxWidth * .23).clamp(100.0, 190.0);
      return Align(
        alignment: Alignment.bottomRight,
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Semantics(
            button: true,
            label: expanded ? 'Shrink your preview' : 'Expand your preview',
            child: Tooltip(
              message: expanded ? 'Shrink your preview' : 'Expand your preview',
              child: InkWell(
                onTap: () => setState(() => expanded = !expanded),
                child: FocusableActionDetector(
                  mouseCursor: SystemMouseCursors.click,
                  child: AnimatedContainer(
                    duration: PvpMotion.duration(context, PvpMotion.travel),
                    width: width,
                    height: (width * .65).clamp(
                      32.0,
                      bounds.maxHeight < 54 ? 32.0 : bounds.maxHeight * .6,
                    ),
                    clipBehavior: Clip.antiAlias,
                    decoration: BoxDecoration(
                      color: pvpSurface,
                      border: Border.all(color: PvpBrandColors.stageMuted),
                      borderRadius: BorderRadius.circular(12),
                      boxShadow: const [
                        BoxShadow(color: Color(0x50000000), blurRadius: 18),
                      ],
                    ),
                    child: IgnorePointer(child: widget.child),
                  ),
                ),
              ),
            ),
          ),
        ),
      );
    },
  );
}

/// Compatibility with IconData keeps existing semantic/test identities while
/// every application glyph is rendered from the same licensed Lucide subset.
class PvpIcon extends Icon {
  const PvpIcon(
    super.icon, {
    super.key,
    super.size,
    super.color,
    super.semanticLabel,
  });
  @override
  Widget build(BuildContext context) => PvpGlyph(
    pvpIconAliases[icon] ?? 'circle-question-mark',
    size: size ?? IconTheme.of(context).size ?? 24,
    color: color ?? IconTheme.of(context).color,
    semanticLabel: semanticLabel,
  );
}

class PvpGlyph extends StatelessWidget {
  final String name;
  final double size;
  final Color? color;
  final String? semanticLabel;
  const PvpGlyph(
    this.name, {
    super.key,
    this.size = 24,
    this.color,
    this.semanticLabel,
  });
  @override
  Widget build(BuildContext context) => SvgPicture.asset(
    'assets/icons/$name.svg',
    width: size,
    height: size,
    colorFilter: ColorFilter.mode(
      color ?? IconTheme.of(context).color ?? Colors.white,
      BlendMode.srcIn,
    ),
    semanticsLabel: semanticLabel,
    excludeFromSemantics: semanticLabel == null,
    matchTextDirection:
        name.startsWith('chevron-') || name.startsWith('arrow-'),
  );
}

class CallAction extends StatelessWidget {
  final String glyph, label;
  final String? semanticLabel;
  final VoidCallback? onPressed;
  final bool active, danger, showLabel, alwaysLabel, busy, add;
  final int badge;
  final bool? toggled;
  const CallAction({
    super.key,
    required this.glyph,
    required this.label,
    required this.onPressed,
    this.semanticLabel,
    this.active = false,
    this.danger = false,
    this.showLabel = false,
    this.alwaysLabel = false,
    this.busy = false,
    this.add = false,
    this.badge = 0,
    this.toggled,
  });
  @override
  Widget build(BuildContext context) => Column(
    mainAxisSize: MainAxisSize.min,
    children: [
      Tooltip(
        message: label,
        excludeFromSemantics: true,
        child: Semantics(
          button: true,
          enabled: onPressed != null && !busy,
          toggled: toggled,
          label: badge > 0
              ? '${semanticLabel ?? label}, $badge unread'
              : semanticLabel ?? label,
          onTap: busy ? null : onPressed,
          excludeSemantics: true,
          child: SizedBox(
            width: danger ? 66 : 52,
            height: 52,
            child: Stack(
              clipBehavior: Clip.none,
              children: [
                Positioned.fill(
                  child: PvpTouch(
                    child: IconButton.filled(
                      onPressed: busy ? null : onPressed,
                      style: IconButton.styleFrom(
                        backgroundColor: danger
                            ? PvpBrandColors.danger
                            : active
                            ? PvpBrandColors.accent
                            : const Color(0xff42464c),
                        foregroundColor: active && !danger
                            ? PvpBrandColors.ink
                            : Colors.white,
                        disabledBackgroundColor: const Color(0xff42464c),
                        disabledForegroundColor: PvpBrandColors.stageMuted,
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(danger ? 19 : 26),
                        ),
                      ),
                      icon: busy
                          ? const SizedBox(
                              width: 22,
                              height: 22,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                                color: pvpAccent,
                              ),
                            )
                          : AnimatedSwitcher(
                              duration: PvpMotion.duration(
                                context,
                                PvpMotion.travel,
                              ),
                              child: PvpGlyph(glyph, key: ValueKey(glyph)),
                            ),
                    ),
                  ),
                ),
                if (add)
                  Positioned(
                    right: 0,
                    top: 0,
                    child: Container(
                      width: 18,
                      height: 18,
                      decoration: BoxDecoration(
                        color: PvpBrandColors.accent,
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: pvpSurface, width: 2),
                      ),
                      child: const Center(
                        child: Text(
                          '+',
                          style: TextStyle(
                            color: PvpBrandColors.ink,
                            fontSize: 12,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                    ),
                  ),
                if (badge > 0)
                  Positioned(
                    right: -3,
                    top: -3,
                    child: IgnorePointer(
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 5,
                          vertical: 2,
                        ),
                        decoration: BoxDecoration(
                          color: PvpBrandColors.accent,
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(color: pvpSurface, width: 2),
                        ),
                        child: Text(
                          badge > 9 ? '9+' : '$badge',
                          style: const TextStyle(
                            color: PvpBrandColors.ink,
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ),
      ),
      if (showLabel || alwaysLabel)
        Padding(
          padding: const EdgeInsets.only(top: 7),
          child: Text(
            semanticLabel == 'Camera'
                ? 'Camera'
                : label == 'Share screen'
                ? 'Share'
                : label,
            style: const TextStyle(
              fontSize: 11,
              color: PvpBrandColors.stageMuted,
            ),
          ),
        ),
    ],
  );
}

class CallDock extends StatelessWidget {
  final List<Widget> children;
  const CallDock({super.key, required this.children});
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(12),
    decoration: BoxDecoration(
      color: pvpSurface,
      border: Border.all(color: const Color(0x20ffffff)),
      borderRadius: BorderRadius.circular(25),
    ),
    child: Wrap(
      alignment: WrapAlignment.center,
      crossAxisAlignment: WrapCrossAlignment.start,
      spacing: 12,
      runSpacing: 12,
      children: children,
    ),
  );
}

class SpeakingAvatar extends StatelessWidget {
  final String name;
  final bool speaking;
  final double size;
  const SpeakingAvatar({
    super.key,
    required this.name,
    this.speaking = false,
    this.size = 136,
  });
  @override
  Widget build(BuildContext context) => AnimatedContainer(
    duration: PvpMotion.duration(context, PvpMotion.travel),
    padding: const EdgeInsets.all(7),
    decoration: BoxDecoration(
      shape: BoxShape.circle,
      border: Border.all(
        color: speaking ? pvpAccent : Colors.transparent,
        width: 2,
      ),
    ),
    child: Container(
      width: size,
      height: size,
      decoration: const BoxDecoration(
        shape: BoxShape.circle,
        gradient: LinearGradient(
          colors: [Color(0xffc8b49c), Color(0xffa28b70)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
      ),
      child: Center(
        child: Text(
          name
              .trim()
              .split(RegExp(r'\s+'))
              .take(2)
              .map((s) => s.isEmpty ? '' : s[0])
              .join()
              .toUpperCase(),
          style: TextStyle(
            fontSize: size / 3,
            fontWeight: FontWeight.w500,
            color: PvpBrandColors.ink,
          ),
        ),
      ),
    ),
  );
}

class ContextSheet extends StatelessWidget {
  final String title;
  final List<Widget> children;
  final bool active;
  const ContextSheet({
    super.key,
    required this.title,
    required this.children,
    this.active = true,
  });
  @override
  Widget build(BuildContext context) {
    if (!active) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (context.mounted && ModalRoute.of(context)?.isCurrent == true) {
          Navigator.pop(context);
        }
      });
    }
    return Theme(
      data: pvpStageTheme(context),
      child: Dialog(
        backgroundColor: pvpSurface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(24),
          side: const BorderSide(color: Color(0xff575754)),
        ),
        child: ConstrainedBox(
          constraints: BoxConstraints(
            maxWidth: 420,
            maxHeight: MediaQuery.sizeOf(context).height - 64,
          ),
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(20),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        title,
                        style: const TextStyle(
                          fontSize: 20,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                    IconButton(
                      tooltip: 'Back to call',
                      onPressed: () => Navigator.pop(context),
                      icon: const PvpGlyph('x'),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                ...children,
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class SheetAction extends StatelessWidget {
  final String glyph, label;
  final Widget? trailing;
  final VoidCallback? onTap;
  const SheetAction({
    super.key,
    required this.glyph,
    required this.label,
    this.trailing,
    this.onTap,
  });
  @override
  Widget build(BuildContext context) => ListTile(
    contentPadding: const EdgeInsets.symmetric(horizontal: 4),
    minTileHeight: 54,
    leading: PvpGlyph(glyph, color: PvpBrandColors.accent, size: 22),
    title: Text(label, style: const TextStyle(fontSize: 15)),
    trailing:
        trailing ?? const PvpGlyph('chevron-right', color: pvpMuted, size: 17),
    onTap: onTap,
  );
}
