import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'brand_tokens.dart';

/// PVP Signal: immediate response, a short travel, a soft landing.
abstract final class PvpMotion {
  static const response = PvpBrandMotion.response;
  static const travel = PvpBrandMotion.travel;
  static const settle = PvpBrandMotion.settle;
  static const curve = Cubic(.16, 1, .3, 1);
  static const signal = PvpBrandColors.accent;

  static bool reduced(BuildContext context) =>
      MediaQuery.disableAnimationsOf(context) ||
      MediaQuery.accessibleNavigationOf(context);

  static Duration duration(BuildContext context, Duration value) =>
      reduced(context) ? Duration.zero : value;
}

/// Replaces the child immediately, including media widgets. Ordinary controller
/// updates preserve the animation; only a new identity starts an entrance.
class PvpArrival extends StatefulWidget {
  final Object identity;
  final Widget child;
  final int order;
  final double distance;
  const PvpArrival({
    super.key,
    required this.identity,
    required this.child,
    this.order = 0,
    this.distance = 10,
  });

  @override
  State<PvpArrival> createState() => _PvpArrivalState();
}

class _PvpArrivalState extends State<PvpArrival>
    with SingleTickerProviderStateMixin {
  late final AnimationController motion = AnimationController(
    vsync: this,
    duration: Duration(milliseconds: 280 + math.min(widget.order * 18, 72)),
  );
  bool initialized = false;

  void start() {
    if (PvpMotion.reduced(context)) {
      motion.value = 1;
    } else {
      motion.forward(from: 0);
    }
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (!initialized) {
      initialized = true;
      start();
    } else if (PvpMotion.reduced(context)) {
      motion.value = 1;
    }
  }

  @override
  void didUpdateWidget(PvpArrival oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.identity != widget.identity) start();
  }

  @override
  void dispose() {
    motion.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: motion,
    child: widget.child,
    builder: (context, child) {
      final delay =
          math.min(widget.order * 18, 72) / motion.duration!.inMilliseconds;
      final t = PvpMotion.curve.transform(
        ((motion.value - delay) / (1 - delay)).clamp(0.0, 1.0),
      );
      return Opacity(
        opacity: .35 + .65 * t,
        child: Transform.translate(
          offset: Offset(0, widget.distance * (1 - t)),
          child: child,
        ),
      );
    },
  );
}

/// Pointer feedback without consuming the child's gestures or semantics.
class PvpTouch extends StatefulWidget {
  final Widget child;
  const PvpTouch({super.key, required this.child});
  @override
  State<PvpTouch> createState() => _PvpTouchState();
}

class _PvpTouchState extends State<PvpTouch> {
  bool pressed = false, hovered = false;
  @override
  Widget build(BuildContext context) => MouseRegion(
    onEnter: (_) => setState(() => hovered = true),
    onExit: (_) => setState(() {
      hovered = false;
      pressed = false;
    }),
    child: Listener(
      onPointerDown: (_) => setState(() => pressed = true),
      onPointerUp: (_) => setState(() => pressed = false),
      onPointerCancel: (_) => setState(() => pressed = false),
      child: AnimatedScale(
        scale: PvpMotion.reduced(context)
            ? 1
            : pressed
            ? .96
            : hovered
            ? 1.015
            : 1,
        duration: PvpMotion.duration(context, PvpMotion.response),
        curve: PvpMotion.curve,
        child: widget.child,
      ),
    ),
  );
}

class PvpControls extends StatelessWidget {
  final List<Widget> children;
  final double spacing, runSpacing;
  final WrapAlignment alignment;
  const PvpControls({
    super.key,
    required this.children,
    this.spacing = 10,
    this.runSpacing = 10,
    this.alignment = WrapAlignment.start,
  });

  @override
  Widget build(BuildContext context) => Wrap(
    spacing: spacing,
    runSpacing: runSpacing,
    alignment: alignment,
    children: [for (final child in children) PvpTouch(child: child)],
  );
}

/// Two waves around a caller, then quiet. No continuous idle animation.
class PvpSignal extends StatefulWidget {
  final Widget child;
  final bool active;
  const PvpSignal({super.key, required this.child, this.active = true});
  @override
  State<PvpSignal> createState() => _PvpSignalState();
}

class _PvpSignalState extends State<PvpSignal>
    with SingleTickerProviderStateMixin {
  late final AnimationController motion = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 5440),
  );

  void update() {
    if (!widget.active || PvpMotion.reduced(context)) {
      motion.stop();
      motion.value = 1;
    } else {
      motion.forward(from: 0);
    }
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    update();
  }

  @override
  void didUpdateWidget(PvpSignal oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.active != widget.active) update();
  }

  @override
  void dispose() {
    motion.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => RepaintBoundary(
    child: CustomPaint(painter: _SignalPainter(motion), child: widget.child),
  );
}

class _SignalPainter extends CustomPainter {
  final Animation<double> motion;
  _SignalPainter(this.motion) : super(repaint: motion);

  @override
  void paint(Canvas canvas, Size size) {
    if (motion.value == 0 || motion.value >= 1) return;
    final time = motion.value * 5440;
    for (var wave = 0; wave < 2; wave++) {
      final elapsed = time - wave * 340;
      if (elapsed < 0 || elapsed >= 5100) continue;
      final t = (elapsed % 1700) / 1700;
      final opacity = math.sin(t * math.pi) * .5;
      canvas.drawCircle(
        size.center(Offset.zero),
        size.shortestSide / 2 + 8 + t * 28,
        Paint()
          ..color = PvpMotion.signal.withValues(alpha: opacity)
          ..style = PaintingStyle.stroke
          ..strokeWidth = 1.2,
      );
    }
  }

  @override
  bool shouldRepaint(_SignalPainter oldDelegate) =>
      oldDelegate.motion != motion;
}

/// Keeps Material's focus, safe-area and dismissal behavior with PVP timing.
Future<T?> showPvpDialog<T>({
  required BuildContext context,
  required WidgetBuilder builder,
  bool useSafeArea = true,
}) => showDialog<T>(
  context: context,
  useSafeArea: useSafeArea,
  animationStyle: PvpMotion.reduced(context)
      ? AnimationStyle.noAnimation
      : const AnimationStyle(
          duration: PvpMotion.travel,
          reverseDuration: PvpMotion.response,
          curve: PvpMotion.curve,
          reverseCurve: Curves.easeIn,
        ),
  builder: (context) =>
      PvpArrival(identity: 'dialog', distance: 8, child: builder(context)),
);
