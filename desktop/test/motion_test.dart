import 'dart:ui' show PointerDeviceKind;
import 'package:flutter/services.dart';
import 'package:pvp_desktop/ui/polish.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/ui/motion.dart';

class LifecycleProbe extends StatefulWidget {
  final VoidCallback disposed;
  const LifecycleProbe({super.key, required this.disposed});
  @override
  State<LifecycleProbe> createState() => _LifecycleProbeState();
}

class _LifecycleProbeState extends State<LifecycleProbe> {
  @override
  void dispose() {
    widget.disposed();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => const Text('Media surface');
}

Widget host(Widget child, {bool reduced = false}) => MaterialApp(
  home: MediaQuery(
    data: MediaQueryData(disableAnimations: reduced),
    child: Scaffold(body: Center(child: child)),
  ),
);

void main() {
  testWidgets('idle call controls return on pointer and keyboard input', (
    tester,
  ) async {
    var disposals = 0;
    await tester.pumpWidget(
      host(
        CallControlActivity(
          active: true,
          child: Column(
            children: [
              LifecycleProbe(disposed: () => disposals++),
              const CallChrome(child: Text('Call controls')),
            ],
          ),
        ),
      ),
    );
    double opacity() =>
        tester.widget<AnimatedOpacity>(find.byType(AnimatedOpacity)).opacity;
    expect(opacity(), 1);
    await tester.pump(const Duration(milliseconds: 3200));
    await tester.pumpAndSettle();
    expect(opacity(), 0);
    final mouse = await tester.createGesture(kind: PointerDeviceKind.mouse);
    await mouse.addPointer(
      location: tester.getCenter(find.text('Media surface')),
    );
    await tester.pumpAndSettle();
    expect(opacity(), 1);
    await tester.pump(const Duration(milliseconds: 3200));
    await tester.pumpAndSettle();
    expect(opacity(), 0);
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    expect(opacity(), 1);
    expect(disposals, 0);
    await mouse.removePointer();
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'arrival never remounts its media child as the animation settles',
    (tester) async {
      var disposals = 0;
      final probe = LifecycleProbe(disposed: () => disposals++);
      await tester.pumpWidget(host(PvpArrival(identity: 'call', child: probe)));
      final state = tester.state(find.byType(LifecycleProbe));
      await tester.pumpAndSettle();
      expect(tester.state(find.byType(LifecycleProbe)), same(state));
      expect(disposals, 0);
      await tester.pumpWidget(host(PvpArrival(identity: 'call', child: probe)));
      await tester.pump();
      expect(
        tester.binding.hasScheduledFrame,
        isFalse,
        reason: 'call statistics must not restart the entrance',
      );
      await tester.pumpWidget(
        host(PvpArrival(identity: 'another', child: probe)),
      );
      await tester.pumpAndSettle();
      expect(tester.state(find.byType(LifecycleProbe)), same(state));
      expect(disposals, 0);
    },
  );

  testWidgets('replacing a call disposes the old surface immediately', (
    tester,
  ) async {
    var disposals = 0;
    await tester.pumpWidget(
      host(
        PvpArrival(
          identity: 'call',
          child: LifecycleProbe(disposed: () => disposals++),
        ),
      ),
    );
    await tester.pump(const Duration(milliseconds: 40));
    await tester.pumpWidget(
      host(const PvpArrival(identity: 'home', child: Text('Friends'))),
    );
    expect(disposals, 1);
    expect(find.text('Friends'), findsOneWidget);
    await tester.pumpAndSettle();
  });

  testWidgets('reduced motion cancels active arrivals and signal waves', (
    tester,
  ) async {
    const content = PvpArrival(
      identity: 'incoming',
      child: PvpSignal(child: SizedBox(width: 80, height: 80)),
    );
    await tester.pumpWidget(host(content));
    await tester.pump(const Duration(milliseconds: 50));
    expect(tester.binding.hasScheduledFrame, isTrue);
    await tester.pumpWidget(host(content, reduced: true));
    await tester.pumpAndSettle();
    expect(tester.binding.hasScheduledFrame, isFalse);
    expect(tester.widget<Opacity>(find.byType(Opacity)).opacity, 1);
    expect(tester.takeException(), isNull);
  });

  testWidgets('controls remain usable during arrival and pointer feedback', (
    tester,
  ) async {
    var taps = 0;
    await tester.pumpWidget(
      host(
        PvpArrival(
          identity: 'actions',
          child: PvpTouch(
            child: FilledButton(
              onPressed: () => taps++,
              child: const Text('Answer'),
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('Answer'));
    expect(taps, 1);
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
  });
}
