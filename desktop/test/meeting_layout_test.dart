import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/controller.dart';
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/ui/group_call.dart';

void main() {
  for (final size in [const Size(860, 540), const Size(1440, 900)]) {
    for (final count in [1, 2, 8, 16]) {
      for (final scale in [1.0, 2.0]) {
        for (final stage in [false, true]) {
          testWidgets(
            'meeting with $count participants fits $size at text scale $scale (raised hands: $stage)',
            (tester) async {
              tester.view.devicePixelRatio = 1;
              tester.view.physicalSize = size;
              addTearDown(tester.view.resetPhysicalSize);
              addTearDown(tester.view.resetDevicePixelRatio);
              final c = PvpController()
                ..user = const Person('self', 'self', 'David');
              c.group.room = {
                'room_id': 'test',
                'name': 'Team meet',
                'meeting_id': 'meeting',
                'raise_hand_enabled': stage,
                'members': List.generate(
                  count,
                  (i) => {
                    'id': i == 0 ? 'self' : 'peer$i',
                    'display_name': i == 0 ? 'David' : 'Participant $i',
                    'joined': true,
                    'is_admin': false,
                    'moderator_muted': stage,
                    'hand_raised': stage && i % 3 == 0,
                    'speaking_allowed': false,
                  },
                ),
              };
              await tester.pumpWidget(
                MaterialApp(
                  builder: (context, child) => MediaQuery(
                    data: MediaQuery.of(
                      context,
                    ).copyWith(textScaler: TextScaler.linear(scale)),
                    child: child!,
                  ),
                  home: Scaffold(body: GroupCallView(c: c)),
                ),
              );
              expect(tester.takeException(), isNull);
              expect(find.text('Leave'), findsOneWidget);
              await tester.tap(find.byTooltip('Chat'));
              await tester.pumpAndSettle();
              expect(tester.takeException(), isNull);
              expect(find.text('No messages yet'), findsOneWidget);
              final send = tester.widget<IconButton>(
                find.byWidgetPredicate(
                  (w) => w is IconButton && w.tooltip == 'Send',
                ),
              );
              expect(send.onPressed, isNull);
              await tester.tap(find.byTooltip('Close chat'));
              await tester.pumpAndSettle();
              await tester.tap(find.byTooltip('People'));
              await tester.pumpAndSettle();
              expect(find.text('People'), findsOneWidget);
              expect(
                find.descendant(
                  of: find.byType(Dialog),
                  matching: find.text('David'),
                ),
                findsOneWidget,
              );
              expect(tester.takeException(), isNull);
              await tester.tap(find.byTooltip('Back to call'));
              await tester.pumpAndSettle();
              await tester.pumpWidget(const SizedBox.shrink());
              c.group.room = null;
              c.dispose();
            },
          );
        }
      }
    }
  }
}
