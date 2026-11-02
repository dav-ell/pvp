import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/controller.dart';
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/ui/app.dart';

void main() {
  testWidgets(
    'minimum Mac window supports auth, people, requests and settings',
    (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(860, 622);
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final c = PvpController()..loading = false;
      await tester.pumpWidget(PvpApp(controller: c));
      expect(tester.takeException(), isNull);
      await tester.ensureVisible(find.text('Create account'));
      await tester.tap(find.text('Create account'));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      c.user = const Person(
        'me',
        'a_very_long_account_username_123',
        'Alex Morgan',
      );
      c.online = true;
      c.friends = [
        const Person('one', 'jamie', 'Jamie Chen', online: true),
        const Person('two', 'sam', 'Sam Rivera'),
        const Person('request', 'olivia', 'Olivia Taylor', status: 'received'),
      ];
      for (final view in ['people', 'requests', 'history', 'settings']) {
        c.navigate(view);
        await tester.pumpAndSettle();
        expect(
          tester.takeException(),
          isNull,
          reason: '$view fits the minimum window',
        );
      }
      c.dispose();
    },
  );
}
