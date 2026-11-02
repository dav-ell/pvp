import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/api.dart';
import 'package:pvp_desktop/core/controller.dart';
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/ui/meetings.dart';

class MeetingsApi extends PvpApi {
  MeetingsApi() : super('https://lopixel.space');
  Object? created;
  final meeting = <String, dynamic>{
    'meeting_id': 'a' * 64,
    'name': 'Team meet',
    'owner_id': 'self',
    'url': 'https://lopixel.space/#meeting=${'a' * 64}',
    'open_invite': false,
    'participants': [],
    'members': [
      {
        'id': 'self',
        'display_name': 'David',
        'username': 'david',
        'is_admin': true,
      },
    ],
  };
  @override
  Future<dynamic> request(
    String path, {
    String method = 'GET',
    Object? data,
  }) async {
    if (method == 'POST') {
      created = data;
      return meeting;
    }
    return path == '/meetings' ? [meeting] : meeting;
  }
}

void main() {
  for (final size in [const Size(860, 540), const Size(1440, 900)]) {
    testWidgets(
      'meeting library, creation and details keep actions visible at $size',
      (tester) async {
        tester.view.devicePixelRatio = 1;
        tester.view.physicalSize = size;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);
        final api = MeetingsApi();
        final c = PvpController()
          ..user = const Person('self', 'david', 'David')
          ..meetingsAvailable = true
          ..openMeetingsAvailable = true;
        c.api.dispose();
        c.api = api;
        c.friends = List.generate(
          25,
          (i) => Person('friend$i', 'friend$i', 'Friend $i'),
        );
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(body: MeetingDialog(c: c)),
          ),
        );
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
        expect(find.text('Team meet'), findsOneWidget);
        await tester.tap(find.text('Create room'));
        await tester.pumpAndSettle();
        expect(find.text('Create room').hitTestable(), findsOneWidget);
        FilledButton primary() => tester.widget<FilledButton>(
          find.ancestor(
            of: find.text('Create room'),
            matching: find.byWidgetPredicate((w) => w is FilledButton),
          ),
        );
        expect(primary().onPressed, isNull);
        await tester.enterText(
          find.widgetWithText(TextField, 'Room name'),
          '   ',
        );
        await tester.pump();
        expect(primary().onPressed, isNull);
        await tester.enterText(
          find.widgetWithText(TextField, 'Room name'),
          'Weekly catch-up',
        );
        await tester.pump();
        expect(primary().onPressed, isNotNull);
        await tester.tap(find.text('Create room'));
        await tester.pumpAndSettle();
        expect((api.created as Map)['name'], 'Weekly catch-up');
        expect((api.created as Map)['open_invite'], false);
        expect(
          c.group.busy,
          false,
          reason: 'Creating a link never starts a call',
        );
        expect(find.text('Join with microphone').hitTestable(), findsOneWidget);
        expect(tester.takeException(), isNull);
        c.phase = 'connected';
        c.notifyListeners();
        await tester.pump();
        final join = tester.widget<OutlinedButton>(
          find.ancestor(
            of: find.text('Join with microphone'),
            matching: find.byWidgetPredicate((w) => w is OutlinedButton),
          ),
        );
        expect(join.onPressed, isNull);
        await tester.tap(find.byTooltip('All rooms'));
        await tester.pumpAndSettle();
        expect(find.text('Create room').hitTestable(), findsOneWidget);
        await tester.pumpWidget(const SizedBox.shrink());
        c.phase = 'idle';
        c.dispose();
      },
    );
  }
}
