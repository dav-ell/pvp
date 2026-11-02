import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/api.dart';
import 'package:pvp_desktop/core/controller.dart';
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/ui/app.dart';
import 'package:pvp_desktop/ui/meetings.dart';

class LinkApi extends PvpApi {
  LinkApi() : super('https://lopixel.space');
  Map? created;
  final meeting = {
    'meeting_id': 'a' * 64,
    'name': 'Our meeting',
    'owner_id': 'self',
    'url': 'https://lopixel.space/#meeting=${'a' * 64}',
    'zoom': true,
    'open_invite': true,
    'participants': [],
    'members': [
      {
        'id': 'self',
        'username': '~guest',
        'display_name': 'Guest',
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
    if (path == '/zoom') {
      if ((data as Map)['link'].contains('/my/')) {
        throw const ApiException(400, 'Use the numbered join link.');
      }
      return meeting;
    }
    if (method == 'POST') created = data as Map;
    return path == '/meetings' && method == 'GET' ? [meeting] : meeting;
  }
}

void main() {
  for (final kind in ['signed out', 'guest', 'account']) {
    testWidgets(
      'Zoom link preview and copy work for $kind without starting media',
      (tester) async {
        tester.view.devicePixelRatio = 1;
        tester.view.physicalSize = const Size(1440, 900);
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);
        final c = PvpController()..loading = false;
        c.api.dispose();
        c.api = LinkApi();
        if (kind != 'signed out') {
          c.user = Person('self', kind == 'guest' ? '~guest' : 'alex', 'Alex');
        }
        String? clipboard;
        tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
          SystemChannels.platform,
          (call) async {
            if (call.method == 'Clipboard.setData') {
              clipboard = call.arguments['text'];
            }
            return null;
          },
        );
        addTearDown(
          () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
            SystemChannels.platform,
            null,
          ),
        );
        await tester.pumpWidget(PvpApp(controller: c));
        await tester.pumpAndSettle();
        final entry = find.text('Move a group from a Zoom invitation');
        if (kind != 'signed out') {
          await tester.scrollUntilVisible(
            entry,
            180,
            scrollable: find
                .descendant(
                  of: find.byKey(const PageStorageKey('rooms-home')),
                  matching: find.byType(Scrollable),
                )
                .first,
          );
        }
        await Scrollable.ensureVisible(tester.element(entry), alignment: .5);
        await tester.pumpAndSettle();
        await tester.tap(entry);
        await tester.pumpAndSettle();
        final input = find.widgetWithText(
          TextField,
          'Zoom link, full invitation, or meeting ID',
        );
        await tester.enterText(
          input,
          'https://zoom.us/j/12345678901?pwd=private',
        );
        await tester.tap(find.text('Create room from invitation'));
        await tester.pumpAndSettle();
        expect(find.text('Your reusable PVP invitation'), findsOneWidget);
        await tester.ensureVisible(find.text('Copy PVP link'));
        await tester.tap(find.text('Copy PVP link'));
        await tester.pumpAndSettle();
        expect(clipboard, (c.api as LinkApi).meeting['url']);
        expect(c.group.busy, false);
        await tester.ensureVisible(input);
        await tester.enterText(input, 'https://zoom.us/my/team');
        await tester.pumpAndSettle();
        expect(find.text('Your reusable PVP invitation'), findsNothing);
        await tester.tap(find.text('Create room from invitation'));
        await tester.pumpAndSettle();
        expect(find.textContaining('numbered join link'), findsWidgets);
        expect(tester.takeException(), isNull);
        await tester.pumpWidget(const SizedBox.shrink());
        c.dispose();
      },
    );
  }

  testWidgets('guest-created native links default to open admission', (
    tester,
  ) async {
    final c = PvpController()
      ..user = const Person('self', '~guest', 'Guest')
      ..meetingsAvailable = true
      ..openMeetingsAvailable = true;
    c.api.dispose();
    final api = LinkApi();
    c.api = api;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: MeetingDialog(c: c)),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('Create room'));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.widgetWithText(TextField, 'Room name'),
      'Weekly guests',
    );
    await tester.pump();
    await tester.tap(find.text('Create room'));
    await tester.pumpAndSettle();
    expect(api.created?['open_invite'], true);
    expect(c.group.busy, false);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
    c.dispose();
  });
}
