import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/api.dart';
import 'package:pvp_desktop/core/controller.dart';
import 'package:pvp_desktop/core/group_calls.dart';
import 'package:pvp_desktop/core/media.dart';
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/ui/app.dart';
import 'package:pvp_desktop/ui/brand_tokens.dart';
import 'package:pvp_desktop/ui/polish.dart';

class RoomApi extends PvpApi {
  RoomApi() : super('https://lopixel.space');
  final room = <String, dynamic>{
    'meeting_id': 'a' * 64,
    'name': 'Sunday circle',
    'url': 'https://lopixel.space/#meeting=${'a' * 64}',
    'owner_id': 'self',
    'open_invite': true,
    'participants': [],
    'members': [
      {
        'id': 'self',
        'username': '~guest',
        'display_name': 'Alex',
        'is_admin': true,
      },
    ],
  };
  @override
  Future<dynamic> request(
    String path, {
    String method = 'GET',
    Object? data,
  }) async => path == '/meetings' ? [room] : room;
}

void main() {
  for (final guest in [false, true]) {
    for (final width in [390.0, 860.0, 1440.0]) {
      for (final scale in [1.0, 2.0]) {
        testWidgets(
          'Rooms stays home for ${guest ? 'guest' : 'account'} at $width and scale $scale',
          (tester) async {
            tester.view.devicePixelRatio = 1;
            tester.view.physicalSize = Size(width, 900);
            addTearDown(tester.view.resetPhysicalSize);
            addTearDown(tester.view.resetDevicePixelRatio);
            var captures = 0;
            final api = RoomApi();
            final c =
                PvpController(
                    media: CallMedia(
                      captureOverride: (_) async {
                        captures++;
                        throw StateError('Unexpected capture');
                      },
                    ),
                    groupMedia: GroupMedia(
                      captureOverride: (_) async {
                        captures++;
                        throw StateError('Unexpected capture');
                      },
                    ),
                  )
                  ..loading = false
                  ..user = Person('self', guest ? '~guest' : 'alex', 'Alex')
                  ..meetingsAvailable = true
                  ..openMeetingsAvailable = true
                  ..online = true;
            c.api.dispose();
            c.api = api;
            c.meetings = [api.room];
            await tester.pumpWidget(
              MediaQuery(
                data: MediaQueryData(
                  size: Size(width, 900),
                  textScaler: TextScaler.linear(scale),
                ),
                child: PvpApp(controller: c),
              ),
            );
            await tester.pumpAndSettle();
            expect(c.page, 'rooms');
            expect(find.text('Your rooms.'), findsOneWidget);
            await tester.scrollUntilVisible(
              find.text('Join room'),
              160,
              scrollable: find
                  .descendant(
                    of: find.byKey(const PageStorageKey('rooms-home')),
                    matching: find.byType(Scrollable),
                  )
                  .first,
            );
            expect(find.text('Sunday circle'), findsOneWidget);
            expect(find.text('Open more private Zoom'), findsNothing);
            expect(
              Theme.of(
                tester.element(find.text('Your rooms.')),
              ).scaffoldBackgroundColor,
              PvpBrandColors.paper,
            );
            expect(tester.takeException(), isNull);
            await Scrollable.ensureVisible(
              tester.element(find.text('Join room')),
              alignment: .5,
            );
            await tester.pumpAndSettle();
            expect(
              tester
                  .getSize(
                    find.ancestor(
                      of: find.text('Join room'),
                      matching: find.byType(FilledButton),
                    ),
                  )
                  .height,
              greaterThanOrEqualTo(44),
            );
            await tester.tap(find.text('Join room'));
            await tester.pumpAndSettle();
            expect(find.text('Join to listen'), findsOneWidget);
            expect(find.text('Join with microphone'), findsOneWidget);
            final listen = tester.widget<FilledButton>(
              find.ancestor(
                of: find.text('Join to listen'),
                matching: find.byWidgetPredicate((w) => w is FilledButton),
              ),
            );
            expect(listen.onPressed, isNotNull);
            expect(
              captures,
              0,
              reason: 'Opening a room preview never captures devices',
            );
            expect(c.group.busy, isFalse);
            expect(tester.takeException(), isNull);
            await tester.tap(find.byTooltip('Close rooms'));
            await tester.pumpAndSettle();
            c.rememberMeeting(api.room['meeting_id'], 'Sunday circle');
            await tester.pumpAndSettle();
            expect(find.text('Return to room'), findsOneWidget);
            expect(c.page, 'rooms');
            expect(captures, 0);
            expect(tester.takeException(), isNull);
            await tester.pumpWidget(const SizedBox.shrink());
            c.dispose();
          },
        );
      }
    }
  }

  testWidgets('self preview expands without replacing its video child', (
    tester,
  ) async {
    final childKey = GlobalKey();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SizedBox(
            width: 800,
            height: 500,
            child: ExpandableSelfPreview(
              child: ColoredBox(key: childKey, color: Colors.black),
            ),
          ),
        ),
      ),
    );
    final element = childKey.currentContext;
    final initial = tester.getSize(find.byKey(childKey));
    await tester.tap(find.byTooltip('Expand your preview'));
    await tester.pumpAndSettle();
    expect(childKey.currentContext, same(element));
    expect(
      tester.getSize(find.byKey(childKey)).width,
      greaterThan(initial.width),
    );
    expect(find.byTooltip('Shrink your preview'), findsOneWidget);
    await tester.tap(find.byTooltip('Shrink your preview'));
    await tester.pumpAndSettle();
    expect(tester.getSize(find.byKey(childKey)), initial);
    expect(tester.takeException(), isNull);
    final c = PvpController()
      ..loading = false
      ..user = const Person('self', 'alex', 'Alex')
      ..peer = const Person('peer', 'jo', 'Jo')
      ..phase = 'connected'
      ..callId = 'contrast-test';
    await tester.pumpWidget(PvpApp(controller: c));
    await tester.pumpAndSettle();
    final stageText = tester.element(find.text('Jo').first);
    expect(
      DefaultTextStyle.of(stageText).style.color,
      PvpBrandColors.stageText,
    );
    expect(
      Theme.of(stageText).inputDecorationTheme.fillColor,
      PvpBrandColors.stageSurface,
    );
    expect(
      Theme.of(stageText).dialogTheme.contentTextStyle?.color,
      PvpBrandColors.stageText,
    );
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
    c.dispose();
  });
}
