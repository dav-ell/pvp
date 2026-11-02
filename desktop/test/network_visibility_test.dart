import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/api.dart';
import 'package:pvp_desktop/core/controller.dart';
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/ui/meetings.dart';

class NetworkApi extends PvpApi {
  NetworkApi() : super('https://lopixel.space');
  Object? sent;
  @override
  Future<dynamic> request(
    String path, {
    String method = 'GET',
    Object? data,
  }) async {
    expect(path, '/meetings/test-room/network');
    expect(method, 'POST');
    sent = data;
    return {};
  }
}

void main() {
  testWidgets(
    'only the owner can share a room shape, with explicit off-by-default control',
    (tester) async {
      final api = NetworkApi(),
          c = PvpController()
            ..loading = false
            ..user = const Person('owner', 'alex', 'Alex');
      c.api.dispose();
      c.api = api;
      final room = <String, dynamic>{
        'meeting_id': 'test-room',
        'owner_id': 'owner',
        'open_invite': true,
        'network_visible': false,
      };
      var changed = 0;
      Future<void> show() async {
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: Builder(
                builder: (context) => meetingNetworkSetting(
                  context,
                  c,
                  room,
                  onChanged: () async {
                    changed++;
                  },
                ),
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();
      }

      await show();
      await tester.tap(find.text('Public room map'));
      await tester.pumpAndSettle();
      expect(
        tester.widget<SwitchListTile>(find.byType(SwitchListTile)).value,
        false,
      );
      await tester.tap(find.byType(Switch));
      await tester.pumpAndSettle();
      expect(api.sent, {'visible': true});
      expect(changed, 1);
      c.user = const Person('guest', 'sam', 'Sam');
      room['network_visible'] = true;
      await show();
      expect(find.byType(SwitchListTile), findsNothing);
      expect(find.textContaining('shares its anonymous size'), findsOneWidget);
      room['network_visible'] = false;
      await show();
      expect(find.textContaining('shares its anonymous size'), findsNothing);
      c.user = const Person('owner', 'alex', 'Alex');
      room['open_invite'] = false;
      await show();
      expect(find.byType(SwitchListTile), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
      c.dispose();
    },
  );
}
