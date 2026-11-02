import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:pvp_desktop/core/controller.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets('Keychain sign-in survives a separate native app process', (
    tester,
  ) async {
    final c = PvpController();
    await c.initialize();
    const phase = String.fromEnvironment('PVP_SESSION_PHASE');
    if (phase == 'save') {
      expect(c.user, isNull);
      expect(
        await c.authenticate(
          const String.fromEnvironment('PVP_NATIVE_USER'),
          'session-test-password-123',
          '',
          false,
        ),
        isTrue,
      );
      expect(c.message, isNot(contains('until you quit')));
      expect(await c.host.readSession(c.api.address), c.api.session);
    } else {
      expect(c.user?.username, const String.fromEnvironment('PVP_NATIVE_USER'));
      expect(c.online, isTrue);
      await c.signOut();
      expect(await c.host.readSession(c.api.address), isNull);
    }
    await c.endCall();
    c.group.dispose();
    c.api.dispose();
    c.dispose();
  });
}
