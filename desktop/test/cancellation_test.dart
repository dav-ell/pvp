import 'dart:async';
import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/controller.dart';
import 'package:pvp_desktop/core/media.dart';
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/core/native.dart';

class DelayedWindow extends NativeHost {
  final shown = Completer<void>();
  @override
  Future<T?> invoke<T>(String method, [dynamic arguments]) async {
    if (method == 'show') await shown.future;
    return null;
  }
}

class CountingCapture extends CallMedia {
  int acquisitions = 0;
  @override
  Future<void> acquire(Preferences preferences) async {
    acquisitions++;
  }

  @override
  Future<void> stop() async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test(
    'canceling before a window action completes never opens media devices',
    () async {
      final host = DelayedWindow(), media = CountingCapture();
      final c = PvpController(host: host, media: media)..online = true;
      final calling = c.startCall(
        const Person('friend', 'jamie', 'Jamie Chen'),
      );
      await c.endCall();
      host.shown.complete();
      await calling;
      expect(media.acquisitions, 0);
      expect(c.busy, isFalse);
      c.dispose();
    },
  );
}
