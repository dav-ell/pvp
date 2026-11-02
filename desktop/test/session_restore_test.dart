import 'dart:convert';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/controller.dart';
import 'package:pvp_desktop/core/media.dart';
import 'package:pvp_desktop/core/group_calls.dart';
import 'package:pvp_desktop/core/native.dart';

class SavedSessionHost extends NativeHost {
  String? saved = List.filled(64, 'a').join();
  @override
  Future<String?> readSession(String origin) async => saved;
  @override
  Future<void> saveSession(String origin, String? value) async {
    saved = value;
  }

  @override
  Future<String?> readPreferences(String key) async => null;
  @override
  Future<T?> invoke<T>(String method, [dynamic arguments]) async => null;
}

class FailedRenderer extends CallMedia {
  @override
  Future<void> initialize() async {
    throw StateError('Renderer unavailable');
  }

  @override
  Future<void> stop() async {}
}

class EmptyGroupMedia extends GroupMedia {
  @override
  Future<void> stop() async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  // This suite uses only its own loopback HTTP server.
  HttpOverrides.global = null;
  for (final status in [200, 401, 503]) {
    test(
      'native startup with media initialization failure preserves or restores session (HTTP $status)',
      () async {
        final host = SavedSessionHost(),
            server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        final sockets = <WebSocket>[];
        server.listen((request) async {
          if (WebSocketTransformer.isUpgradeRequest(request)) {
            final ws = await WebSocketTransformer.upgrade(request);
            sockets.add(ws);
            ws.listen((_) {});
            return;
          }
          request.response.headers.contentType = ContentType.json;
          if (request.uri.path == '/api/me') {
            request.response.statusCode = status;
            request.response.write(
              jsonEncode(
                status == 200
                    ? {
                        'id': 'saved',
                        'username': 'saved',
                        'display_name': 'Saved User',
                      }
                    : {'error': 'Unavailable'},
              ),
            );
          } else {
            request.response.write('[]');
          }
          await request.response.close();
        });
        final c = PvpController(
          host: host,
          media: FailedRenderer(),
          groupMedia: EmptyGroupMedia(),
          address: 'http://localhost:${server.port}',
        );
        try {
          await c.initialize();
          if (status == 200) {
            expect(c.user?.id, 'saved');
            expect(c.online, isTrue);
            expect(host.saved, isNotNull);
          }
          if (status == 401) {
            expect(c.user, isNull);
            expect(host.saved, isNull);
          }
          if (status == 503) {
            expect(c.user, isNull);
            expect(host.saved, isNotNull);
            expect(c.api.session, host.saved);
          }
        } finally {
          await c.signOut(remote: false);
          c.group.dispose();
          c.api.dispose();
          c.dispose();
          for (final socket in sockets) {
            await socket.close();
          }
          await server.close(force: true);
        }
      },
    );
  }
}
