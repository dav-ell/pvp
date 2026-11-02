import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'models.dart';

class PvpApi {
  final Uri origin;
  final HttpClient _client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 12);
  String? session;
  Map<String, dynamic>? signalingSocket;
  PvpApi(String address) : origin = serviceUri(address);
  String get address => origin.toString();
  Future<dynamic> request(
    String path, {
    String method = 'GET',
    Object? data,
  }) async {
    final req = await _client
        .openUrl(method, origin.resolve('/api$path'))
        .timeout(const Duration(seconds: 15));
    req.followRedirects = false;
    req.headers.set('Origin', address);
    if (session != null) req.headers.set('Cookie', 'pvp_session=$session');
    if (data != null) {
      req.headers.contentType = ContentType.json;
      req.write(jsonEncode(data));
    }
    final res = await req.close().timeout(const Duration(seconds: 20));
    final bytes = <int>[];
    final reading = Stopwatch()..start();
    await for (final chunk in res.timeout(const Duration(seconds: 20))) {
      if (reading.elapsed > const Duration(seconds: 20) ||
          bytes.length + chunk.length > 262144) {
        _client.close(force: true);
        throw const ApiException(0, 'The service response is too large.');
      }
      bytes.addAll(chunk);
    }
    final body = utf8.decode(bytes);
    dynamic result;
    try {
      result = jsonDecode(body);
    } catch (_) {
      throw ApiException(
        res.statusCode,
        'The service returned an unreadable response.',
      );
    }
    if (res.statusCode >= 300) {
      throw ApiException(
        res.statusCode,
        result is Map
            ? result['error'] ?? 'Request failed.'
            : 'Request failed.',
      );
    }
    for (final cookie in res.cookies) {
      if (cookie.name == 'pvp_session') {
        if (cookie.value.isNotEmpty &&
            !RegExp(r'^[0-9a-f]{64}$').hasMatch(cookie.value)) {
          throw const ApiException(0, 'Invalid sign-in session.');
        }
        session = cookie.value.isEmpty ? null : cookie.value;
      }
    }
    return result;
  }

  // The SDK's WebSocket.connect follows HTTP redirects. Perform a bounded,
  // non-redirecting RFC 6455 handshake so cookies stay on the selected service.
  Future<WebSocket> connect() {
    signalingSocket = null;
    var canceled = false;
    return _connect(() => canceled).timeout(
      const Duration(seconds: 15),
      onTimeout: () {
        canceled = true;
        throw const ApiException(0, 'The service connection timed out.');
      },
    );
  }

  Future<WebSocket> _connect(bool Function() canceled) async {
    if (session == null || !RegExp(r'^[0-9a-f]{64}$').hasMatch(session!)) {
      throw const ApiException(401, 'Please sign in.');
    }
    final random = Random.secure();
    final nonce = base64Encode(
      List<int>.generate(16, (_) => random.nextInt(256)),
    );
    final request = await _client.getUrl(origin.resolve('/api/ws'));
    if (canceled()) {
      request.abort();
      throw const ApiException(0, 'Connection canceled.');
    }
    request.followRedirects = false;
    request.headers
      ..set('Origin', address)
      ..set('Cookie', 'pvp_session=$session')
      ..set('Connection', 'Upgrade')
      ..set('Upgrade', 'websocket')
      ..set('Sec-WebSocket-Version', '13')
      ..set('Sec-WebSocket-Key', nonce);
    final response = await request.close();
    final expected = base64Encode(
      sha1
          .convert(utf8.encode('${nonce}258EAFA5-E914-47DA-95CA-C5AB0DC85B11'))
          .bytes,
    );
    if (canceled() ||
        response.statusCode != 101 ||
        response.headers.value('sec-websocket-accept') != expected ||
        response.headers.value('upgrade')?.toLowerCase() != 'websocket' ||
        !(response.headers
                .value('connection')
                ?.toLowerCase()
                .split(',')
                .map((v) => v.trim())
                .contains('upgrade') ??
            false) ||
        response.headers.value('sec-websocket-extensions') != null) {
      final socket = await response.detachSocket();
      socket.destroy();
      throw WebSocketException(
        'Could not connect (${response.statusCode}).',
        response.statusCode,
      );
    }
    final socket = await response.detachSocket();
    if (canceled()) {
      socket.destroy();
      throw const ApiException(0, 'Connection canceled.');
    }
    signalingSocket = {
      'source': 'Live dart:io socket',
      'sampledAt': DateTime.now().toUtc().toIso8601String(),
      'local': {
        'address': socket.address.address,
        'port': socket.port,
        'protocol': 'tcp',
      },
      'remote': {
        'address': socket.remoteAddress.address,
        'port': socket.remotePort,
        'protocol': 'tcp',
      },
    };
    return WebSocket.fromUpgradedSocket(socket, serverSide: false);
  }

  void dispose() => _client.close(force: true);
}
