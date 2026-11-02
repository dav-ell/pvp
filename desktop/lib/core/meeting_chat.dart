import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter/foundation.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:crypto/crypto.dart';

const chatLimit = 100 * 1024 * 1024, chatChunk = 16384;

class ChatItem {
  final String id, peer;
  String? text, name, hash, author;
  int size;
  String status;
  Uint8List? bytes;
  DateTime? expires;
  final receipts = <String>{};
  ChatItem(
    this.id,
    this.peer, {
    this.text,
    this.name,
    this.hash,
    this.size = 0,
    this.status = 'Offered',
    this.expires,
  });
}

class _Peer {
  final RTCDataChannel channel;
  bool ready = false;
  Future<void> chain = Future.value();
  DateTime at = DateTime.now();
  int count = 0, metadata = 0;
  _Peer(this.channel);
}

class _File {
  final Uint8List bytes;
  final Set<String> allowed;
  _File(this.bytes, this.allowed);
}

class _Incoming {
  final ChatItem item;
  final data = BytesBuilder(copy: false);
  int received = 0;
  Timer? timer;
  _Incoming(this.item);
}

class _Job {
  final String id;
  bool cancelled = false;
  _Job(this.id);
}

class MeetingChat extends ChangeNotifier {
  final String Function() self;
  final String Function(String) name;
  final void Function(String) error;
  final _peers = <String, _Peer>{};
  final items = <ChatItem>[];
  final _files = <String, _File>{},
      _incoming = <String, _Incoming>{},
      _jobs = <String, _Job>{};
  int _generation = 0, _reserved = 0;
  bool _disposed = false;
  bool reading = false;
  final _seen = <String>{};
  int get unread => items
      .where((i) => i.peer != self() && !_seen.contains('${i.peer}:${i.id}'))
      .length;
  void markReading(bool value) {
    reading = value;
    if (value) {
      for (final i in items) {
        _seen.add('${i.peer}:${i.id}');
      }
    }
    notifyListeners();
  }

  @override
  void notifyListeners() {
    if (reading) {
      for (final i in items) {
        _seen.add('${i.peer}:${i.id}');
      }
    }
    super.notifyListeners();
  }

  MeetingChat({
    required this.self,
    required this.error,
    String Function(String)? name,
  }) : name = name ?? ((id) => id);
  String newId() => List.generate(
    16,
    (_) => Random.secure().nextInt(256).toRadixString(16).padLeft(2, '0'),
  ).join();
  bool validId(dynamic id) =>
      id is String && RegExp(r'^[a-f0-9]{32}$').hasMatch(id);
  List<String> get ready => _peers.entries
      .where(
        (p) =>
            p.value.ready &&
            p.value.channel.state == RTCDataChannelState.RTCDataChannelOpen,
      )
      .map((p) => p.key)
      .toList();
  void add(ChatItem item) {
    if (items.length >= 200) {
      final old = items.removeAt(0);
      cancel(old);
    }
    item.author = name(item.peer);
    items.add(item);
    notifyListeners();
  }

  bool send(String peer, Map<String, dynamic> message) {
    final p = _peers[peer];
    if (p?.channel.state != RTCDataChannelState.RTCDataChannelOpen) {
      return false;
    }
    unawaited(
      p!.channel
          .send(RTCDataChannelMessage(jsonEncode({'v': 1, ...message})))
          .catchError((Object _) {
            if (_peers[peer] == p) {
              remove(peer);
            }
          }),
    );
    return true;
  }

  void peer(String id, RTCDataChannel channel) {
    remove(id);
    final p = _Peer(channel);
    _peers[id] = p;
    channel.onDataChannelState = (state) {
      if (state == RTCDataChannelState.RTCDataChannelOpen) {
        send(id, {'type': 'hello'});
      } else if (state == RTCDataChannelState.RTCDataChannelClosed &&
          _peers[id] == p) {
        remove(id);
      }
    };
    if (channel.state == RTCDataChannelState.RTCDataChannelOpen) {
      send(id, {'type': 'hello'});
    }
    channel.onMessage = (event) {
      if (event.isBinary || event.text.length > 24000 || _peers[id] != p) {
        return;
      }
      if (DateTime.now().difference(p.at).inSeconds >= 1) {
        p.at = DateTime.now();
        p.count = 0;
        p.metadata = 0;
      }
      if (++p.count > 120) return;
      Map<String, dynamic> message;
      try {
        message = Map<String, dynamic>.from(jsonDecode(event.text));
      } catch (_) {
        return;
      }
      if (message['type'] != 'chunk' && ++p.metadata > 10) return;
      p.chain = p.chain
          .then((_) => receive(id, message))
          .catchError((Object _) {});
    };
  }

  void text(String value) {
    value = value.trim();
    if (value.isEmpty || value.length > 4000) {
      throw StateError('Messages support up to 4,000 characters.');
    }
    if (ready.isEmpty) {
      throw StateError('Waiting for a participant with chat support.');
    }
    final id = newId();
    for (final peer in ready) {
      send(peer, {'type': 'text', 'id': id, 'text': value});
    }
    add(ChatItem(id, self(), text: value, status: 'Sent'));
  }

  void offer(String name, Uint8List bytes) {
    if (bytes.isEmpty || bytes.length > chatLimit) {
      throw StateError('Choose a file between 1 byte and 100 MiB.');
    }
    if (_files.values.fold<int>(0, (n, f) => n + f.bytes.length) +
            bytes.length >
        chatLimit) {
      throw StateError(
        'Clear an earlier attachment before sharing more files.',
      );
    }
    final targets = ready;
    if (targets.isEmpty) {
      throw StateError('Waiting for a participant with chat support.');
    }
    name = name.replaceAll(RegExp(r'[\x00-\x1f\x7f/\\]'), '_');
    if (name.length > 200) name = name.substring(0, 200);
    name = name.trim();
    if (name.isEmpty || name == '.' || name == '..') name = 'attachment';
    final id = newId(), hash = sha256.convert(bytes).toString();
    _files[id] = _File(bytes, targets.toSet());
    add(ChatItem(id, self(), name: name, size: bytes.length, hash: hash));
    for (final peer in targets) {
      send(peer, {
        'type': 'offer',
        'id': id,
        'name': name,
        'size': bytes.length,
        'hash': hash,
      });
    }
  }

  Future<void> receive(String peer, Map<String, dynamic> m) async {
    if (m['v'] != 1 || !_peers.containsKey(peer)) return;
    if (m['type'] == 'hello') {
      final p = _peers[peer]!;
      if (!p.ready) {
        p.ready = true;
        send(peer, {'type': 'hello'});
        notifyListeners();
      }
      return;
    }
    if (!validId(m['id'])) return;
    final id = m['id'] as String, key = '$peer:$id';
    switch (m['type']) {
      case 'text':
        final text = m['text'];
        if (text is! String ||
            text.trim().isEmpty ||
            text.length > 4000 ||
            items.any((i) => i.peer == peer && i.id == id)) {
          return;
        }
        add(ChatItem(id, peer, text: text, status: 'Received'));
        send(peer, {'type': 'ack', 'id': id});
      case 'ack':
        final item = items
            .where((i) => i.id == id && i.peer == self())
            .firstOrNull;
        if (item != null) {
          item.receipts.add(peer);
          item.status = 'Delivered to ${item.receipts.length}';
          notifyListeners();
        }
      case 'offer':
        final name = m['name'], size = m['size'], hash = m['hash'];
        if (name is! String ||
            name.trim().isEmpty ||
            name == '.' ||
            name == '..' ||
            name.length > 200 ||
            RegExp(r'[\x00-\x1f\x7f/\\]').hasMatch(name) ||
            size is! int ||
            size < 1 ||
            size > chatLimit ||
            hash is! String ||
            !RegExp(r'^[a-f0-9]{64}$').hasMatch(hash) ||
            items.any((i) => i.peer == peer && i.id == id)) {
          return;
        }
        add(
          ChatItem(
            id,
            peer,
            name: name,
            size: size,
            hash: hash,
            expires: DateTime.now().add(const Duration(minutes: 5)),
          ),
        );
      case 'accept':
        final file = _files[id];
        if (file == null || !file.allowed.contains(peer)) return;
        if (_jobs.containsKey(peer)) {
          send(peer, {'type': 'cancel', 'id': id});
          return;
        }
        file.allowed.remove(peer);
        unawaited(
          _transfer(peer, id, file).catchError((Object e) {
            send(peer, {'type': 'cancel', 'id': id});
            error(e.toString());
          }),
        );
      case 'chunk':
        final rx = _incoming[key];
        if (rx == null) return;
        final encoded = m['data'];
        if (m['offset'] != rx.received ||
            encoded is! String ||
            encoded.length > 21848) {
          cancel(rx.item);
          return;
        }
        Uint8List data;
        try {
          data = base64Decode(encoded);
        } catch (_) {
          cancel(rx.item);
          return;
        }
        if (data.isEmpty ||
            data.length > chatChunk ||
            rx.received + data.length > rx.item.size) {
          cancel(rx.item);
          return;
        }
        rx.data.add(data);
        rx.received += data.length;
        rx.item.status =
            'Receiving ${(100 * rx.received / rx.item.size).floor()}%';
        _timeout(rx);
        if (rx.received == rx.item.size) {
          rx.timer?.cancel();
          _incoming.remove(key);
          final bytes = rx.data.takeBytes();
          if (sha256.convert(bytes).toString() != rx.item.hash) {
            _reserved -= rx.item.size;
            rx.item.status = 'Integrity check failed';
            send(peer, {'type': 'cancel', 'id': id});
          } else {
            rx.item.bytes = bytes;
            rx.item.status = 'Ready to save';
            send(peer, {'type': 'ack', 'id': id});
          }
        }
        notifyListeners();
      case 'cancel':
        _files[id]?.allowed.remove(peer);
        final offered = items
            .where((i) => i.id == id && i.peer == peer)
            .firstOrNull;
        if (offered?.status == 'Offered') offered!.status = 'Cancelled';
        final rx = _incoming.remove(key);
        if (rx != null) {
          rx.timer?.cancel();
          _reserved -= rx.item.size;
          rx.item.status = 'Cancelled';
          notifyListeners();
        }
        if (_jobs[peer]?.id == id) _jobs[peer]!.cancelled = true;
        notifyListeners();
    }
  }

  void _timeout(_Incoming rx) {
    rx.timer?.cancel();
    rx.timer = Timer(const Duration(seconds: 30), () => cancel(rx.item));
  }

  void accept(ChatItem item) {
    if (item.status != 'Offered' || DateTime.now().isAfter(item.expires!)) {
      throw StateError('Offer expired. Ask the sender to share it again.');
    }
    if (_reserved + item.size > chatLimit ||
        _incoming.values.any((rx) => rx.item.peer == item.peer)) {
      throw StateError(
        'Clear an attachment first; one incoming transfer per sender and 100 MiB total.',
      );
    }
    if (!send(item.peer, {'type': 'accept', 'id': item.id})) {
      throw StateError('Sender disconnected.');
    }
    _reserved += item.size;
    final rx = _Incoming(item);
    _incoming['${item.peer}:${item.id}'] = rx;
    _timeout(rx);
    item.status = 'Receiving 0%';
    notifyListeners();
  }

  void cancel(ChatItem item) {
    final rx = _incoming.remove('${item.peer}:${item.id}');
    if (rx != null) {
      rx.timer?.cancel();
      _reserved -= item.size;
    }
    if (item.peer == self()) {
      for (final peer in _files[item.id]?.allowed ?? <String>{}) {
        send(peer, {'type': 'cancel', 'id': item.id});
      }
      for (final entry in _jobs.entries) {
        if (entry.value.id == item.id) {
          entry.value.cancelled = true;
          send(entry.key, {'type': 'cancel', 'id': item.id});
        }
      }
      _files.remove(item.id);
    } else {
      send(item.peer, {'type': 'cancel', 'id': item.id});
    }
    if (item.bytes != null) {
      _reserved -= item.bytes!.length;
      item.bytes = null;
    }
    item.status = 'Cancelled';
    notifyListeners();
  }

  Future<void> _transfer(String peer, String id, _File file) async {
    final job = _Job(id), generation = _generation;
    _jobs[peer] = job;
    try {
      for (var offset = 0; offset < file.bytes.length; offset += chatChunk) {
        final started = DateTime.now();
        while ((_peers[peer]?.channel.bufferedAmount ?? 0) > 262144) {
          if (job.cancelled || generation != _generation) return;
          if (DateTime.now().difference(started).inSeconds > 30) {
            throw StateError('File transfer stalled.');
          }
          await Future<void>.delayed(const Duration(milliseconds: 25));
        }
        if (job.cancelled || generation != _generation) return;
        if (!send(peer, {
          'type': 'chunk',
          'id': id,
          'offset': offset,
          'data': base64Encode(
            Uint8List.sublistView(
              file.bytes,
              offset,
              min(offset + chatChunk, file.bytes.length),
            ),
          ),
        })) {
          throw StateError('Participant disconnected during transfer.');
        }
        final item = items
            .where((i) => i.id == id && i.peer == self())
            .firstOrNull;
        if (item != null) {
          item.status =
              'Sending · ${min(100, (100 * (offset + chatChunk) / file.bytes.length).floor())}%';
          notifyListeners();
        }
        if (offset + chatChunk < file.bytes.length) {
          await Future<void>.delayed(
            Duration(milliseconds: 63 * max(1, _jobs.length)),
          );
        }
      }
    } finally {
      if (_jobs[peer] == job) _jobs.remove(peer);
    }
  }

  void remove(String peer) {
    if (_disposed) return;
    _peers.remove(peer);
    for (final file in _files.values) {
      file.allowed.remove(peer);
    }
    _jobs[peer]?.cancelled = true;
    for (final rx in _incoming.values.toList()) {
      if (rx.item.peer == peer) cancel(rx.item);
    }
    for (final item in items) {
      if (item.peer == peer && item.status == 'Offered') {
        item.status = 'Sender disconnected';
      }
    }
    notifyListeners();
  }

  void clear() {
    _generation++;
    for (final rx in _incoming.values) {
      rx.timer?.cancel();
    }
    for (final job in _jobs.values) {
      job.cancelled = true;
    }
    _peers.clear();
    _incoming.clear();
    _files.clear();
    _jobs.clear();
    items.clear();
    _seen.clear();
    _reserved = 0;
    notifyListeners();
  }

  @override
  void dispose() {
    clear();
    _disposed = true;
    super.dispose();
  }
}
