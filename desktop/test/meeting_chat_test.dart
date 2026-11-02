import 'dart:async';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:pvp_desktop/core/meeting_chat.dart';

class Channel extends RTCDataChannel {
  final sent = <Map<String, dynamic>>[];
  Completer<void>? pending;
  @override
  RTCDataChannelState get state => RTCDataChannelState.RTCDataChannelOpen;
  @override
  int get id => 0;
  @override
  String get label => 'pvp-group-chat';
  @override
  int get bufferedAmount => 0;
  @override
  Future<void> send(RTCDataChannelMessage message) async {
    sent.add(Map<String, dynamic>.from(jsonDecode(message.text)));
    if (pending != null) await pending!.future;
  }

  @override
  Future<void> close() async {}
}

void main() {
  late MeetingChat chat;
  late Channel channel;
  setUp(() {
    chat = MeetingChat(self: () => 'native', error: (_) {});
    channel = Channel();
    chat.peer('browser', channel);
  });
  tearDown(() => chat.dispose());
  Map<String, dynamic> offer(
    String id, {
    int size = 3,
    String name = 'test.bin',
  }) => {
    'v': 1,
    'type': 'offer',
    'id': id,
    'name': name,
    'size': size,
    'hash': sha256.convert(utf8.encode('abc')).toString(),
  };
  test(
    'text has authenticated link identity, no duplicate messages, and no history after clear',
    () async {
      await chat.receive('browser', {
        'v': 1,
        'type': 'text',
        'id': 'a' * 32,
        'text': '<script> 🌍',
        'sender': 'owner',
      });
      await chat.receive('browser', {
        'v': 1,
        'type': 'text',
        'id': 'a' * 32,
        'text': 'replay',
      });
      expect(chat.items.length, 1);
      expect(chat.items.first.peer, 'browser');
      expect(chat.items.first.text, '<script> 🌍');
      chat.clear();
      expect(chat.items, isEmpty);
      expect(chat.ready, isEmpty);
    },
  );
  test('file consent, exact bytes and verified completion', () async {
    final id = 'a' * 32;
    await chat.receive('browser', offer(id));
    final item = chat.items.single;
    await chat.receive('browser', {
      'v': 1,
      'type': 'chunk',
      'id': id,
      'offset': 0,
      'data': 'YWJj',
    });
    expect(item.bytes, isNull);
    chat.accept(item);
    await chat.receive('browser', {
      'v': 1,
      'type': 'chunk',
      'id': id,
      'offset': 0,
      'data': 'YWJj',
    });
    expect(item.bytes, orderedEquals([97, 98, 99]));
    expect(item.status, 'Ready to save');
    chat.cancel(item);
    expect(item.bytes, isNull);
  });
  test(
    'unread counts unseen incoming messages, not transfer updates or history',
    () async {
      await chat.receive('browser', {
        'v': 1,
        'type': 'text',
        'id': 'c' * 32,
        'text': 'Hello',
      });
      expect(chat.unread, 1);
      chat.markReading(true);
      expect(chat.unread, 0);
      await chat.receive('browser', {
        'v': 1,
        'type': 'text',
        'id': 'd' * 32,
        'text': 'Still reading',
      });
      expect(chat.unread, 0);
      chat.markReading(false);
      await chat.receive('browser', offer('e' * 32));
      expect(chat.unread, 1);
      chat.markReading(true);
      chat.markReading(false);
      chat.cancel(chat.items.last);
      expect(chat.unread, 0);
      chat.clear();
      expect(chat.unread, 0);
    },
  );
  test(
    'path names and oversized files denied; corrupt and unordered data fail closed',
    () async {
      final id = 'a' * 32;
      await chat.receive('browser', offer(id, name: '../escape'));
      await chat.receive('browser', offer(id, size: chatLimit + 1));
      expect(chat.items, isEmpty);
      await chat.receive('browser', offer(id));
      chat.accept(chat.items.single);
      await chat.receive('browser', {
        'v': 1,
        'type': 'chunk',
        'id': id,
        'offset': 1,
        'data': 'YWJj',
      });
      expect(chat.items.single.status, 'Cancelled');
      await chat.receive('browser', offer('b' * 32));
      chat.accept(chat.items.last);
      await chat.receive('browser', {
        'v': 1,
        'type': 'chunk',
        'id': 'b' * 32,
        'offset': 0,
        'data': 'eHl6',
      });
      expect(chat.items.last.status, 'Integrity check failed');
      expect(chat.items.last.bytes, isNull);
    },
  );
  test(
    'receive memory is bounded; departure cancels transfer and frees budget',
    () async {
      await chat.receive('browser', offer('a' * 32, size: chatLimit));
      chat.accept(chat.items.single);
      await chat.receive('browser', offer('b' * 32));
      expect(() => chat.accept(chat.items.last), throwsStateError);
      chat.remove('browser');
      expect(chat.items.first.status, 'Cancelled');
      chat.clear();
      expect(chat.items, isEmpty);
    },
  );
  test(
    'a failed send on a retired channel cannot remove its replacement',
    () async {
      final retired = Channel()..pending = Completer<void>();
      chat.peer('browser', retired);
      final replacement = Channel();
      chat.peer('browser', replacement);
      await chat.receive('browser', {'v': 1, 'type': 'hello'});
      retired.pending!.completeError(StateError('retired'));
      await Future<void>.delayed(Duration.zero);
      expect(chat.ready, contains('browser'));
    },
  );
}
