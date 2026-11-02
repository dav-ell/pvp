import 'dart:async';
import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/group_calls.dart';
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/core/native.dart';

class GroupHost extends NativeHost {
  final calls = <String>[];
  @override
  Future<T?> invoke<T>(String method, [dynamic arguments]) async {
    calls.add(method);
    return null;
  }
}

class GroupCapture extends GroupMedia {
  int acquisitions = 0, stops = 0;
  @override
  Future<void> acquire(Preferences preferences) async {
    acquisitions++;
  }

  @override
  Future<void> stop() async {
    stops++;
  }
}

class DelayedGroupCapture extends GroupCapture {
  final released = Completer<void>();
  @override
  Future<void> stop() async {
    stops++;
    await released.future;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const me = Person('self', 'self', 'Self');
  Map<String, dynamic> invite({bool joined = false, int revision = 1}) => {
    'type': 'room-state',
    'room_id': 'room',
    'revision': revision,
    'members': [
      {
        'id': 'self',
        'joined': joined,
        'display_name': 'Self',
        'username': 'self',
      },
    ],
  };
  test(
    'voice entry captures audio only and uses dedicated admission',
    () async {
      final media = GroupCapture(), sent = <Map<String, dynamic>>[];
      final group = GroupCalls(
        host: GroupHost(),
        media: media,
        user: () => me,
        preferences: () => Preferences(),
        send: sent.add,
        stopPreview: () async {},
        otherBusy: () => false,
      );
      group.available = true;
      group.voiceAvailable = true;
      await group.enterVoice('friends-room');
      expect(media.voiceOnly, isTrue);
      expect(media.constraints(Preferences())['video'], isFalse);
      expect(sent.single, {'type': 'voice-join', 'room_id': 'friends-room'});
      await group.cleanup();
      await group.start(['friend']);
      expect(media.voiceOnly, isTrue);
      await group.cleanup();
      group.dispose();
    },
  );
  test(
    'group invitation never captures devices and requires explicit join',
    () async {
      final media = GroupCapture(), sent = <Map<String, dynamic>>[];
      final group = GroupCalls(
        host: GroupHost(),
        media: media,
        user: () => me,
        preferences: () => Preferences(),
        send: sent.add,
        stopPreview: () async {},
        otherBusy: () => false,
      );
      await group.handle(invite());
      expect(group.busy, isTrue);
      expect(group.joined, isFalse);
      expect(media.acquisitions, 0);
      await group.join();
      expect(media.acquisitions, 1);
      expect(sent.last['type'], 'room-join');
      await group.leave();
      expect(group.busy, isFalse);
      expect(media.stops, greaterThan(0));
      group.dispose();
    },
  );
  test(
    'canceling while preview shuts down prevents new capture and late room activation',
    () async {
      final media = GroupCapture(),
          sent = <Map<String, dynamic>>[],
          preview = Completer<void>();
      final group = GroupCalls(
        host: GroupHost(),
        media: media,
        user: () => me,
        preferences: () => Preferences(),
        send: sent.add,
        stopPreview: () => preview.future,
        otherBusy: () => false,
      )..available = true;
      final start = group.start(['friend']);
      await group.leave();
      preview.complete();
      await start;
      expect(media.acquisitions, 0);
      expect(sent, isEmpty);
      await group.handle(invite(joined: true));
      expect(group.busy, isFalse);
      expect(sent.single['type'], 'room-leave');
      group.dispose();
    },
  );
  test(
    'admin mute blocks local unmute and release never enables the microphone',
    () {
      final media = GroupCapture();
      final group = GroupCalls(
        host: GroupHost(),
        media: media,
        user: () => me,
        preferences: () => Preferences(),
        send: (_) {},
        stopPreview: () async {},
        otherBusy: () => false,
      );
      group.room = invite(joined: true);
      (group.room!['members'] as List).first['moderator_muted'] = true;
      group.applyModeration();
      expect(media.muted, isTrue);
      group.toggleMic();
      expect(media.muted, isTrue);
      (group.room!['members'] as List).first['moderator_muted'] = false;
      group.applyModeration();
      expect(
        media.muted,
        isTrue,
        reason: 'allowing unmute preserves user privacy',
      );
      group.toggleMic();
      expect(media.muted, isFalse);
      group.dispose();
    },
  );
  test(
    'speaker approval chimes once and preserves microphone consent',
    () async {
      final media = GroupCapture(), host = GroupHost();
      final group = GroupCalls(
        host: host,
        media: media,
        user: () => me,
        preferences: () => Preferences(),
        send: (_) {},
        stopPreview: () async {},
        otherBusy: () => false,
      );
      Map<String, dynamic> speakingState(
        int revision,
        bool allowed, {
        bool raised = false,
      }) {
        final state = invite(joined: true, revision: revision);
        state['meeting_id'] = 'meeting';
        state['raise_hand_enabled'] = true;
        (state['members'] as List).first.addAll({
          'is_admin': false,
          'moderator_muted': !allowed,
          'hand_raised': raised,
          'speaking_allowed': allowed,
        });
        return state;
      }

      group.room = speakingState(1, false, raised: true);
      media.muted = false;
      group.applyModeration();
      expect(group.awaitingApproval, isTrue);
      expect(media.muted, isTrue);
      group.toggleMic();
      expect(
        media.muted,
        isTrue,
        reason: 'unapproved participants cannot unmute',
      );
      await group.handle(speakingState(2, true));
      expect(group.awaitingApproval, isFalse);
      expect(
        media.muted,
        isTrue,
        reason: 'permission does not turn on the microphone',
      );
      expect(host.calls.where((m) => m == 'speakingAllowed').length, 1);
      await group.handle(speakingState(2, true));
      await group.handle(speakingState(3, true));
      expect(
        host.calls.where((m) => m == 'speakingAllowed').length,
        1,
        reason: 'duplicate and unrelated roster updates stay quiet',
      );
      group.toggleMic();
      expect(media.muted, isFalse);
      await group.handle(speakingState(4, false));
      expect(media.muted, isTrue, reason: 'ending a turn immediately mutes');
      await group.handle(speakingState(5, true));
      expect(host.calls.where((m) => m == 'speakingAllowed').length, 2);
      expect(media.muted, isTrue);
      await group.cleanup();
      group.dispose();
    },
  );
  test(
    'kick cleanup stays busy until media stops and concurrent cleanup is shared',
    () async {
      final media = DelayedGroupCapture();
      final group = GroupCalls(
        host: GroupHost(),
        media: media,
        user: () => me,
        preferences: () => Preferences(),
        send: (_) {},
        stopPreview: () async {},
        otherBusy: () => false,
      );
      group.available = true;
      group.room = invite(joined: true);
      final first = group.cleanup(), second = group.cleanup();
      expect(identical(first, second), true);
      expect(group.busy, true);
      await expectLater(group.startMeeting('a' * 64), throwsStateError);
      expect(media.acquisitions, 0);
      media.released.complete();
      await first;
      expect(group.busy, false);
      expect(media.stops, 1);
      group.dispose();
    },
  );
}
