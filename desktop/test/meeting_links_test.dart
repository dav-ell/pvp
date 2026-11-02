import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/meeting_links.dart';

void main() {
  final id = 'a' * 64;
  test(
    'same-service recurring links and native handoff resolve the same ID',
    () {
      expect(
        meetingIdFromLink(
          'https://lopixel.space/#meeting=$id',
          'https://lopixel.space',
        ),
        id,
      );
      expect(
        meetingIdFromLink(
          'pvp://meeting/$id?origin=https%3A%2F%2Flopixel.space',
          'https://lopixel.space',
        ),
        id,
      );
      expect(meetingIdFromLink(' $id ', 'https://lopixel.space'), id);
    },
  );
  test('links cannot switch service or smuggle credentials', () {
    for (final link in [
      'https://other.example/#meeting=$id',
      'https://user:password@lopixel.space/#meeting=$id',
      'pvp://meeting/$id?origin=https%3A%2F%2Fother.example',
      'pvp://meeting/$id',
      'pvp://user@meeting/$id?origin=https%3A%2F%2Flopixel.space',
      'pvp://meeting:123/$id?origin=https%3A%2F%2Flopixel.space',
      'https://lopixel.space/#meeting=${'A' * 64}',
      'https://lopixel.space/#meeting=abc',
    ]) {
      expect(
        meetingIdFromLink(link, 'https://lopixel.space'),
        isNull,
        reason: link,
      );
    }
  });
}
