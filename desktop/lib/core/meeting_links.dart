import 'models.dart';

String? meetingIdFromLink(String value, String service) {
  final raw = value.trim();
  if (RegExp(r'^[0-9a-f]{64}$').hasMatch(raw)) return raw;
  try {
    final uri = Uri.parse(raw), origin = serviceUri(service).origin;
    String? id;
    if (uri.userInfo.isNotEmpty) return null;
    if (uri.scheme == 'pvp' &&
        uri.host == 'meeting' &&
        !uri.hasPort &&
        uri.pathSegments.length == 1) {
      if (!uri.queryParameters.containsKey('origin') ||
          serviceUri(uri.queryParameters['origin']!).origin != origin) {
        return null;
      }
      id = uri.pathSegments.single;
    } else if ((uri.scheme == 'https' || uri.scheme == 'http') &&
        uri.origin == origin) {
      id = Uri.splitQueryString(uri.fragment)['meeting'];
    }
    return id != null && RegExp(r'^[0-9a-f]{64}$').hasMatch(id) ? id : null;
  } catch (_) {
    return null;
  }
}
