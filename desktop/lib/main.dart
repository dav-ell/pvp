import 'package:flutter/material.dart';
import 'core/controller.dart';
import 'ui/app.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final controller = PvpController();
  runApp(PvpApp(controller: controller));
  controller.initialize();
}
