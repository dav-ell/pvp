# PVP for Mac

Compiled Flutter UI with native WebRTC and Swift/AppKit integration. See [native design and build instructions](../docs/NATIVE.md).

```sh
flutter pub get
flutter run -d macos
flutter analyze
flutter test
```

From the repository root, run `scripts/build-macos.sh` to package the release app, or `npm run test:native` to verify actual native/browser WebRTC interoperability against an isolated Rust service.
