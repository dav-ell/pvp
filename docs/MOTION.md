# PVP Signal motion

PVP's motion follows a direct signal between people: immediate feedback, a short
travel, a soft landing. The paired wave around a ringing avatar is the signature.
It appears for three waves, then settles; idle screens stay quiet.

Both browser and native Mac clients use the same timing:

| Purpose | Duration | Behavior |
| --- | --- | --- |
| Pointer response | 110 ms | Controls compress on press and settle on release |
| Short travel | 180 ms | Dialogs, focus, selection and speaking borders |
| Screen arrival | 280 ms | Short translation with a fast ease-out |
| List stagger | 18 ms per row, capped at 72 ms | New friends and filtered results arrive together |
| Caller wave | 1,700 ms, three cycles | Two rings, offset by 340 ms |

The ease-out curve is `cubic-bezier(.16, 1, .3, 1)`. Screens and controls become
usable as soon as their state changes. Animation never gates navigation,
answering, ending calls, or media cleanup.

## Browser

`web/motion.css` owns visual transitions, the traveling navigation marker, short
screen entrances, dialog entry/exit, pointer feedback and the paired wave.
Browsers with discrete CSS transitions animate dialog exits while preserving
native focus and Escape behavior. Other browsers close dialogs immediately.

`web/motion.js` owns interruptible Web Animations effects and list movement.
Existing rows stay still during ordinary presence updates. New rows arrive with
a bounded stagger; reordered rows travel from their previous position. Only
the first 32 rows are measured or animated. Chat transfer progress and delivery
updates do not replay message entrances. Meeting transitions run when changing
between the library, creation and a different meeting.

## Native Mac

`desktop/lib/ui/motion.dart` provides shared timing, entrances, pointer feedback,
control groups, caller waves and dialog timing. Entrances keep the same child
element throughout animation and controller updates. Replacing a call disposes
its previous media view immediately; departing video textures are not retained
for a crossfade. Signal painting has its own repaint boundary and finishes after
three waves.

## Accessibility and validation

The browser honors `prefers-reduced-motion`, including preference changes while
effects are running. Native views honor `MediaQuery.disableAnimations` and
accessible navigation. Reducing motion removes travel, press scaling and waves;
selection and call state remain visible. Native chat jumps directly to new
messages when reduced motion is enabled.

```sh
npm run test:motion
cd desktop && ../.build/flutter-security-sdk/bin/flutter test test/motion_test.dart
```

Motion regression coverage checks rapid navigation, stable friend updates,
dialog focus, live preference changes, mobile bounds, invitation centering,
media element identity, immediate disposal and actions during entrances.

## Published release

PVP Signal is live in signaling/browser 0.3.15 and the signed universal Mac app
1.0.16+17. The [release record](motion-release.json) includes public verification,
artifact hashes and rollback paths.
