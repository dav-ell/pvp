# Landing page force graph

## Build in this order

1. **Make the field move as a whole.** Keep the existing SVG and safe initial placement. Remove the dotted orbit rings. Give room bubbles soft attraction to broad areas around the hero, mutual collision, and gentle drift. The headline, buttons, explanatory text, and footer stay protected by measured obstacles. Constrain motion and hit testing at those obstacles during drag as well as at rest. Keep the SVG mask as a paint safeguard. Use the same layout rules for resize, text enlargement, and zoom, and show fewer bubbles where space is tight.
2. **Make rooms feel elastic.** Use a seeded, fixed-step model with separate room bodies and local peer positions. Start with room attraction, peer repulsion, and a small set of springs. Render the existing topology from the resulting positions, with the denser audio mesh quieter than the highlighted video routes. Drive SVG positions, hulls, and edges from a single animation loop. Drag a peer to stretch its links, or drag the soft hull to move the whole room. Preserve grab identity through updates and handle release, cancellation, and a room leaving the scene. Start with a restrained elastic preset and compare it against a looser, more buoyant one.
3. **Add passing notes.** Click, tap, or use Enter or Space on a focused room to send an illustrated note. Draw each note along the current link geometry so it follows moving peers. For forwarded video, start a child hop after its parent arrives. Keep this as a local interaction and retain the existing explanation of anonymous counts and illustrated connections. In reduced motion, highlight the same path without travel. Allow touch scrolling through the hero and make activation available without dragging.
4. **Integrate and verify.** Freeze autonomous motion while paused, offscreen, or in a hidden tab. Preserve the aggregate-only API, example and live modes, empty and unavailable states, and room-level keyboard focus. Register any new production JS module with the signaling server, which embeds and routes web assets explicitly. Run the existing network integration suite against the real server contract.

## Model and browser gates

- With a fixed seed and input trace, the pure simulation must repeat its trajectory. Check finite coordinates, bounded velocity, correct links, and protected bounds at each step.
- At release, a grabbed peer should travel visibly with the pointer, neighboring peers should follow, and the room should settle without jitter or crossing the protected area. Compare travel, recoil, and settle measurements with the orbit baseline. Choose feel by inspecting the frames and exercising the gesture in a browser.
- Exercise desktop and touch widths, the 700/701 px breakpoint, zoom and enlarged text, sparse and dense fixtures, and a 16-peer room. Confirm that focus and touch activation work and that pause and reduced motion stop autonomous travel.
- Use the browser harness for comparison and the existing `tests/network.mjs` suite for live privacy and integration checks. Replace its orbit-specific animation assertions when the simulation lands.

## Run the review harness

```sh
npm run review:network -- --browser both --preset both
node scripts/network-harness.mjs --browser both --preset baseline --root /path/to/orbit-checkout --out .build/network-harness/baseline
```

The harness renders the actual homepage from a checkout with intercepted fixtures. It saves per-scenario geometry and motion measurements alongside idle, drag, release, note, pause, touch, and keyboard screenshots. It uses screenshot pixels to check that drag and note activation visibly change the graph and that pause and reduced motion leave the graph still. Pixel differences are saved as images next to the source frames. Candidate runs also check copy clearance and the motion of neighboring peers. The baseline option records the same evidence for the original orbit renderer. Use the pure model tests for exact trajectories.

Elastic is the default. Both presets can be exercised in the harness or by opening the homepage with `?network-preset=elastic` or `?network-preset=buoyant`.

### Subagent workflow

- **Simulation and interaction builder** owns the shared model and SVG integration. Give it the baseline summary and the model gates. Have it produce evidence for both motion presets against the same fixture and report the chosen defaults.
- **Independent visual reviewer** runs the harness against the baseline and candidate checkouts in separate output directories. Ask it to cite specific frames and measurements for drag response, neighbor motion, recoil, pause, copy clearance, and touch or keyboard behavior. Ask it to rank the presets after those checks.
- The lead compares the evidence, selects the preset, and runs the real-server suite after integration. The harness only compares the UI it renders. Production privacy and topology come from the existing integration checks and the new model tests.
