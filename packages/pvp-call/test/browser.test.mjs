import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { chromium } from "playwright-core";

test(
  "Standalone package: four-party encrypted audio, optional video, mute, direct-route evidence and disposal",
  { timeout: 60000 },
  async () => {
    const root = fileURLToPath(new URL("../", import.meta.url));
    const server = http.createServer(async (req, res) => {
      if (req.url === "/") {
        res.setHeader("content-type", "text/html");
        res.end("<!doctype html><title>PVP library test</title>");
        return;
      }
      const file = path.resolve(
        root,
        "." + new URL(req.url, "http://localhost").pathname,
      );
      if (!file.startsWith(root) || !file.endsWith(".js")) {
        res.writeHead(404);
        res.end();
        return;
      }
      try {
        await stat(file);
        res.setHeader("content-type", "text/javascript");
        res.end(await readFile(file));
      } catch {
        res.writeHead(404);
        res.end();
      }
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const chrome =
      process.env.CHROME_PATH ||
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
    const browser = await chromium.launch({
      headless: true,
      ...(existsSync(chrome) ? { executablePath: chrome } : {}),
      args: ["--autoplay-policy=no-user-gesture-required"],
    });
    try {
      const page = await browser.newPage();
      const errors = [];
      page.on("pageerror", (e) => errors.push(e.message));
      await page.goto("http://127.0.0.1:" + server.address().port);
      await page.evaluate(async () => {
        const { PvpMesh, MediaController, CallRoom } = await import(
          "/src/index.js"
        );
        const ids = ["a", "b", "c", "d"],
          members = ids.map((id) => ({
            id,
            name: id,
            epoch: "participant_" + id,
            connected: true,
          }));
        const meshes = {},
          media = {},
          videos = {},
          failures = [];
        const room = new CallRoom({
          roster: () => members,
          deliver: (id, event) => {
            if (event.kind === "signal")
              queueMicrotask(() =>
                meshes[id]
                  .receive(event.from, event.signal)
                  .catch((e) => failures.push(e.message)),
              );
          },
        });
        for (const [index, id] of ids.entries()) {
          media[id] = new MediaController({
            capture: async (c) => {
              const stream = new MediaStream();
              if (c.audio) {
                const context = new AudioContext(),
                  tone = context.createOscillator(),
                  gain = context.createGain(),
                  out = context.createMediaStreamDestination();
                tone.frequency.value = 300 + index * 100;
                gain.gain.value = 0.04;
                tone.connect(gain);
                gain.connect(out);
                tone.start();
                await context.resume();
                const t = out.stream.getAudioTracks()[0],
                  stop = t.stop.bind(t);
                t.stop = () => {
                  stop();
                  tone.stop();
                  context.close();
                };
                stream.addTrack(t);
              }
              if (c.video) {
                const canvas = document.createElement("canvas");
                canvas.width = 640;
                canvas.height = 480;
                const ctx = canvas.getContext("2d");
                ctx.fillStyle = "#ee2244";
                const tick = () => ctx.fillRect(0, 0, 640, 480);
                tick();
                const timer = setInterval(tick, 100);
                const t = canvas.captureStream(10).getVideoTracks()[0],
                  stop = t.stop.bind(t);
                t.stop = () => {
                  clearInterval(timer);
                  stop();
                };
                stream.addTrack(t);
              }
              return stream;
            },
            changed: () => meshes[id]?.updateStream(),
          });
          if (id !== "d") await media[id].enable("audio");
          meshes[id] = new PvpMesh({
            self: members[index],
            stream: media[id].stream,
            send: (to, signal) => {
              const deliver = () =>
                room.receive(id, { kind: "signal", to, signal });
              if (signal.type === "offer") setTimeout(deliver, 150);
              else deliver();
            },
            onError: (e) => failures.push(e.message),
            onStream: (from, stream) => {
              if (!stream) return;
              const video =
                videos[id + "_" + from] || document.createElement("video");
              video.muted = true;
              video.autoplay = true;
              video.playsInline = true;
              video.srcObject = stream;
              document.body.append(video);
              videos[id + "_" + from] = video;
              video.play().catch(() => {});
            },
          });
          room.receive(id, {
            kind: "state",
            state: {
              epoch: members[index].epoch,
              mic: id !== "d",
              camera: false,
            },
          });
        }
        for (const mesh of Object.values(meshes)) mesh.setPeers(members);
        window.fixture = { meshes, media, videos, failures, room, members };
      });
      await page.waitForFunction(() =>
        Object.values(fixture.meshes).every(
          (m) =>
            m.links.size === 3 &&
            [...m.links.values()].every(
              (l) => l.pc.connectionState === "connected",
            ),
        ),
      );
      await page.waitForFunction(async () => {
        await Promise.all(Object.values(fixture.meshes).map((m) => m.sample()));
        return Object.values(fixture.meshes).every((m) =>
          [...m.links.values()].some((l) =>
            l.evidence?.media.some(
              (s) =>
                s.kind === "audio" && s.direction === "incoming" && s.bytes > 0,
            ),
          ),
        );
      });
      assert.equal(
        await page.evaluate(() =>
          Object.values(fixture.media).every((m) => m.get("video") === null),
        ),
        true,
      );
      assert.equal(
        await page.evaluate(
          () =>
            fixture.media.d.getTracks?.length ||
            fixture.media.d.stream.getTracks().length,
        ),
        0,
      );
      await page.evaluate(() => fixture.media.a.enable("video"));
      await page.waitForFunction(() =>
        ["b", "c", "d"].every(
          (id) => fixture.videos[id + "_a"]?.videoWidth > 0,
        ),
      );
      await page.evaluate(() => fixture.media.a.mute(true));
      assert.equal(
        await page.evaluate(() => fixture.media.a.get("audio").enabled),
        false,
      );
      await page.evaluate(() => fixture.media.a.disable("video"));
      assert.equal(
        await page.evaluate(() => fixture.media.a.get("video")),
        null,
      );
      await page.evaluate(() => fixture.meshes.a.retry("b", 0));
      await page.waitForFunction(
        () =>
          fixture.meshes.a.links.get("b").generation === 2 &&
          fixture.meshes.b.links.get("a").generation === 2 &&
          fixture.meshes.a.links.get("b").pc.connectionState === "connected" &&
          fixture.meshes.b.links.get("a").pc.connectionState === "connected",
      );
      await page.evaluate(() =>
        Promise.all(Object.values(fixture.meshes).map((m) => m.sample())),
      );
      assert.equal(
        await page.evaluate(() =>
          Object.values(fixture.meshes).every((m) =>
            [...m.links.values()].every((l) => l.evidence?.direct),
          ),
        ),
        true,
      );
      assert.deepEqual(await page.evaluate(() => fixture.failures), []);
      await page.evaluate(() => {
        for (const m of Object.values(fixture.meshes)) m.close();
        for (const m of Object.values(fixture.media)) m.stop();
      });
      assert.equal(
        await page.evaluate(
          () =>
            Object.values(fixture.meshes).every((m) => m.links.size === 0) &&
            Object.values(fixture.media).every(
              (m) => m.stream.getTracks().length === 0,
            ),
        ),
        true,
      );
      assert.deepEqual(errors, []);
    } finally {
      await browser.close();
      await new Promise((resolve) => server.close(resolve));
    }
  },
);
