// Ready a self-contained Lighthouse build. Run this once before `tauri build`
// (CI runs it too). It does the two things a bundled Lighthouse needs that a
// plain checkout does not:
//
//   1. installs the Node worker's dependencies (bundled as a resource), and
//   2. fetches a pinned Node runtime for THIS build's platform into
//      src-tauri/binaries/node-<triple>[.exe], where Tauri's `externalBin`
//      picks it up.
//
// Runs on the build machine's own Node (the one that runs the Tauri CLI); the
// SHIPPED Node is the one it downloads. Native builds only: it fetches for the
// host platform, and the CI matrix builds each target on its own runner.

import { writeFile, mkdir, rm, cp, chmod, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import https from "node:https";

const HERE = dirname(fileURLToPath(import.meta.url));
const DESKTOP = join(HERE, "..");
const WORKER = join(DESKTOP, "worker");
const BINARIES = join(DESKTOP, "src-tauri", "binaries");

// Host platform/arch -> the Tauri target triple, the Node dist slug, and where
// the `node` binary sits inside that archive.
function target() {
  const key = `${process.platform}-${process.arch}`;
  const table = {
    "win32-x64": { triple: "x86_64-pc-windows-msvc", ext: ".exe", dist: "win-x64", archive: "zip", bin: "node.exe" },
    "darwin-arm64": { triple: "aarch64-apple-darwin", ext: "", dist: "darwin-arm64", archive: "tar.gz", bin: "bin/node" },
    "darwin-x64": { triple: "x86_64-apple-darwin", ext: "", dist: "darwin-x64", archive: "tar.gz", bin: "bin/node" },
    "linux-x64": { triple: "x86_64-unknown-linux-gnu", ext: "", dist: "linux-x64", archive: "tar.gz", bin: "bin/node" },
  };
  const t = table[key];
  if (!t) throw new Error(`unsupported build platform ${key}; add it to prepare-bundle.mjs`);
  return t;
}

function fetchBuffer(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { "user-agent": "slap-build" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          fetchBuffer(res.headers.location).then(resolve, reject);
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`GET ${url} -> ${res.statusCode}`));
          return;
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks)));
      })
      .on("error", reject);
  });
}

// The newest Node 22.x that satisfies the worker's `engines` (>=22.19), unless
// NODE_PIN overrides it. Pinning by policy, resolving the exact patch live, so
// the build does not break when a hardcoded patch is superseded.
async function pinnedVersion() {
  if (process.env.NODE_PIN) return process.env.NODE_PIN;
  const index = JSON.parse((await fetchBuffer("https://nodejs.org/dist/index.json")).toString());
  const v22 = index
    .map((e) => e.version)
    .filter((v) => v.startsWith("v22.") && Number(v.split(".")[1]) >= 19);
  if (!v22.length) throw new Error("no Node 22.19+ on nodejs.org");
  return v22[0]; // index.json is newest-first
}

async function installWorker() {
  console.log("Installing the Lighthouse worker dependencies...");
  // On Windows npm is a `.cmd`, which execFileSync can only launch through a
  // shell; elsewhere it is a normal executable run directly.
  const win = process.platform === "win32";
  execFileSync(win ? "npm.cmd" : "npm", ["install", "--no-audit", "--no-fund"], {
    cwd: WORKER,
    stdio: "inherit",
    shell: win,
  });
}

async function fetchNode() {
  const t = target();
  const version = await pinnedVersion();
  const slug = `node-${version}-${t.dist}`;
  const url = `https://nodejs.org/dist/${version}/${slug}.${t.archive}`;
  console.log(`Fetching a Node runtime to bundle: ${url}`);

  const tmp = join(tmpdir(), `slap-node-${process.pid}`);
  await rm(tmp, { recursive: true, force: true });
  await mkdir(tmp, { recursive: true });
  const archivePath = join(tmp, `node.${t.archive}`);
  await writeFile(archivePath, await fetchBuffer(url));

  // `tar` extracts .tar.gz everywhere and .zip on Windows (bsdtar).
  execFileSync("tar", ["-xf", archivePath, "-C", tmp], { stdio: "inherit" });

  const extracted = join(tmp, slug, t.bin);
  if (!existsSync(extracted)) throw new Error(`node binary not found at ${extracted}`);

  await mkdir(BINARIES, { recursive: true });
  // Named `slap-node`, not `node`: Tauri strips the triple and drops the
  // sidecar beside the main binary (e.g. /usr/bin), where a literal `node`
  // would collide with a system Node package.
  const dest = join(BINARIES, `slap-node-${t.triple}${t.ext}`);
  await cp(extracted, dest);
  if (t.ext === "") await chmod(dest, 0o755);
  await rm(tmp, { recursive: true, force: true });

  const mb = ((await stat(dest)).size / 1048576).toFixed(1);
  console.log(`Wrote ${dest} (${mb} MB) for target ${t.triple}`);
}

await installWorker();
await fetchNode();
console.log("Bundle prerequisites ready. Now run: tauri build");
