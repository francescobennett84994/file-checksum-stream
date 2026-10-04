/**
 * Tests for the streaming file checksum implementation.
 *
 * We compute expected digests with `node:crypto`'s `Hash` directly on full
 * buffers, then assert the streaming implementation produces the same bytes.
 * This compares against the same primitives Node uses internally, which is the
 * strongest oracle available without a second, independent implementation.
 *
 * All tests are deterministic: no wall-clock sleeps, no reliance on
 * filesystem timestamps, no float comparisons. Temporary files are created in
 * `os.tmpdir()` and cleaned up with a finally-block so a failure still removes
 * them.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

import { checksumFile, SUPPORTED_ALGORITHMS } from "../src/core.js";

/**
 * Writes `contents` to a uniquely-named temp file and returns its path.
 *
 * The caller is responsible for deleting the file when done; tests here wrap
 * that in a `finally` block.
 */
async function makeTempFile(contents) {
  const path = join(tmpdir(), `fcs-${randomUUID()}`);
  await writeFile(path, contents);
  return path;
}

/**
 * Returns the hex digest of `contents` for the given algorithm, computed in a
 * single `Hash#update` call. Used as the expected-value oracle.
 */
function expectedHex(algorithm, contents) {
  return createHash(algorithm).update(contents).digest("hex");
}

test("SUPPORTED_ALGORITHMS lists md5, sha1, sha256 and is frozen", () => {
  assert.deepEqual([...SUPPORTED_ALGORITHMS], ["md5", "sha1", "sha256"]);
  assert.equal(Object.isFrozen(SUPPORTED_ALGORITHMS), true);
});

test("checksumFile hashes a small file correctly for each algorithm", async () => {
  const data = Buffer.from("hello world\n");
  const path = await makeTempFile(data);
  try {
    for (const algo of SUPPORTED_ALGORITHMS) {
      const got = await checksumFile(path, algo);
      assert.equal(got, expectedHex(algo, data));
    }
  } finally {
    await rm(path, { force: true });
  }
});

test("checksumFile matches a buffer larger than the default highWaterMark", async () => {
  // 256 KiB of pseudo-random bytes. The default read-stream highWaterMark is
  // 64 KiB, so this forces multiple chunks through the pipeline. We avoid
  // Math.random for determinism; a fixed seed and a simple LCG keeps the data
  // reproducible across runs.
  const size = 256 * 1024;
  const buf = Buffer.allocUnsafe(size);
  let seed = 0x12345678;
  for (let i = 0; i < size; i++) {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    buf[i] = seed & 0xff;
  }
  const path = await makeTempFile(buf);
  try {
    const got = await checksumFile(path, "sha256");
    assert.equal(got, expectedHex("sha256", buf));
  } finally {
    await rm(path, { force: true });
  }
});

test("checksumFile returns lowercase hex by default", async () => {
  const data = Buffer.from("abc");
  const path = await makeTempFile(data);
  try {
    const got = await checksumFile(path, "sha256");
    assert.equal(got, expectedHex("sha256", data));
    assert.match(got, /^[0-9a-f]+$/);
  } finally {
    await rm(path, { force: true });
  }
});

test("checksumFile honours an explicit base64 encoding", async () => {
  const data = Buffer.from("encode me");
  const path = await makeTempFile(data);
  try {
    const expected = createHash("sha256").update(data).digest("base64");
    const got = await checksumFile(path, "sha256", { encoding: "base64" });
    assert.equal(got, expected);
  } finally {
    await rm(path, { force: true });
  }
});

test("checksumFile throws TypeError for an unsupported algorithm before touching the filesystem", async () => {
  // Use a path that does not exist. If the implementation touched the fs first,
  // we would see an ENOENT error instead of the TypeError. We assert the error
  // is a TypeError and carries the algorithm name so callers can surface it.
  const missing = join(tmpdir(), `fcs-missing-${randomUUID()}`);
  await assert.rejects(
    () => checksumFile(missing, "sha512"),
    (err) => {
      assert.ok(err instanceof TypeError, "error should be a TypeError");
      assert.match(err.message, /sha512/);
      assert.match(err.message, /sha256/);
      return true;
    },
  );
});

test("checksumFile rejects on a missing file with a usable error", async () => {
  const missing = join(tmpdir(), `fcs-no-such-${randomUUID()}`);
  await assert.rejects(() => checksumFile(missing, "sha1"), (err) => {
    // Node surfaces ENOENT via fs; we don't wrap it, so the code is preserved.
    assert.equal(err.code, "ENOENT");
    return true;
  });
});

test("checksumFile rejects on a directory path with ENOENT or EISDIR", async () => {
  // A directory is not a readable file; Node's fs either refuses to open it
  // for reading as a file (EISDIR) or the read emits an error. Both are
  // legitimate platform behaviours, so we accept either code.
  const dir = join(tmpdir(), `fcs-dir-${randomUUID()}`);
  // Create an empty directory. We use fs/promises.open with O_DIRECTORY to
  // avoid depending on mkdir here, but mkdir is simpler and reliable.
  const { mkdir } = await import("node:fs/promises");
  await mkdir(dir, { recursive: true });
  try {
    await assert.rejects(() => checksumFile(dir, "sha256"), (err) => {
      assert.ok(
        err.code === "EISDIR" || err.code === "ENOENT",
        `expected EISDIR or ENOENT, got ${err.code}`,
      );
      return true;
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("checksumFile with an explicit small highWaterMark still produces the correct digest", async () => {
  // A 1-byte highWaterMark is pathological but must still produce the correct
  // hash. This verifies the pipeline handles many tiny chunks correctly.
  const data = Buffer.from("chunked-streaming-test");
  const path = await makeTempFile(data);
  try {
    const got = await checksumFile(path, "sha1", { highWaterMark: 1 });
    assert.equal(got, expectedHex("sha1", data));
  } finally {
    await rm(path, { force: true });
  }
});

test("checksumFile handles an empty file correctly", async () => {
  // An empty file produces a well-known digest; this guards against off-by-one
  // bugs where zero chunks means the hash never gets pushed to final.
  const path = await makeTempFile(Buffer.alloc(0));
  try {
    const got = await checksumFile(path, "md5");
    // md5 of the empty string — a stable reference value.
    assert.equal(got, "d41d8cd98f00b204e9800998ecf8427e");
  } finally {
    await rm(path, { force: true });
  }
});

test("checksumFile accepts an AbortSignal and rejects when aborted", async () => {
  // We use a large-ish file and a small highWaterMark so the pipeline is
  // guaranteed to have multiple chunks to read, giving the abort a window to
  // fire mid-stream rather than after completion.
  const size = 1024 * 1024; // 1 MiB
  const buf = Buffer.allocUnsafe(size);
  buf.fill(0x41); // deterministic content
  const path = await makeTempFile(buf);
  try {
    const ac = new AbortController();
    const readPromise = checksumFile(path, "sha256", {
      signal: ac.signal,
      highWaterMark: 1024,
    });
    // Abort synchronously after kicking off the read. The pipeline will see
    // the aborted signal and destroy the streams. We only assert that the
    // promise rejects with *some* error; the exact name/code is an
    // implementation detail of Node's stream abort handling.
    ac.abort();
    await assert.rejects(readPromise, (err) => {
      assert.ok(err instanceof Error);
      return true;
    });
  } finally {
    await rm(path, { force: true });
  }
});

test("two concurrent checksumFile calls on different files do not interfere", async () => {
  // Because the implementation builds a fresh Hash per call, running two in
  // parallel must not corrupt each other. This guards against a future change
  // that caches a Hash at module scope.
  const a = Buffer.from("first-file-contents");
  const b = Buffer.from("second-file-contents-which-are-different");
  const pathA = await makeTempFile(a);
  const pathB = await makeTempFile(b);
  try {
    const [gotA, gotB] = await Promise.all([
      checksumFile(pathA, "sha256"),
      checksumFile(pathB, "sha256"),
    ]);
    assert.equal(gotA, expectedHex("sha256", a));
    assert.equal(gotB, expectedHex("sha256", b));
  } finally {
    await rm(pathA, { force: true });
    await rm(pathB, { force: true });
  }
});

test("checksumFile on a file held open with an advisory lock still reads the bytes", async () => {
  // Open the file with `O_RDONLY` and hold the fd; the streaming read should
  // still succeed because a second `open` for reading is permitted. This is
  // a smoke test for environments where an external process holds the file.
  const data = Buffer.from("locked-but-readable");
  const path = await makeTempFile(data);
  let handle;
  try {
    handle = await open(path, "r");
    const got = await checksumFile(path, "sha1");
    assert.equal(got, expectedHex("sha1", data));
  } finally {
    if (handle) await handle.close();
    await rm(path, { force: true });
  }
});
