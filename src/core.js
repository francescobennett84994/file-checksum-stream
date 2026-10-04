/**
 * Core implementation of streaming file checksums.
 *
 * Design notes:
 *
 * - `createHash` is deliberately NOT re-entrant per call. Each call to
 *   `checksumFile` builds a fresh `Hash` instance so concurrent calls on
 *   different files do not interfere. We intentionally avoid any shared
 *   internal state — the function is pure with respect to its arguments.
 *
 * - We use `stream.pipeline` rather than wiring `'data'`/`'end'` by hand.
 *   `pipeline` guarantees the source is destroyed if the destination errors,
 *   and rejects on any stream error. Hand-rolled event wiring tends to leak
 *   file descriptors when the hash throws mid-way; `pipeline` closes that gap.
 *
 * - The file path is resolved relative to `process.cwd()` lazily, inside the
 *   function. This means the caller can pass paths that are absolute or
 *   relative and the result is consistent with what `fs.createReadStream` would
 *   open directly. We do not normalise the path beyond `resolve` because
 *   normalisation rules (symlinks, case-folding on case-insensitive systems)
 *   are platform-specific and the caller knows their filesystem better than we
 *   do.
 *
 * - We deliberately reject unknown algorithms eagerly (before touching the
 *   filesystem). An `ENOENT` on a real file combined with a typo'd algorithm
 *   would otherwise surface the file error and hide the more fundamental
 *   configuration error.
 *
 * - The `hash.setEncoding('hex')` call makes the final value a lowercase hex
 *   string, which is the conventional representation for file checksums and is
 *   what tools like `shasum` and `md5sum` print. If you need `base64` or raw
 *   bytes, read the file yourself — this library is opinionated on purpose.
 */

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { resolve } from "node:path";
import { pipeline } from "node:stream/promises";

/**
 * Algorithms this library knows how to use.
 *
 * Kept as a frozen array (not an `enum`) so consumers can iterate over it and
 * because ESM makes `const` reassignment hard anyway — `Object.freeze` also
 * prevents accidental mutation of the array contents.
 */
export const SUPPORTED_ALGORITHMS = Object.freeze(["md5", "sha1", "sha256"]);

const KNOWN_ALGORITHMS = new Set(SUPPORTED_ALGORITHMS);

/**
 * Options accepted by {@link checksumFile}.
 *
 * @typedef {Object} ChecksumFileOptions
 * @property {BufferEncoding} [encoding="hex"]  Output encoding. Defaults to
 *   `"hex"` to match the conventional representation of checksums. Accepts
 *   `"base64"` or `"latin1"` if you need those encodings. Raw `Buffer` output
 *   is not supported here because the function's return type is a `string`.
 * @property {number} [highWaterMark]  Optional highWaterMark for the read
 *   stream, in bytes. Forwarded to `fs.createReadStream`. Use this when the
 *   default 64 KiB chunk is too small (many small reads) or too large (tight
 *   memory) for your workload.
 * @property {AbortSignal} [signal]  Optional `AbortSignal`. If aborted, the
 *   pipeline rejects with an `AbortError` and the read stream is destroyed.
 */

/**
 * Stream a file through a Node `Hash` and return the digest as a string.
 *
 * The file is never fully buffered in memory; `pipeline` pulls chunks from the
 * read stream and feeds them to the hash, which itself only keeps its rolling
 * internal state. For multi-gigabyte files this stays at a constant few KiB of
 * resident memory regardless of file size.
 *
 * @param {string} filePath  Path to the file. Resolved relative to
 *   `process.cwd()` if not absolute. The caller is responsible for any symlink
 *   or case-sensitivity handling.
 * @param {("md5"|"sha1"|"sha256")} algorithm  Which hash to compute. Must be a
 *   member of {@link SUPPORTED_ALGORITHMS}; anything else throws before any
 *   file is opened.
 * @param {ChecksumFileOptions} [options]  Optional behaviour overrides.
 * @returns {Promise<string>}  The digest, encoded per `options.encoding`
 *   (lowercase hex by default).
 * @throws {TypeError} if `algorithm` is not one of
 *   {@link SUPPORTED_ALGORITHMS}.
 * @throws {Error} if the file cannot be opened or read, or if the stream is
 *   aborted via `options.signal`.
 */
export async function checksumFile(filePath, algorithm, options = {}) {
  if (!KNOWN_ALGORITHMS.has(algorithm)) {
    // Reject eagerly so a typo doesn't masquerade as a missing-file error.
    throw new TypeError(
      `Unsupported algorithm: ${String(algorithm)}. ` +
        `Expected one of: ${[...SUPPORTED_ALGORITHMS].join(", ")}.`,
    );
  }

  const { encoding = "hex", highWaterMark, signal } = options;

  // `createHash` accepts the algorithm name directly; we validated it above so
  // the call will not throw with `ERR_OSSL_UNSUPPORTED` for typos.
  const hash = createHash(algorithm);

  // `setEncoding` makes `hash.read()` return a string of the chosen encoding
  // once the stream is finished. Called before any data flows so the encoding
  // applies to the final digest, not to intermediate chunks.
  hash.setEncoding(encoding);

  const resolvedPath = resolve(filePath);

  const streamOptions = /** @type {import("node:fs").ReadStreamOptions} */ ({
    flags: "r",
    // `autoClose: true` is the default; stated explicitly because the whole
    // point of this library is to not leak file descriptors, and a reader
    // skimming the options should see that guarantee spelled out.
    autoClose: true,
    emitClose: true,
  });
  if (typeof highWaterMark === "number") {
    streamOptions.highWaterMark = highWaterMark;
  }
  if (signal) {
    // `fs.createReadStream` accepts `signal` directly and will destroy the
    // stream on abort. Passing it here (rather than only to `pipeline`) means
    // an abort that fires before the first chunk is read still tears down the
    // underlying fd via `autoClose`.
    streamOptions.signal = signal;
  }

  const source = createReadStream(resolvedPath, streamOptions);

  // `pipeline` returns a promise that rejects on any stream error or abort.
  await pipeline(source, hash);

  // After `'finish'`, the hash's internal buffer holds the digest in the
  // encoding we set. `hash.read()` returns it as a string (or `null` if read
  // twice, which we never do here).
  const digest = hash.read();
  if (typeof digest !== "string") {
    // Defensive: `setEncoding` was called, so this should be unreachable. If
    // a future Node change made `read()` return a `Buffer`, surfacing a clear
    // error is better than returning a value of the wrong type.
    throw new Error(
      `Unexpected digest type for ${algorithm}: expected string, got ${typeof digest}`,
    );
  }
  return digest;
}
