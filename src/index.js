/**
 * File Checksum Stream — public API.
 *
 * Computes MD5, SHA1, or SHA256 hashes of files using Node.js crypto streams
 * without buffering entire files into memory.
 *
 * The hash functions themselves come from Node's `crypto` module; this library
 * just connects a `createReadStream` to a `Hash` in flowing mode and resolves
 * the digest when the stream ends. No third-party packages are used, which
 * keeps the dependency surface to exactly what Node ships.
 *
 * ESM only — there is no CommonJS build. Import from `src/index.js` (or wherever
 * the package entry points).
 */

export { checksumFile, SUPPORTED_ALGORITHMS } from "./core.js";
