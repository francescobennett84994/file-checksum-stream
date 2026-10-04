# File Checksum Stream

Computes MD5, SHA1, or SHA256 digests of files by streaming them through Node's `crypto.Hash`, without buffering the whole file into memory. ESM only, zero runtime dependencies.

## Usage

```js
import { checksumFile, SUPPORTED_ALGORITHMS } from "file-checksum-stream";

const sha256 = await checksumFile("./package.json", "sha256");
console.log(sha256); // lowercase hex string

for (const algo of SUPPORTED_ALGORITHMS) {
  console.log(algo, await checksumFile("./package.json", algo));
}
```

`checksumFile(filePath, algorithm, options?)` returns a `Promise<string>`.

- `algorithm` must be one of `"md5"`, `"sha1"`, `"sha256"`. Anything else throws `TypeError` before the filesystem is touched.
- `options.encoding` — output encoding, defaults to `"hex"` (lowercase). Also accepts `"base64"` or `"latin1"`.
- `options.highWaterMark` — read-stream chunk size in bytes, forwarded to `fs.createReadStream`.
- `options.signal` — an `AbortSignal`; aborting destroys the read stream and the promise rejects.

## Why this exists

The problem is simple: hashing a multi-gigabyte file should not allocate a multi-gigabyte buffer. Node's `crypto` module already solves this if you wire `fs.createReadStream` into a `Hash` yourself; this library exists to do that wiring once, correctly, and to reject bad algorithms before opening a file descriptor. The trade-off is opinionatedness: the output is always a string (hex by default), and only three algorithms are supported. If you need BLAKE3, HMAC, or raw `Buffer` output, read the file yourself — this library is not trying to be a general-purpose hashing toolkit.

## Awkward edges

- **Directories.** Passing a directory path rejects with either `EISDIR` or `ENOENT` depending on platform and Node version. The library does not paper over this; check your input.
- **Empty files.** Hash correctly to the well-known empty-input digest (`md5` → `d41d8cd98f00b204e9800998ecf8427e`). This is tested because the "zero chunks" path is the easiest place for an off-by-one to hide.
- **MD5 and SHA1 are not collision-resistant.** They are included because checksum tooling (e.g. legacy package registries) still uses them, not because they are safe for integrity verification against an adversary. Prefer `sha256` for anything security-relevant.
