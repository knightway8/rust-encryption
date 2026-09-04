# Security design

## Cryptographic construction

For a plaintext of exactly N bytes, pad generation obtains these independent
values from the operating system:

- a 32-byte public random pad identifier;
- a 32-byte secret authentication key;
- N secret one-time-pad bytes.

Encryption computes:

~~~text
ciphertext = plaintext XOR pad
tag = HMAC-SHA-256(authentication_key,
    "otp/envelope-auth/v1\0" || envelope_header || ciphertext)
~~~

The ciphertext is uniform for every same-length plaintext when the pad is
uniform and used once. The tag is a function of that uniform ciphertext and an
independent secret, so it does not change the perfect-confidentiality argument.
HMAC authenticity itself is computational.

The checksum stored at the end of a pad file is secret key-package material. It
must be protected and transferred exactly like the rest of that pad; it is never
copied into an encrypted file or log.

## Pad file v1

Integers are unsigned and big-endian.

~~~text
offset  bytes  field
0       8      "OTPPAD01"
8       2      version = 1
10      2      header length = 80
12      2      suite = 1 (XOR + HMAC-SHA-256)
14      2      flags = 0
16      1      role: 1 sender, 2 receiver
17      1      state: 0 fresh, 1 consumed
18      6      reserved = 0
24      32     random pad identifier
56      8      message capacity N
64      16     reserved = 0
80      32     authentication key
112     N      XOR pad bytes
112+N   32     SHA-256 private pad checksum
~~~

The checksum covers a domain separator, the header with state normalized to
fresh, the authentication key, and all pad bytes. Normalizing the state permits
validation after the durable consumed marker is written. The exact file size is
144 + N; truncation and trailing bytes are rejected.

Sender and receiver files have the same identifier and secret material but
different roles and therefore different checksums.

## Encrypted file v1

~~~text
offset  bytes  field
0       8      "OTPENC01"
8       2      version = 1
10      2      header length = 64
12      2      suite = 1 (XOR + HMAC-SHA-256)
14      2      flags = 0
16      32     random pad identifier
48      8      plaintext length N
56      8      reserved = 0
64      N      ciphertext
64+N   32      HMAC-SHA-256 tag
~~~

The exact file size is 96 + N. Unknown versions, suites, flags, reserved values,
malformed lengths, truncation, and trailing data are rejected.

## Lifecycle and crash behavior

Pad operations take an exclusive advisory file lock.

Encryption:

1. validates the input, complete pad checksum, role, state, exact capacity, and
   output destination;
2. creates and synchronizes a create-once sender-ledger record;
3. writes and synchronizes the consumed marker in the sender pad;
4. writes the encrypted file to a sibling temporary file;
5. synchronizes and atomically persists it without overwriting any path.

A crash after step 2 permanently reserves the pad. This may sacrifice
availability, but prevents an interrupted operation from presenting a pad as
safe to reuse.

Decryption:

1. validates the envelope framing and complete receiver pad;
2. authenticates the whole header and ciphertext;
3. creates a sibling temporary output and synchronizes a create-once
   receiver-ledger record;
4. writes and synchronizes the consumed marker;
5. decrypts while re-authenticating the exact ciphertext bytes and hashing the
   exact pad bytes used against the checksum captured in step 1;
6. synchronizes and atomically persists plaintext without overwriting any path.

Malformed or unauthenticated input does not reserve the receiver pad and creates
no plaintext output. A failure after the receiver reservation burns the pad.
The second authentication pass closes a modification race between validation and
decryption; if the file changes, the private temporary output is discarded.

Usage records contain no secret material. They are named by the public random
identifier and role. Existing records are treated as used even if truncated or
corrupt; the application never automatically rolls them back.

## Scope and limitations

- The application is designed for regular, seekable files, not pipes or terminal
  binary I/O.
- File locks are advisory on some platforms. The ledger and in-file state are
  additional barriers, but malicious software running as the user can bypass
  them.
- A copied sender pad used with another ledger or another implementation
  destroys confidentiality. No local application can solve this distributed
  state problem.
- Temporary and final files are created with restrictive permissions where the
  platform supports it. Existing directory ACLs and administrators can still
  grant access.
- Zeroization cannot erase compiler copies, kernel buffers, swap, filesystem
  caches, crash dumps, snapshots, or storage-controller remapping.
- Best-effort overwrite and truncation is not reliable secure erasure on SSDs, copy-on-write
  storage, snapshots, backups, or journaled filesystems.
- File length is public. Traffic analysis and endpoint compromise are out of
  scope.

If a pad may have been copied, exposed, restored, reused, or generated on a
compromised system, destroy it and create a new pair. Never use it to protect
another message.

## Reporting a vulnerability

Do not include pad material, plaintext, or live encrypted files in a report.
Provide a minimal synthetic reproducer and the affected version.
