const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const Io = std.Io;
const mem = std.mem;
const process = std.process;

const aead = crypto.aead.chacha_poly.XChaCha20Poly1305;
const argon2 = crypto.pwhash.argon2;

// ─── Constants ───────────────────────────────────────────────────────────────

const MAGIC = "SEAL01";
const VERSION: u8 = 1;
const SALT_LEN = 16;
const KEY_LEN = aead.key_length; // 32
const NONCE_LEN = aead.nonce_length; // 24
const TAG_LEN = aead.tag_length; // 16
const CHUNK_SIZE = 64 * 1024; // 64 KiB – good balance of throughput / memory
const HEADER_SIZE = MAGIC.len + 1 + SALT_LEN + 12; // magic + ver + salt + t/m/p

// Default Argon2id parameters (OWASP-ish, tuned for interactive use)
// ~64 MiB memory, 3 iterations, 4 lanes – adjustable via flags later if needed
const DEFAULT_T: u32 = 3;
const DEFAULT_M: u32 = 64 * 1024; // KiB
const DEFAULT_P: u32 = 4;

// ─── Errors ──────────────────────────────────────────────────────────────────

const SealError = error{
    InvalidMagic,
    UnsupportedVersion,
    AuthenticationFailed,
    TruncatedFile,
    PasswordMismatch,
    EmptyPassword,
    FileTooSmall,
    OutputExists,
};

// ─── Main ────────────────────────────────────────────────────────────────────

pub fn main(init: process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();

    var args = try init.minimal.args.toSlice(arena);
    // skip program name
    if (args.len > 0) args = args[1..];

    if (args.len == 0 or mem.eql(u8, args[0], "--help") or mem.eql(u8, args[0], "-h")) {
        try printUsage(io);
        return;
    }

    const cmd = args[0];
    args = args[1..];

    if (mem.eql(u8, cmd, "encrypt") or mem.eql(u8, cmd, "e") or mem.eql(u8, cmd, "-e")) {
        try cmdEncrypt(gpa, io, arena, args);
    } else if (mem.eql(u8, cmd, "decrypt") or mem.eql(u8, cmd, "d") or mem.eql(u8, cmd, "-d")) {
        try cmdDecrypt(gpa, io, arena, args);
    } else if (mem.eql(u8, cmd, "version") or mem.eql(u8, cmd, "-V")) {
        try printVersion(io);
    } else {
        try printUsage(io);
        std.process.exit(1);
    }
}

// ─── CLI helpers ─────────────────────────────────────────────────────────────

fn printUsage(io: Io) !void {
    const msg =
        \\seal – modern authenticated file encryption
        \\
        \\Usage:
        \\  seal encrypt  <input> [-o <output>] [--force] [--pass-file <path>]
        \\  seal decrypt  <input> [-o <output>] [--force] [--pass-file <path>]
        \\  seal version
        \\
        \\Options:
        \\  -o, --output <path>     Output file (default: input.seal / strip .seal)
        \\  -f, --force             Overwrite existing output
        \\      --pass-file <path>  Read password from file (trailing newline stripped)
        \\  -h, --help              Show this help
        \\
        \\Security:
        \\  • XChaCha20-Poly1305 AEAD (24-byte nonces)
        \\  • Argon2id key derivation (64 MiB, t=3, p=4)
        \\  • Streaming encryption – constant memory, any file size
        \\  • Authenticated header + per-chunk tags
        \\  • Sensitive memory is wiped
        \\
        \\Examples:
        \\  seal encrypt secret.pdf
        \\  seal decrypt secret.pdf.seal -o secret.pdf
        \\  echo -n 'hunter2' | seal encrypt data.bin --pass-file /dev/stdin
        \\
    ;
    try writeAll(io, .stderr(), msg);
}

fn printVersion(io: Io) !void {
    try writeAll(io, .stderr(), "seal 1.0.0 (Zig 0.16, XChaCha20-Poly1305 + Argon2id)\n");
}

fn writeAll(io: Io, file: Io.File, data: []const u8) !void {
    try file.writeStreamingAll(io, data);
}

// ─── Argument parsing ────────────────────────────────────────────────────────

const Options = struct {
    input: []const u8,
    output: ?[]const u8 = null,
    force: bool = false,
    pass_file: ?[]const u8 = null,
};

fn parseOptions(args: []const []const u8) !Options {
    var opts: Options = .{ .input = undefined };
    var i: usize = 0;
    var got_input = false;

    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (mem.eql(u8, a, "-o") or mem.eql(u8, a, "--output")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            opts.output = args[i];
        } else if (mem.eql(u8, a, "-f") or mem.eql(u8, a, "--force")) {
            opts.force = true;
        } else if (mem.eql(u8, a, "--pass-file")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            opts.pass_file = args[i];
        } else if (a.len > 0 and a[0] != '-') {
            if (got_input) return error.TooManyInputs;
            opts.input = a;
            got_input = true;
        } else {
            return error.UnknownOption;
        }
    }
    if (!got_input) return error.MissingInput;
    return opts;
}

// ─── Password handling ───────────────────────────────────────────────────────

fn readPassword(gpa: mem.Allocator, io: Io, prompt: []const u8, confirm: bool) ![]u8 {
    // Prefer --pass-file path handled by caller; this is interactive path.
    try writeAll(io, .stderr(), prompt);

    const pass = try readLineHidden(gpa, io);
    errdefer {
        crypto.secureZero(u8, pass);
        gpa.free(pass);
    }

    if (pass.len == 0) return SealError.EmptyPassword;

    if (confirm) {
        try writeAll(io, .stderr(), "Confirm password: ");
        const pass2 = try readLineHidden(gpa, io);
        defer {
            crypto.secureZero(u8, pass2);
            gpa.free(pass2);
        }
        if (!mem.eql(u8, pass, pass2)) return SealError.PasswordMismatch;
    }

    return pass;
}

fn readPasswordFromFile(gpa: mem.Allocator, io: Io, path: []const u8) ![]u8 {
    const cwd = Io.Dir.cwd();
    const file = try cwd.openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);

    var buf: [4096]u8 = undefined;
    const n = try file.read(io, &buf);
    var slice = buf[0..n];

    // strip trailing newlines / CR
    while (slice.len > 0 and (slice[slice.len - 1] == '\n' or slice[slice.len - 1] == '\r')) {
        slice = slice[0 .. slice.len - 1];
    }
    if (slice.len == 0) return SealError.EmptyPassword;

    const owned = try gpa.dupe(u8, slice);
    return owned;
}

fn readLineHidden(gpa: mem.Allocator, io: Io) ![]u8 {
    // Cross-platform no-echo input
    const stdin = Io.File.stdin();
    const is_tty = stdin.isTty();

    var original_termios: ?std.posix.termios = null;
    var original_console_mode: ?std.os.windows.DWORD = null;

    if (is_tty) {
        if (builtin.os.tag == .windows) {
            original_console_mode = try setEchoWindows(false);
        } else {
            original_termios = try setEchoPosix(false);
        }
    }
    defer {
        if (is_tty) {
            if (builtin.os.tag == .windows) {
                if (original_console_mode) |m| _ = setEchoWindowsRestore(m) catch {};
            } else {
                if (original_termios) |t| _ = setEchoPosixRestore(t) catch {};
            }
        }
    }

    var list = std.ArrayList(u8).empty;
    errdefer list.deinit(gpa);

    var buf: [256]u8 = undefined;
    while (true) {
        const n = try stdin.read(io, &buf);
        if (n == 0) break;
        for (buf[0..n]) |c| {
            if (c == '\n' or c == '\r') {
                try writeAll(io, .stderr(), "\n");
                return try list.toOwnedSlice(gpa);
            }
            try list.append(gpa, c);
        }
    }
    try writeAll(io, .stderr(), "\n");
    return try list.toOwnedSlice(gpa);
}

fn setEchoPosix(enable: bool) !std.posix.termios {
    const fd = Io.File.stdin().handle;
    const original = try std.posix.tcgetattr(fd);
    var raw = original;
    raw.lflag.ECHO = enable;
    raw.lflag.ECHONL = enable;
    try std.posix.tcsetattr(fd, .NOW, raw);
    return original;
}

fn setEchoPosixRestore(original: std.posix.termios) !void {
    const fd = Io.File.stdin().handle;
    try std.posix.tcsetattr(fd, .NOW, original);
}

fn setEchoWindows(enable: bool) !std.os.windows.DWORD {
    const windows = std.os.windows;
    const handle = windows.GetStdHandle(windows.STD_INPUT_HANDLE) catch return error.StdHandleFailed;
    var mode: windows.DWORD = undefined;
    if (windows.kernel32.GetConsoleMode(handle, &mode) == 0) return error.GetConsoleModeFailed;
    const ENABLE_ECHO_INPUT: windows.DWORD = 0x0004;
    const new_mode = if (enable) mode | ENABLE_ECHO_INPUT else mode & ~ENABLE_ECHO_INPUT;
    if (windows.kernel32.SetConsoleMode(handle, new_mode) == 0) return error.SetConsoleModeFailed;
    return mode;
}

fn setEchoWindowsRestore(mode: std.os.windows.DWORD) !void {
    const windows = std.os.windows;
    const handle = windows.GetStdHandle(windows.STD_INPUT_HANDLE) catch return error.StdHandleFailed;
    _ = windows.kernel32.SetConsoleMode(handle, mode);
}

// ─── Key derivation ──────────────────────────────────────────────────────────

fn deriveKey(
    gpa: mem.Allocator,
    io: Io,
    password: []const u8,
    salt: []const u8,
    t: u32,
    m: u32,
    p: u32,
) ![KEY_LEN]u8 {
    var key: [KEY_LEN]u8 = undefined;
    const params = argon2.Params{ .t = t, .m = m, .p = @intCast(p) };
    try argon2.kdf(gpa, &key, password, salt, params, .argon2id, io);
    return key;
}

// ─── Encrypt ─────────────────────────────────────────────────────────────────

fn cmdEncrypt(gpa: mem.Allocator, io: Io, arena: mem.Allocator, args: []const []const u8) !void {
    const opts = parseOptions(args) catch |err| {
        try writeAll(io, .stderr(), "error: invalid arguments\n");
        try printUsage(io);
        return err;
    };

    const out_path = opts.output orelse try std.fmt.allocPrint(arena, "{s}.seal", .{opts.input});

    // Refuse to overwrite unless --force
    if (!opts.force) {
        if (Io.Dir.cwd().access(io, out_path, .{})) |_| {
            try writeAll(io, .stderr(), "error: output already exists (use --force)\n");
            return SealError.OutputExists;
        } else |_| {}
    }

    // Password
    var password: []u8 = undefined;
    if (opts.pass_file) |pf| {
        password = try readPasswordFromFile(gpa, io, pf);
    } else {
        password = try readPassword(gpa, io, "Password: ", true);
    }
    defer {
        crypto.secureZero(u8, password);
        gpa.free(password);
    }

    // Open input
    const cwd = Io.Dir.cwd();
    const in_file = try cwd.openFile(io, opts.input, .{ .mode = .read_only });
    defer in_file.close(io);

    const in_size = try in_file.getEndPos(io);

    // Create output (atomic when possible)
    const out_file = try cwd.createFile(io, out_path, .{ .truncate = true });
    defer out_file.close(io);

    // Generate salt
    var salt: [SALT_LEN]u8 = undefined;
    try Io.randomSecure(io, &salt);

    // Derive key
    try writeAll(io, .stderr(), "Deriving key (Argon2id)…\n");
    var key = try deriveKey(gpa, io, password, &salt, DEFAULT_T, DEFAULT_M, DEFAULT_P);
    defer crypto.secureZero(u8, &key);

    // Write header
    // MAGIC (6) | VERSION (1) | SALT (16) | t (4 LE) | m (4 LE) | p (4 LE)
    var header: [HEADER_SIZE]u8 = undefined;
    @memcpy(header[0..MAGIC.len], MAGIC);
    header[MAGIC.len] = VERSION;
    @memcpy(header[MAGIC.len + 1 ..][0..SALT_LEN], &salt);
    mem.writeInt(u32, header[MAGIC.len + 1 + SALT_LEN ..][0..4], DEFAULT_T, .little);
    mem.writeInt(u32, header[MAGIC.len + 1 + SALT_LEN + 4 ..][0..4], DEFAULT_M, .little);
    mem.writeInt(u32, header[MAGIC.len + 1 + SALT_LEN + 8 ..][0..4], DEFAULT_P, .little);

    try out_file.writeStreamingAll(io, &header);

    // Generate base nonce (16 random bytes; remaining 8 bytes = chunk counter)
    var base_nonce: [16]u8 = undefined;
    try Io.randomSecure(io, &base_nonce);

    // Streaming encrypt
    var chunk_idx: u64 = 0;
    var processed: u64 = 0;
    var plain_buf: [CHUNK_SIZE]u8 = undefined;
    var cipher_buf: [CHUNK_SIZE]u8 = undefined;
    var tag: [TAG_LEN]u8 = undefined;

    // Progress
    const show_progress = in_size > 1024 * 1024; // only for >1 MiB
    var last_pct: u8 = 255;

    while (true) {
        const n = try in_file.read(io, &plain_buf);
        if (n == 0) break;

        // Build nonce: base[0..16] || counter (big-endian u64)
        var nonce: [NONCE_LEN]u8 = undefined;
        @memcpy(nonce[0..16], &base_nonce);
        mem.writeInt(u64, nonce[16..24], chunk_idx, .big);

        // AD = chunk index (prevents reordering / splicing)
        var ad: [8]u8 = undefined;
        mem.writeInt(u64, &ad, chunk_idx, .big);

        aead.encrypt(cipher_buf[0..n], &tag, plain_buf[0..n], &ad, nonce, key);

        // Write: nonce (24) + ciphertext + tag (16)
        // For the first chunk we already wrote the header; subsequent chunks
        // still carry a full nonce so the format is uniform and seekable.
        try out_file.writeStreamingAll(io, &nonce);
        try out_file.writeStreamingAll(io, cipher_buf[0..n]);
        try out_file.writeStreamingAll(io, &tag);

        // Wipe plaintext
        crypto.secureZero(u8, plain_buf[0..n]);

        processed += n;
        chunk_idx += 1;

        if (show_progress) {
            const pct: u8 = @intCast((processed * 100) / in_size);
            if (pct != last_pct) {
                last_pct = pct;
                var prog_buf: [32]u8 = undefined;
                const msg = try std.fmt.bufPrint(&prog_buf, "\rEncrypting… {d}%", .{pct});
                try writeAll(io, .stderr(), msg);
            }
        }
    }

    if (show_progress) try writeAll(io, .stderr(), "\rEncrypting… 100%\n");
    try writeAll(io, .stderr(), "Done.\n");
}

// ─── Decrypt ─────────────────────────────────────────────────────────────────

fn cmdDecrypt(gpa: mem.Allocator, io: Io, arena: mem.Allocator, args: []const []const u8) !void {
    const opts = parseOptions(args) catch |err| {
        try writeAll(io, .stderr(), "error: invalid arguments\n");
        try printUsage(io);
        return err;
    };

    // Default output: strip .seal if present
    const out_path = opts.output orelse blk: {
        if (mem.endsWith(u8, opts.input, ".seal")) {
            break :blk opts.input[0 .. opts.input.len - 5];
        }
        break :blk try std.fmt.allocPrint(arena, "{s}.dec", .{opts.input});
    };

    if (!opts.force) {
        if (Io.Dir.cwd().access(io, out_path, .{})) |_| {
            try writeAll(io, .stderr(), "error: output already exists (use --force)\n");
            return SealError.OutputExists;
        } else |_| {}
    }

    // Password
    var password: []u8 = undefined;
    if (opts.pass_file) |pf| {
        password = try readPasswordFromFile(gpa, io, pf);
    } else {
        password = try readPassword(gpa, io, "Password: ", false);
    }
    defer {
        crypto.secureZero(u8, password);
        gpa.free(password);
    }

    const cwd = Io.Dir.cwd();
    const in_file = try cwd.openFile(io, opts.input, .{ .mode = .read_only });
    defer in_file.close(io);

    const in_size = try in_file.getEndPos(io);
    if (in_size < HEADER_SIZE + NONCE_LEN + TAG_LEN) return SealError.FileTooSmall;

    // Read & validate header
    var header: [HEADER_SIZE]u8 = undefined;
    const hn = try in_file.read(io, &header);
    if (hn != HEADER_SIZE) return SealError.TruncatedFile;

    if (!mem.eql(u8, header[0..MAGIC.len], MAGIC)) return SealError.InvalidMagic;
    if (header[MAGIC.len] != VERSION) return SealError.UnsupportedVersion;

    const salt = header[MAGIC.len + 1 ..][0..SALT_LEN];
    const t = mem.readInt(u32, header[MAGIC.len + 1 + SALT_LEN ..][0..4], .little);
    const m = mem.readInt(u32, header[MAGIC.len + 1 + SALT_LEN + 4 ..][0..4], .little);
    const p = mem.readInt(u32, header[MAGIC.len + 1 + SALT_LEN + 8 ..][0..4], .little);

    // Derive key
    try writeAll(io, .stderr(), "Deriving key (Argon2id)…\n");
    var key = try deriveKey(gpa, io, password, salt, t, m, p);
    defer crypto.secureZero(u8, &key);

    // Create output
    const out_file = try cwd.createFile(io, out_path, .{ .truncate = true });
    defer out_file.close(io);

    // Streaming decrypt
    var chunk_idx: u64 = 0;
    var processed: u64 = HEADER_SIZE;
    var nonce: [NONCE_LEN]u8 = undefined;
    var cipher_buf: [CHUNK_SIZE]u8 = undefined;
    var plain_buf: [CHUNK_SIZE]u8 = undefined;
    var tag: [TAG_LEN]u8 = undefined;

    const show_progress = in_size > 1024 * 1024;
    var last_pct: u8 = 255;
    const data_size = in_size - HEADER_SIZE;

    while (processed < in_size) {
        // Read nonce
        const nn = try in_file.read(io, &nonce);
        if (nn != NONCE_LEN) return SealError.TruncatedFile;
        processed += NONCE_LEN;

        // How many ciphertext bytes remain before the tag?
        // We don't know exact chunk size a priori for the last chunk,
        // so we read up to CHUNK_SIZE + TAG, then split.
        const remaining = in_size - processed;
        if (remaining < TAG_LEN) return SealError.TruncatedFile;

        const max_ct = @min(CHUNK_SIZE, remaining - TAG_LEN);
        const ct_n = try in_file.read(io, cipher_buf[0..max_ct]);
        if (ct_n == 0) return SealError.TruncatedFile;
        processed += ct_n;

        // Read tag
        const tn = try in_file.read(io, &tag);
        if (tn != TAG_LEN) return SealError.TruncatedFile;
        processed += TAG_LEN;

        // AD
        var ad: [8]u8 = undefined;
        mem.writeInt(u64, &ad, chunk_idx, .big);

        aead.decrypt(plain_buf[0..ct_n], cipher_buf[0..ct_n], tag, &ad, nonce, key) catch {
            // Wipe everything on failure
            crypto.secureZero(u8, &key);
            crypto.secureZero(u8, &plain_buf);
            try writeAll(io, .stderr(), "error: authentication failed (wrong password or corrupted file)\n");
            // Best-effort delete the partial output
            cwd.deleteFile(io, out_path) catch {};
            return SealError.AuthenticationFailed;
        };

        try out_file.writeStreamingAll(io, plain_buf[0..ct_n]);
        crypto.secureZero(u8, plain_buf[0..ct_n]);

        chunk_idx += 1;

        if (show_progress) {
            const pct: u8 = @intCast(((processed - HEADER_SIZE) * 100) / data_size);
            if (pct != last_pct) {
                last_pct = pct;
                var prog_buf: [32]u8 = undefined;
                const msg = try std.fmt.bufPrint(&prog_buf, "\rDecrypting… {d}%", .{pct});
                try writeAll(io, .stderr(), msg);
            }
        }
    }

    if (show_progress) try writeAll(io, .stderr(), "\rDecrypting… 100%\n");
    try writeAll(io, .stderr(), "Done.\n");
}
