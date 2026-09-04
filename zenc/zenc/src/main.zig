const std = @import("std");
const c = @import("c");
const fmt = @import("format.zig");

const Io = std.Io;
const Aead = fmt.Aead;
const Argon2 = fmt.Argon2;

const program_version = "0.1.0";
const max_password_len = 1024;

const Command = enum { encrypt, decrypt, verify, info, help, version };

const Options = struct {
    command: Command,
    input: ?[]const u8 = null,
    output: ?[]const u8 = null,
    force: bool = false,
    password_file: ?[]const u8 = null,
    kdf: fmt.KdfParams = .{},
};

const Secret = struct {
    buf: [max_password_len]u8 = [_]u8{0} ** max_password_len,
    len: usize = 0,

    fn slice(self: *const Secret) []const u8 {
        return self.buf[0..self.len];
    }

    fn wipe(self: *Secret) void {
        std.crypto.secureZero(u8, &self.buf);
        self.len = 0;
    }
};

pub fn main(init: std.process.Init) !void {
    run(init) catch |err| {
        printError(init.io, err);
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const opts = try parseArgs(args);

    switch (opts.command) {
        .help => return printUsage(io),
        .version => return std.Io.File.stdout().writeStreamingAll(io, "zenc " ++ program_version ++ "\n"),
        .info => try infoFile(io, opts.input.?),
        .encrypt => try encryptFile(io, gpa, opts),
        .decrypt => try decryptFile(io, gpa, opts, false),
        .verify => try decryptFile(io, gpa, opts, true),
    }
}

fn parseArgs(args: []const []const u8) !Options {
    if (args.len < 2) return .{ .command = .help };

    const cmd: Command = if (std.mem.eql(u8, args[1], "encrypt") or std.mem.eql(u8, args[1], "enc"))
        .encrypt
    else if (std.mem.eql(u8, args[1], "decrypt") or std.mem.eql(u8, args[1], "dec"))
        .decrypt
    else if (std.mem.eql(u8, args[1], "verify"))
        .verify
    else if (std.mem.eql(u8, args[1], "info"))
        .info
    else if (std.mem.eql(u8, args[1], "help") or std.mem.eql(u8, args[1], "-h") or std.mem.eql(u8, args[1], "--help"))
        .help
    else if (std.mem.eql(u8, args[1], "version") or std.mem.eql(u8, args[1], "--version"))
        .version
    else
        return error.UnknownCommand;

    var opts: Options = .{ .command = cmd };
    if (cmd == .help or cmd == .version) return opts;

    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= args.len or opts.output != null) return error.InvalidArguments;
            opts.output = args[i];
        } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--force")) {
            opts.force = true;
        } else if (std.mem.eql(u8, arg, "--password-file")) {
            i += 1;
            if (i >= args.len or opts.password_file != null) return error.InvalidArguments;
            opts.password_file = args[i];
        } else if (std.mem.eql(u8, arg, "--kdf-memory-mib")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            const mib = std.fmt.parseInt(u32, args[i], 10) catch return error.InvalidArguments;
            opts.kdf.memory_kib = std.math.mul(u32, mib, 1024) catch return error.InvalidKdfParameters;
        } else if (std.mem.eql(u8, arg, "--kdf-iterations")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            opts.kdf.iterations = std.fmt.parseInt(u32, args[i], 10) catch return error.InvalidArguments;
        } else if (std.mem.eql(u8, arg, "--kdf-parallelism")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            opts.kdf.parallelism = std.fmt.parseInt(u32, args[i], 10) catch return error.InvalidArguments;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return error.UnknownOption;
        } else {
            if (opts.input != null) return error.InvalidArguments;
            opts.input = arg;
        }
    }

    if (opts.input == null) return error.MissingInput;
    if (cmd == .info and (opts.output != null or opts.force or opts.password_file != null)) return error.InvalidArguments;
    if (cmd == .verify and (opts.output != null or opts.force)) return error.InvalidArguments;
    if (cmd != .encrypt and (opts.kdf.memory_kib != fmt.KdfParams{}.memory_kib or
        opts.kdf.iterations != fmt.KdfParams{}.iterations or
        opts.kdf.parallelism != fmt.KdfParams{}.parallelism)) return error.InvalidArguments;
    if (cmd == .encrypt) try opts.kdf.validate();
    return opts;
}

fn encryptFile(io: Io, gpa: std.mem.Allocator, opts: Options) !void {
    const input_path = opts.input.?;
    var owned_output: ?[]u8 = null;
    defer if (owned_output) |p| gpa.free(p);
    const output_path = opts.output orelse blk: {
        owned_output = try std.fmt.allocPrint(gpa, "{s}.zenc", .{input_path});
        break :blk owned_output.?;
    };
    if (std.mem.eql(u8, input_path, output_path)) return error.InputEqualsOutput;

    var password: Secret = .{};
    defer password.wipe();
    if (opts.password_file) |path| {
        try readPasswordFile(io, path, &password);
    } else {
        try promptPassword("Password: ", &password);
        var confirm: Secret = .{};
        defer confirm.wipe();
        try promptPassword("Confirm password: ", &confirm);
        if (!std.mem.eql(u8, password.slice(), confirm.slice())) return error.PasswordMismatch;
    }
    if (password.len == 0) return error.EmptyPassword;

    var input = try std.Io.Dir.cwd().openFile(io, input_path, .{});
    defer input.close(io);
    const stat = try input.stat(io);
    const plain_size = stat.size;
    const chunks = fmt.chunkCount(plain_size, fmt.default_chunk_size);
    if (chunks >= fmt.metadata_nonce_counter) return error.FileTooLarge;

    var salt: [32]u8 = undefined;
    var nonce_prefix: [16]u8 = undefined;
    try io.randomSecure(&salt);
    try io.randomSecure(&nonce_prefix);

    var key: [Aead.key_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    try deriveKey(io, gpa, &key, password.slice(), &salt, opts.kdf);

    var header: fmt.Header = .{
        .chunk_size = fmt.default_chunk_size,
        .kdf = opts.kdf,
        .salt = salt,
        .nonce_prefix = nonce_prefix,
        .metadata_ciphertext = [_]u8{0} ** fmt.metadata_len,
        .metadata_tag = [_]u8{0} ** Aead.tag_length,
    };
    header = fmt.sealMetadata(header, key, .{
        .plaintext_size = plain_size,
        .chunk_count = chunks,
    });
    const header_bytes = header.encode();

    var atomic = try std.Io.Dir.cwd().createFileAtomic(io, output_path, .{
        .permissions = .fromMode(0o600),
        .replace = opts.force,
    });
    defer atomic.deinit(io);

    try atomic.file.writeStreamingAll(io, &header_bytes);

    const chunk_size: usize = @intCast(header.chunk_size);
    const plain = try gpa.alloc(u8, chunk_size);
    defer {
        std.crypto.secureZero(u8, plain);
        gpa.free(plain);
    }
    const cipher = try gpa.alloc(u8, chunk_size);
    defer gpa.free(cipher);

    var remaining = plain_size;
    var chunk_index: u64 = 0;
    while (chunk_index < chunks) : (chunk_index += 1) {
        const take_u64 = @min(remaining, @as(u64, header.chunk_size));
        const take: usize = @intCast(take_u64);
        if (take != 0) try readExactly(io, input, plain[0..take]);
        if (take < chunk_size) try io.randomSecure(plain[take..chunk_size]);

        const ad = fmt.dataAd(&header_bytes, chunk_index);
        var tag: [Aead.tag_length]u8 = undefined;
        Aead.encrypt(cipher, &tag, plain, &ad, fmt.nonce(header.nonce_prefix, chunk_index), key);
        try atomic.file.writeStreamingAll(io, cipher);
        try atomic.file.writeStreamingAll(io, &tag);
        remaining -= take_u64;
    }

    var extra: [1]u8 = undefined;
    if (try input.readStreaming(io, &extra) != 0) return error.InputChangedDuringEncryption;

    if (opts.force)
        try atomic.replace(io)
    else
        try atomic.link(io);

    try printSuccess(io, "encrypted", input_path, output_path);
}

fn decryptFile(io: Io, gpa: std.mem.Allocator, opts: Options, verify_only: bool) !void {
    const input_path = opts.input.?;
    var input = try std.Io.Dir.cwd().openFile(io, input_path, .{});
    defer input.close(io);
    const input_stat = try input.stat(io);

    var header_bytes: [fmt.header_len]u8 = undefined;
    try readExactly(io, input, &header_bytes);
    const header = try fmt.Header.decode(&header_bytes);

    var password: Secret = .{};
    defer password.wipe();
    if (opts.password_file) |path|
        try readPasswordFile(io, path, &password)
    else
        try promptPassword("Password: ", &password);
    if (password.len == 0) return error.EmptyPassword;

    var key: [Aead.key_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    try deriveKey(io, gpa, &key, password.slice(), &header.salt, header.kdf);

    const meta = fmt.openMetadata(header, &header_bytes, key) catch |err| switch (err) {
        error.AuthenticationFailed => return error.WrongPasswordOrCorruptFile,
        else => return err,
    };
    try fmt.validateMetadata(meta, header.chunk_size);
    const expected_size = try fmt.expectedEncryptedSize(meta.chunk_count, header.chunk_size);
    if (input_stat.size != expected_size) return error.TruncatedOrExtendedFile;

    var owned_output: ?[]u8 = null;
    defer if (owned_output) |p| gpa.free(p);
    var atomic_opt: ?std.Io.File.Atomic = null;
    if (!verify_only) {
        const output_path = opts.output orelse blk: {
            if (std.mem.endsWith(u8, input_path, ".zenc") and input_path.len > 5) {
                owned_output = try gpa.dupe(u8, input_path[0 .. input_path.len - 5]);
            } else {
                owned_output = try std.fmt.allocPrint(gpa, "{s}.dec", .{input_path});
            }
            break :blk owned_output.?;
        };
        if (std.mem.eql(u8, input_path, output_path)) return error.InputEqualsOutput;
        atomic_opt = try std.Io.Dir.cwd().createFileAtomic(io, output_path, .{
            .permissions = .fromMode(0o600),
            .replace = opts.force,
        });
    }
    defer if (atomic_opt) |*a| a.deinit(io);

    const chunk_size: usize = @intCast(header.chunk_size);
    const cipher = try gpa.alloc(u8, chunk_size);
    defer gpa.free(cipher);
    const plain = try gpa.alloc(u8, chunk_size);
    defer {
        std.crypto.secureZero(u8, plain);
        gpa.free(plain);
    }

    var remaining = meta.plaintext_size;
    var chunk_index: u64 = 0;
    while (chunk_index < meta.chunk_count) : (chunk_index += 1) {
        try readExactly(io, input, cipher);
        var tag: [Aead.tag_length]u8 = undefined;
        try readExactly(io, input, &tag);
        const ad = fmt.dataAd(&header_bytes, chunk_index);
        Aead.decrypt(plain, cipher, tag, &ad, fmt.nonce(header.nonce_prefix, chunk_index), key) catch |err| switch (err) {
            error.AuthenticationFailed => return error.WrongPasswordOrCorruptFile,
        };

        const take_u64 = @min(remaining, @as(u64, header.chunk_size));
        const take: usize = @intCast(take_u64);
        if (!verify_only and take != 0) {
            if (atomic_opt) |*a| {
                try a.file.writeStreamingAll(io, plain[0..take]);
            } else unreachable;
        }
        remaining -= take_u64;
    }
    if (remaining != 0) return error.InvalidFormat;

    if (verify_only) {
        try std.Io.File.stdout().writeStreamingAll(io, "OK: password and every encrypted chunk authenticated successfully.\n");
        return;
    }

    const output_path = opts.output orelse owned_output.?;
    if (atomic_opt) |*a| {
        if (opts.force)
            try a.replace(io)
        else
            try a.link(io);
    } else unreachable;
    try printSuccess(io, "decrypted", input_path, output_path);
}

fn infoFile(io: Io, path: []const u8) !void {
    var input = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer input.close(io);
    var bytes: [fmt.header_len]u8 = undefined;
    try readExactly(io, input, &bytes);
    const h = try fmt.Header.decode(&bytes);

    var out_buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out_buf);
    try writer.print(
        \\format: ZENC v{d}
        \\AEAD: XChaCha20-Poly1305
        \\KDF: Argon2id
        \\KDF memory: {d} MiB
        \\KDF iterations: {d}
        \\KDF parallelism: {d}
        \\chunk size: {d} KiB
        \\exact plaintext size: encrypted
        \\
    , .{
        fmt.version,
        h.kdf.memory_kib / 1024,
        h.kdf.iterations,
        h.kdf.parallelism,
        h.chunk_size / 1024,
    });
    try std.Io.File.stdout().writeStreamingAll(io, writer.buffered());
}

fn deriveKey(
    io: Io,
    allocator: std.mem.Allocator,
    out: *[Aead.key_length]u8,
    password: []const u8,
    salt: *const [32]u8,
    params: fmt.KdfParams,
) !void {
    try params.validate();
    try Argon2.kdf(
        allocator,
        out,
        password,
        salt,
        params.toArgon2(),
        .argon2id,
        io,
    );
}

fn readExactly(io: Io, file: std.Io.File, dest: []u8) !void {
    var done: usize = 0;
    while (done < dest.len) {
        const n = try file.readStreaming(io, dest[done..]);
        if (n == 0) return error.UnexpectedEndOfFile;
        done += n;
    }
}

fn readPasswordFile(io: Io, path: []const u8, secret: *Secret) !void {
    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var used: usize = 0;
    while (used < secret.buf.len) {
        const n = try file.readStreaming(io, secret.buf[used..]);
        if (n == 0) break;
        used += n;
    }
    if (used == secret.buf.len) {
        var extra: [1]u8 = undefined;
        if (try file.readStreaming(io, &extra) != 0) return error.PasswordTooLong;
    }
    while (used > 0 and (secret.buf[used - 1] == '\n' or secret.buf[used - 1] == '\r')) used -= 1;
    secret.len = used;
}

fn promptPassword(prompt: []const u8, secret: *Secret) !void {
    const fd = c.open("/dev/tty", c.O_RDWR | c.O_CLOEXEC);
    if (fd < 0) return error.NoControllingTerminal;
    defer _ = c.close(fd);

    try cWriteAll(fd, prompt);

    var old_term: c.struct_termios = undefined;
    if (c.tcgetattr(fd, &old_term) != 0) return error.TerminalError;
    var new_term = old_term;
    new_term.c_lflag &= ~@as(@TypeOf(new_term.c_lflag), @intCast(c.ECHO | c.ECHONL));

    var block_set: c.sigset_t = undefined;
    var old_set: c.sigset_t = undefined;
    if (c.sigemptyset(&block_set) != 0) return error.TerminalError;
    _ = c.sigaddset(&block_set, c.SIGINT);
    _ = c.sigaddset(&block_set, c.SIGTERM);
    _ = c.sigaddset(&block_set, c.SIGHUP);
    _ = c.sigaddset(&block_set, c.SIGQUIT);
    if (c.sigprocmask(c.SIG_BLOCK, &block_set, &old_set) != 0) return error.TerminalError;
    var signals_blocked = true;
    defer if (signals_blocked) _ = c.sigprocmask(c.SIG_SETMASK, &old_set, null);

    if (c.tcsetattr(fd, c.TCSAFLUSH, &new_term) != 0) return error.TerminalError;
    var term_changed = true;
    defer if (term_changed) _ = c.tcsetattr(fd, c.TCSAFLUSH, &old_term);

    var len: usize = 0;
    while (true) {
        var byte: [1]u8 = undefined;
        const n = c.read(fd, &byte, 1);
        if (n < 0) return error.TerminalError;
        if (n == 0) return error.TerminalError;
        if (byte[0] == '\n' or byte[0] == '\r') break;
        if (len == secret.buf.len) return error.PasswordTooLong;
        secret.buf[len] = byte[0];
        len += 1;
    }
    secret.len = len;

    if (c.tcsetattr(fd, c.TCSAFLUSH, &old_term) != 0) return error.TerminalError;
    term_changed = false;
    try cWriteAll(fd, "\n");

    if (c.sigprocmask(c.SIG_SETMASK, &old_set, null) != 0) return error.TerminalError;
    signals_blocked = false;
}

fn cWriteAll(fd: c_int, bytes: []const u8) !void {
    var done: usize = 0;
    while (done < bytes.len) {
        const n = c.write(fd, bytes.ptr + done, bytes.len - done);
        if (n < 0) return error.TerminalError;
        if (n == 0) return error.TerminalError;
        done += @intCast(n);
    }
}

fn printSuccess(io: Io, verb: []const u8, input: []const u8, output: []const u8) !void {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("{s}: {s} -> {s}\n", .{ verb, input, output });
    try std.Io.File.stdout().writeStreamingAll(io, w.buffered());
}

fn printError(io: Io, err: anyerror) void {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    w.print("zenc: {s}\n", .{@errorName(err)}) catch return;
    std.Io.File.stderr().writeStreamingAll(io, w.buffered()) catch {};
}

fn printUsage(io: Io) !void {
    try std.Io.File.stdout().writeStreamingAll(io,
        \\zenc - authenticated, password-based file encryption
        \\
        \\Usage:
        \\  zenc encrypt [options] FILE
        \\  zenc decrypt [options] FILE.zenc
        \\  zenc verify  [options] FILE.zenc
        \\  zenc info FILE.zenc
        \\  zenc version
        \\
        \\Options:
        \\  -o, --output PATH           Output path
        \\  -f, --force                 Atomically replace an existing output
        \\      --password-file PATH    Read password from file (never argv)
        \\
        \\Encryption KDF tuning:
        \\      --kdf-memory-mib N      Argon2id memory, 64..1024 MiB (default 256)
        \\      --kdf-iterations N      Argon2id passes, 1..10 (default 3)
        \\      --kdf-parallelism N     Argon2id lanes, 1..16 (default 4)
        \\
        \\Security properties:
        \\  * Argon2id password KDF with a fresh 256-bit salt per file
        \\  * XChaCha20-Poly1305 authenticated encryption
        \\  * 1 MiB independently authenticated chunks for bounded memory use
        \\  * Random padding hides exact plaintext size to 1 MiB granularity
        \\  * Header, chunk order, truncation, and corruption are authenticated
        \\  * Atomic output: failed decrypts never leave a plaintext destination
        \\  * Passwords are never accepted as command-line arguments
        \\
    );
}
