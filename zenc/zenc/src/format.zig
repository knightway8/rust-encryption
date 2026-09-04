const std = @import("std");

pub const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
pub const Argon2 = std.crypto.pwhash.argon2;

pub const header_len: usize = 128;
pub const metadata_len: usize = 16;
pub const meta_ad_len: usize = 96;
pub const data_ad_len: usize = header_len + 8;
pub const default_chunk_size: u32 = 1024 * 1024;
pub const min_chunk_size: u32 = 64 * 1024;
pub const max_chunk_size: u32 = 16 * 1024 * 1024;
pub const min_kdf_memory_kib: u32 = 64 * 1024;
pub const max_kdf_memory_kib: u32 = 1024 * 1024;
pub const max_kdf_iterations: u32 = 10;
pub const max_kdf_parallelism: u32 = 16;

pub const magic = [_]u8{ 'Z', 'E', 'N', 'C', 0x0d, 0x0a, 0x1a, 0x0a };
pub const version: u16 = 1;
pub const aead_id: u8 = 1;
pub const kdf_id: u8 = 1;
pub const metadata_nonce_counter: u64 = std.math.maxInt(u64);

pub const KdfParams = struct {
    memory_kib: u32 = 256 * 1024,
    iterations: u32 = 3,
    parallelism: u32 = 4,

    pub fn validate(self: KdfParams) !void {
        if (self.memory_kib < min_kdf_memory_kib or self.memory_kib > max_kdf_memory_kib)
            return error.InvalidKdfParameters;
        if (self.iterations < 1 or self.iterations > max_kdf_iterations)
            return error.InvalidKdfParameters;
        if (self.parallelism < 1 or self.parallelism > max_kdf_parallelism)
            return error.InvalidKdfParameters;
    }

    pub fn toArgon2(self: KdfParams) Argon2.Params {
        return .{
            .t = self.iterations,
            .m = self.memory_kib,
            .p = @intCast(self.parallelism),
        };
    }
};

pub const Header = struct {
    chunk_size: u32,
    kdf: KdfParams,
    salt: [32]u8,
    nonce_prefix: [16]u8,
    metadata_ciphertext: [metadata_len]u8,
    metadata_tag: [Aead.tag_length]u8,

    pub fn encode(self: Header) [header_len]u8 {
        var out = [_]u8{0} ** header_len;
        @memcpy(out[0..8], &magic);
        std.mem.writeInt(u16, out[8..10], version, .little);
        out[10] = aead_id;
        out[11] = kdf_id;
        std.mem.writeInt(u32, out[12..16], 0, .little); // flags, reserved
        std.mem.writeInt(u32, out[16..20], self.chunk_size, .little);
        std.mem.writeInt(u32, out[20..24], self.kdf.memory_kib, .little);
        std.mem.writeInt(u32, out[24..28], self.kdf.iterations, .little);
        std.mem.writeInt(u32, out[28..32], self.kdf.parallelism, .little);
        @memcpy(out[32..64], &self.salt);
        @memcpy(out[64..80], &self.nonce_prefix);
        @memcpy(out[80..96], &self.metadata_ciphertext);
        @memcpy(out[96..112], &self.metadata_tag);
        // 112..128 intentionally zero/reserved and authenticated.
        return out;
    }

    pub fn decode(bytes: *const [header_len]u8) !Header {
        if (!std.mem.eql(u8, bytes[0..8], &magic)) return error.NotZencFile;
        if (std.mem.readInt(u16, bytes[8..10], .little) != version) return error.UnsupportedVersion;
        if (bytes[10] != aead_id or bytes[11] != kdf_id) return error.UnsupportedAlgorithm;
        if (std.mem.readInt(u32, bytes[12..16], .little) != 0) return error.UnsupportedFlags;
        for (bytes[112..128]) |b| if (b != 0) return error.UnsupportedFlags;

        const chunk_size = std.mem.readInt(u32, bytes[16..20], .little);
        if (chunk_size < min_chunk_size or chunk_size > max_chunk_size) return error.InvalidFormat;
        if (!std.math.isPowerOfTwo(chunk_size)) return error.InvalidFormat;

        const params: KdfParams = .{
            .memory_kib = std.mem.readInt(u32, bytes[20..24], .little),
            .iterations = std.mem.readInt(u32, bytes[24..28], .little),
            .parallelism = std.mem.readInt(u32, bytes[28..32], .little),
        };
        try params.validate();

        return .{
            .chunk_size = chunk_size,
            .kdf = params,
            .salt = bytes[32..64].*,
            .nonce_prefix = bytes[64..80].*,
            .metadata_ciphertext = bytes[80..96].*,
            .metadata_tag = bytes[96..112].*,
        };
    }
};

pub const Metadata = struct {
    plaintext_size: u64,
    chunk_count: u64,

    pub fn encode(self: Metadata) [metadata_len]u8 {
        var out: [metadata_len]u8 = undefined;
        std.mem.writeInt(u64, out[0..8], self.plaintext_size, .little);
        std.mem.writeInt(u64, out[8..16], self.chunk_count, .little);
        return out;
    }

    pub fn decode(bytes: *const [metadata_len]u8) Metadata {
        return .{
            .plaintext_size = std.mem.readInt(u64, bytes[0..8], .little),
            .chunk_count = std.mem.readInt(u64, bytes[8..16], .little),
        };
    }
};

pub fn chunkCount(plaintext_size: u64, chunk_size: u32) u64 {
    if (plaintext_size == 0) return 1;
    return 1 + (plaintext_size - 1) / @as(u64, chunk_size);
}

pub fn expectedEncryptedSize(chunk_count: u64, chunk_size: u32) !u64 {
    const record_size = try std.math.add(u64, @as(u64, chunk_size), Aead.tag_length);
    const records = try std.math.mul(u64, chunk_count, record_size);
    return std.math.add(u64, header_len, records);
}

pub fn nonce(prefix: [16]u8, counter: u64) [Aead.nonce_length]u8 {
    var out: [Aead.nonce_length]u8 = undefined;
    @memcpy(out[0..16], &prefix);
    std.mem.writeInt(u64, out[16..24], counter, .little);
    return out;
}

pub fn metadataAd(header_bytes: *const [header_len]u8) [meta_ad_len]u8 {
    var ad: [meta_ad_len]u8 = undefined;
    @memcpy(ad[0..80], header_bytes[0..80]);
    @memcpy(ad[80..96], header_bytes[112..128]);
    return ad;
}

pub fn dataAd(header_bytes: *const [header_len]u8, chunk_index: u64) [data_ad_len]u8 {
    var ad: [data_ad_len]u8 = undefined;
    @memcpy(ad[0..header_len], header_bytes);
    std.mem.writeInt(u64, ad[header_len .. header_len + 8], chunk_index, .little);
    return ad;
}

pub fn sealMetadata(
    header_without_meta: Header,
    key: [Aead.key_length]u8,
    metadata: Metadata,
) Header {
    var h = header_without_meta;
    h.metadata_ciphertext = [_]u8{0} ** metadata_len;
    h.metadata_tag = [_]u8{0} ** Aead.tag_length;
    const provisional = h.encode();
    const ad = metadataAd(&provisional);
    const plain = metadata.encode();
    Aead.encrypt(
        &h.metadata_ciphertext,
        &h.metadata_tag,
        &plain,
        &ad,
        nonce(h.nonce_prefix, metadata_nonce_counter),
        key,
    );
    return h;
}

pub fn openMetadata(header: Header, header_bytes: *const [header_len]u8, key: [Aead.key_length]u8) !Metadata {
    const ad = metadataAd(header_bytes);
    var plain: [metadata_len]u8 = undefined;
    errdefer std.crypto.secureZero(u8, &plain);
    try Aead.decrypt(
        &plain,
        &header.metadata_ciphertext,
        header.metadata_tag,
        &ad,
        nonce(header.nonce_prefix, metadata_nonce_counter),
        key,
    );
    defer std.crypto.secureZero(u8, &plain);
    return Metadata.decode(&plain);
}

pub fn validateMetadata(meta: Metadata, chunk_size: u32) !void {
    if (meta.chunk_count == 0 or meta.chunk_count == metadata_nonce_counter) return error.InvalidFormat;
    if (meta.chunk_count != chunkCount(meta.plaintext_size, chunk_size)) return error.InvalidFormat;
}

test "header round trip" {
    const h: Header = .{
        .chunk_size = default_chunk_size,
        .kdf = .{},
        .salt = [_]u8{7} ** 32,
        .nonce_prefix = [_]u8{9} ** 16,
        .metadata_ciphertext = [_]u8{3} ** metadata_len,
        .metadata_tag = [_]u8{4} ** Aead.tag_length,
    };
    const bytes = h.encode();
    const decoded = try Header.decode(&bytes);
    try std.testing.expectEqual(h.chunk_size, decoded.chunk_size);
    try std.testing.expectEqual(h.kdf.memory_kib, decoded.kdf.memory_kib);
    try std.testing.expectEqualSlices(u8, &h.salt, &decoded.salt);
    try std.testing.expectEqualSlices(u8, &h.nonce_prefix, &decoded.nonce_prefix);
}

test "metadata is authenticated" {
    const key = [_]u8{0x42} ** Aead.key_length;
    var h: Header = .{
        .chunk_size = default_chunk_size,
        .kdf = .{},
        .salt = [_]u8{1} ** 32,
        .nonce_prefix = [_]u8{2} ** 16,
        .metadata_ciphertext = [_]u8{0} ** metadata_len,
        .metadata_tag = [_]u8{0} ** Aead.tag_length,
    };
    h = sealMetadata(h, key, .{ .plaintext_size = 1234, .chunk_count = 1 });
    const encoded = h.encode();
    const meta = try openMetadata(h, &encoded, key);
    try std.testing.expectEqual(@as(u64, 1234), meta.plaintext_size);

    var tampered = encoded;
    // Salt is public header material that must remain authenticated. Changing it
    // keeps the header structurally valid but must invalidate the metadata tag.
    tampered[32] ^= 1;
    const parsed = try Header.decode(&tampered);
    try std.testing.expectError(error.AuthenticationFailed, openMetadata(parsed, &tampered, key));
}


test "data records bind ciphertext to header and record index" {
    const key = [_]u8{0x5a} ** Aead.key_length;
    var h: Header = .{
        .chunk_size = default_chunk_size,
        .kdf = .{},
        .salt = [_]u8{0x11} ** 32,
        .nonce_prefix = [_]u8{0x22} ** 16,
        .metadata_ciphertext = [_]u8{0} ** metadata_len,
        .metadata_tag = [_]u8{0} ** Aead.tag_length,
    };
    h = sealMetadata(h, key, .{ .plaintext_size = 32, .chunk_count = 1 });
    const header_bytes = h.encode();

    const plaintext = [_]u8{0xa5} ** 32;
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [Aead.tag_length]u8 = undefined;
    const ad0 = dataAd(&header_bytes, 0);
    Aead.encrypt(&ciphertext, &tag, &plaintext, &ad0, nonce(h.nonce_prefix, 0), key);

    var opened: [plaintext.len]u8 = undefined;
    try Aead.decrypt(&opened, &ciphertext, tag, &ad0, nonce(h.nonce_prefix, 0), key);
    try std.testing.expectEqualSlices(u8, &plaintext, &opened);

    const ad1 = dataAd(&header_bytes, 1);
    try std.testing.expectError(
        error.AuthenticationFailed,
        Aead.decrypt(&opened, &ciphertext, tag, &ad1, nonce(h.nonce_prefix, 1), key),
    );

    var tampered = ciphertext;
    tampered[0] ^= 1;
    try std.testing.expectError(
        error.AuthenticationFailed,
        Aead.decrypt(&opened, &tampered, tag, &ad0, nonce(h.nonce_prefix, 0), key),
    );
}

test "chunk count and encrypted size arithmetic" {
    try std.testing.expectEqual(@as(u64, 1), chunkCount(0, default_chunk_size));
    try std.testing.expectEqual(@as(u64, 1), chunkCount(default_chunk_size, default_chunk_size));
    try std.testing.expectEqual(@as(u64, 2), chunkCount(default_chunk_size + 1, default_chunk_size));

    const record_size: u64 = @as(u64, default_chunk_size) + Aead.tag_length;
    try std.testing.expectEqual(
        @as(u64, header_len) + 2 * record_size,
        try expectedEncryptedSize(2, default_chunk_size),
    );
}
