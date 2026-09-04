# e-tools

This workspace contains 50 standalone password-file encryption applications. The rule is literal: **x1 through x50 use 50 different payload-encryption algorithm families**. A KDF change, key-size change, mode change, or chunk-size change does not count as a different payload algorithm.

All apps keep the same command-line contract:

```text
xN E|D <input> <output>
```

The password prompt, bounded password derivation, authenticated record framing, temporary-output handling, and no-clobber commit are shared safety concepts. Each crate still owns its implementation, format ID, dependencies, payload primitive, tests, and README. Ciphertexts are deliberately rejected by every sibling app.

| App | Payload algorithm | Record protection | Intended status |
|---|---|---|---|
| [x1](x1/README.md) | AES-256-GCM | Native AEAD | Modern |
| [x2](x2/README.md) | ChaCha20-Poly1305 | Native AEAD | Modern |
| [x3](x3/README.md) | Ascon-AEAD128 | Native AEAD | Standardized; crate unaudited |
| [x4](x4/README.md) | AEGIS-256 | Native AEAD | Experimental |
| [x5](x5/README.md) | XSalsa20-Poly1305 | Secretbox | Established construction |
| [x6](x6/README.md) | Deoxys-II-256 | Native AEAD | Experimental |
| [x7](x7/README.md) | ISAP-Keccak-128A | Native AEAD | Experimental |
| [x8](x8/README.md) | MORUS-1280-128 | Native AEAD | Experimental |
| [x9](x9/README.md) | Gimli-AEAD | Native AEAD | Educational |
| [x10](x10/README.md) | Xoodyak | Native AEAD | Experimental |
| [x11](x11/README.md) | Forro14-Poly1305 | Native AEAD | Experimental |
| [x12](x12/README.md) | KCipher-2 | HMAC Encrypt-then-MAC | Specialized |
| [x13](x13/README.md) | SNOW-V-GCM | Native AEAD | Experimental |
| [x14](x14/README.md) | Strumok | HMAC Encrypt-then-MAC | Specialized |
| [x15](x15/README.md) | Enocoro-128v2 | HMAC Encrypt-then-MAC | Educational |
| [x16](x16/README.md) | HC-128 | HMAC Encrypt-then-MAC | Educational |
| [x17](x17/README.md) | Turing | HMAC Encrypt-then-MAC | Educational |
| [x18](x18/README.md) | NORX64-4-1 | Native AEAD | Experimental / legacy |
| [x19](x19/README.md) | Grain-128AEADv2 | Native AEAD | Experimental |
| [x20](x20/README.md) | Romulus-M | Native AEAD | Experimental |
| [x21](x21/README.md) | Saturnin-CTR-Cascade | Native AEAD | Experimental |
| [x22](x22/README.md) | MKV128-256-GCM | Native AEAD | Experimental |
| [x23](x23/README.md) | BLAKE3-AEAD | Native authenticated cipher | Research-only |
| [x24](x24/README.md) | Kalyna-256/256-GCM | Native AEAD | Specialized |
| [x25](x25/README.md) | ZUC-128 | HMAC Encrypt-then-MAC | Specialized |
| [x26](x26/README.md) | SIMON128-256 | HMAC Encrypt-then-MAC | Educational |
| [x27](x27/README.md) | SPECK128-256 | HMAC Encrypt-then-MAC | Educational |
| [x28](x28/README.md) | CAST6-256 | HMAC Encrypt-then-MAC | Legacy |
| [x29](x29/README.md) | RC6-256 | HMAC Encrypt-then-MAC | Legacy |
| [x30](x30/README.md) | IDEA-128 | HMAC Encrypt-then-MAC | Legacy |
| [x31](x31/README.md) | SEED-128 | HMAC Encrypt-then-MAC | Legacy |
| [x32](x32/README.md) | PRESENT-128 | HMAC Encrypt-then-MAC | Educational |
| [x33](x33/README.md) | Magma | HMAC Encrypt-then-MAC | Legacy |
| [x34](x34/README.md) | Trivium | HMAC Encrypt-then-MAC | Educational |
| [x35](x35/README.md) | ARIA-256 | HMAC Encrypt-then-MAC | Standardized; crate unaudited |
| [x36](x36/README.md) | Camellia-256 | HMAC Encrypt-then-MAC | Standardized; crate unaudited |
| [x37](x37/README.md) | Serpent-256 | HMAC Encrypt-then-MAC | AES finalist; crate unaudited |
| [x38](x38/README.md) | Twofish-256 | HMAC Encrypt-then-MAC | AES finalist; crate unaudited |
| [x39](x39/README.md) | Kuznyechik | HMAC Encrypt-then-MAC | Standardized; crate unaudited |
| [x40](x40/README.md) | SM4 | HMAC Encrypt-then-MAC | Standardized; crate unaudited |
| [x41](x41/README.md) | Blowfish | HMAC Encrypt-then-MAC | Legacy; educational only |
| [x42](x42/README.md) | BELT-DWP | Native AEAD plus outer HMAC EtM | Standardized; crate unaudited |
| [x43](x43/README.md) | GIFT-128 | HMAC Encrypt-then-MAC | Experimental |
| [x44](x44/README.md) | Threefish-256 | HMAC Encrypt-then-MAC | Experimental |
| [x45](x45/README.md) | LEA-256 | HMAC Encrypt-then-MAC | Specialized |
| [x46](x46/README.md) | Spritz | HMAC Encrypt-then-MAC | Educational only |
| [x47](x47/README.md) | Rabbit | HMAC Encrypt-then-MAC | Legacy |
| [x48](x48/README.md) | TEA-32 | HMAC Encrypt-then-MAC | Broken / educational only |
| [x49](x49/README.md) | Skipjack | HMAC Encrypt-then-MAC | Broken / educational only |
| [x50](x50/README.md) | RC4-drop3072 | HMAC Encrypt-then-MAC | Broken / educational only |

Run the workspace guard before accepting changes:

```powershell
./verify-algorithms.ps1
cargo test --workspace
```

The verifier requires 50 declared payload algorithms and 50 distinct `src/main.rs` hashes. These custom file formats have not had an independent cryptographic audit. The legacy and educational apps exist to meet the explicit algorithm-diversity requirement and must not be used for sensitive data.
