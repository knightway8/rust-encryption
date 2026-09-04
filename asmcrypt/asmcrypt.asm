; asmcrypt - authenticated file encryption in NASM x86-64 assembly
;
; The program owns the CLI, file format, framing, and I/O.  It delegates the
; cryptographic primitives to libsodium instead of attempting to invent or
; hand-code a cipher.

default rel

global main

extern __errno_location
extern basename
extern close
extern dirname
extern dprintf
extern fstatat
extern free
extern fsync
extern getpass
extern linkat
extern lseek
extern memcmp
extern memcpy
extern memset
extern open
extern openat
extern perror
extern prctl
extern read
extern snprintf
extern strdup
extern strcmp
extern strnlen
extern write

extern sodium_init
extern sodium_mlock
extern sodium_memzero
extern sodium_munlock
extern randombytes_buf
extern crypto_pwhash
extern crypto_pwhash_alg_argon2id13
extern crypto_pwhash_saltbytes
extern crypto_secretstream_xchacha20poly1305_statebytes
extern crypto_secretstream_xchacha20poly1305_keybytes
extern crypto_secretstream_xchacha20poly1305_headerbytes
extern crypto_secretstream_xchacha20poly1305_abytes
extern crypto_secretstream_xchacha20poly1305_tag_message
extern crypto_secretstream_xchacha20poly1305_tag_final
extern crypto_secretstream_xchacha20poly1305_init_push
extern crypto_secretstream_xchacha20poly1305_push
extern crypto_secretstream_xchacha20poly1305_init_pull
extern crypto_secretstream_xchacha20poly1305_pull

%define MODE_ENCRYPT            1
%define MODE_DECRYPT            2

%define FORMAT_VERSION          1
%define KDF_ID_ARGON2ID13       1
%define CIPHER_ID_SECRETSTREAM  1

%define HEADER_SIZE             72
%define SALT_SIZE               16
%define STREAM_HEADER_SIZE      24
%define KEY_SIZE                32
%define STATE_CAPACITY          64
%define ABYTES                  17
%define CHUNK_SIZE              65536
%define CIPHER_CHUNK            (CHUNK_SIZE + ABYTES)
%define PASSWORD_CAP            1024
%define SENSITIVE_SIZE          (STATE_CAPACITY + KEY_SIZE + PASSWORD_CAP)

; Fixed v1 KDF parameters: Argon2id, three passes, 256 MiB.
%define KDF_OPSLIMIT            3
%define KDF_MEMLIMIT            268435456

%define O_RDONLY                0
%define O_WRONLY                1
%define O_CLOEXEC               0x80000
%define INPUT_FLAGS             (O_RDONLY | O_CLOEXEC)
%define O_DIRECTORY             0x10000
%define O_TMPFILE               0x410000
%define DIRECTORY_FLAGS         (O_RDONLY | O_DIRECTORY | O_CLOEXEC)
%define TEMPORARY_FLAGS         (O_WRONLY | O_TMPFILE | O_CLOEXEC)
%define OUTPUT_MODE             0x180       ; 0600

%define SEEK_SET                0
%define SEEK_END                2
%define EINTR                   4
%define EIO                     5
%define ENOENT                  2
%define EEXIST                  17

%define AT_FDCWD                -100
%define AT_SYMLINK_NOFOLLOW     0x100
%define AT_SYMLINK_FOLLOW       0x400
%define PR_SET_DUMPABLE         4

%macro FAIL 1
    lea rdi, [rel %1]
    call print_error
    mov dword [rel exit_code], 1
    jmp cleanup_main
%endmacro

%macro FAIL_SYS 1
    lea rdi, [rel %1]
    call perror wrt ..plt
    mov dword [rel exit_code], 1
    jmp cleanup_main
%endmacro

section .rodata
    magic                   db "ASMENC01"
    command_encrypt         db "encrypt", 0
    command_decrypt         db "decrypt", 0

    prompt_encrypt          db "Passphrase: ", 0
    prompt_confirm          db "Confirm passphrase: ", 0
    prompt_decrypt          db "Passphrase: ", 0

    usage_text              db "Usage:", 10
                            db "  asmcrypt encrypt INPUT OUTPUT", 10
                            db "  asmcrypt decrypt INPUT OUTPUT", 10, 0

    error_format            db "asmcrypt: %s", 10, 0
    success_encrypt_format  db "asmcrypt: encrypted -> %s", 10, 0
    success_decrypt_format  db "asmcrypt: decrypted -> %s", 10, 0
    proc_fd_format          db "/proc/self/fd/%d", 0
    current_directory       db ".", 0

    err_crypto_runtime      db "the installed libsodium ABI is unsupported", 0
    err_sodium_init         db "libsodium initialization failed", 0
    err_memory_protection   db "could not protect cryptographic secrets in memory", 0
    err_password            db "passphrase is empty, too long, or unavailable", 0
    err_password_mismatch   db "passphrases do not match", 0
    err_kdf                 db "Argon2id key derivation failed", 0
    err_crypto_init         db "encryption initialization failed", 0
    err_crypto_record       db "encryption failed", 0
    err_bad_format          db "invalid or truncated encrypted file", 0
    err_auth                db "authentication failed (wrong passphrase or damaged file)", 0

    sys_open_input          db "asmcrypt: cannot open input", 0
    sys_create_output       db "asmcrypt: cannot create anonymous output (target may already exist)", 0
    sys_publish_output      db "asmcrypt: cannot publish output (target may already exist)", 0
    sys_read_input          db "asmcrypt: input read failed", 0
    sys_write_output        db "asmcrypt: output write failed", 0
    sys_seek_input          db "asmcrypt: input must be a regular, seekable file", 0
    sys_sync_output         db "asmcrypt: output sync failed", 0
    sys_sync_directory      db "asmcrypt: output published, but directory sync failed", 0
    sys_close_published     db "asmcrypt: output published, but output close failed", 0
    sys_close_directory     db "asmcrypt: output published, but directory close failed", 0

section .bss
    alignb 64
    stream_state            resb STATE_CAPACITY
    key                     resb KEY_SIZE
    password                resb PASSWORD_CAP
    header                  resb HEADER_SIZE
    plain_a                 resb CHUNK_SIZE
    plain_b                 resb CHUNK_SIZE
    cipher_buffer           resb CIPHER_CHUNK
    stat_scratch            resb 256
    proc_fd_path            resb 64

    alignb 8
    password_length         resq 1
    cipher_length           resq 1
    plain_length            resq 1
    input_path              resq 1
    output_path             resq 1
    directory_copy          resq 1
    basename_copy           resq 1
    directory_path          resq 1
    basename_path           resq 1
    file_remaining          resq 1

    input_fd                resd 1
    output_fd               resd 1
    directory_fd            resd 1
    mode                    resd 1
    exit_code               resd 1
    sensitive_locked        resd 1
    pwhash_algorithm        resd 1

    record_tag              resb 1
    tag_message_value       resb 1
    tag_final_value         resb 1

section .text

; int main(int argc, char **argv)
main:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    push r15

    mov dword [rel input_fd], -1
    mov dword [rel output_fd], -1
    mov dword [rel directory_fd], -1
    mov dword [rel exit_code], 0
    mov qword [rel input_path], 0
    mov qword [rel output_path], 0
    mov qword [rel directory_copy], 0
    mov qword [rel basename_copy], 0
    mov qword [rel directory_path], 0
    mov qword [rel basename_path], 0
    mov dword [rel sensitive_locked], 0

    cmp edi, 4
    jne .usage
    mov r12, rsi

    mov rdi, [r12 + 8]
    lea rsi, [rel command_encrypt]
    call strcmp wrt ..plt
    test eax, eax
    jz .selected_encrypt

    mov rdi, [r12 + 8]
    lea rsi, [rel command_decrypt]
    call strcmp wrt ..plt
    test eax, eax
    jz .selected_decrypt
    jmp .usage

.selected_encrypt:
    mov dword [rel mode], MODE_ENCRYPT
    jmp .arguments_ready

.selected_decrypt:
    mov dword [rel mode], MODE_DECRYPT

.arguments_ready:
    mov rax, [r12 + 16]
    mov [rel input_path], rax
    mov rax, [r12 + 24]
    mov [rel output_path], rax

    call sodium_init wrt ..plt
    cmp eax, -1
    je .sodium_init_failed

    call validate_sodium
    test eax, eax
    jnz .crypto_runtime_failed

    call harden_process
    test eax, eax
    jnz .memory_protection_failed

    mov rdi, [rel input_path]
    mov esi, INPUT_FLAGS
    xor edx, edx
    xor eax, eax
    call open wrt ..plt
    test eax, eax
    js .open_input_failed
    mov [rel input_fd], eax

    cmp dword [rel mode], MODE_ENCRYPT
    je encrypt_file
    jmp decrypt_file

.usage:
    mov edi, 2
    lea rsi, [rel usage_text]
    xor eax, eax
    call dprintf wrt ..plt
    mov dword [rel exit_code], 64
    jmp cleanup_main

.sodium_init_failed:
    FAIL err_sodium_init

.crypto_runtime_failed:
    FAIL err_crypto_runtime

.memory_protection_failed:
    FAIL err_memory_protection

.open_input_failed:
    FAIL_SYS sys_open_input

; ---------------------------------------------------------------------------
; Encryption path
; ---------------------------------------------------------------------------
encrypt_file:
    call create_output
    test eax, eax
    jnz .create_failed

    lea rdi, [rel header]
    xor esi, esi
    mov edx, HEADER_SIZE
    call memset wrt ..plt

    mov rax, [rel magic]
    mov [rel header], rax
    mov byte [rel header + 8], FORMAT_VERSION
    mov byte [rel header + 9], KDF_ID_ARGON2ID13
    mov byte [rel header + 10], CIPHER_ID_SECRETSTREAM
    mov byte [rel header + 11], 0
    mov dword [rel header + 12], CHUNK_SIZE
    mov qword [rel header + 16], KDF_OPSLIMIT
    mov qword [rel header + 24], KDF_MEMLIMIT

    lea rdi, [rel header + 32]
    mov esi, SALT_SIZE
    call randombytes_buf wrt ..plt

    mov edi, 1
    call prompt_for_password
    test eax, eax
    jz .encrypt_password_ready
    cmp eax, 2
    je .password_mismatch
    FAIL err_password

.password_mismatch:
    FAIL err_password_mismatch

.encrypt_password_ready:
    call derive_key
    test eax, eax
    jnz .kdf_failed

    lea rdi, [rel stream_state]
    lea rsi, [rel header + 48]
    lea rdx, [rel key]
    call crypto_secretstream_xchacha20poly1305_init_push wrt ..plt
    test eax, eax
    jnz .crypto_init_failed

    call wipe_password_and_key

    mov edi, [rel output_fd]
    lea rsi, [rel header]
    mov edx, HEADER_SIZE
    call write_all
    test eax, eax
    jz .write_failed

    lea r12, [rel plain_a]
    lea r13, [rel plain_b]
    mov edi, [rel input_fd]
    mov rsi, r12
    mov edx, CHUNK_SIZE
    call read_chunk
    test rax, rax
    js .read_failed
    mov r14, rax
    test r14, r14
    jz .encrypt_empty

.encrypt_loop:
    mov edi, [rel input_fd]
    mov rsi, r13
    mov edx, CHUNK_SIZE
    call read_chunk
    test rax, rax
    js .read_failed
    mov r15, rax
    test r15, r15
    jz .encrypt_final_record

    mov rdi, r12
    mov rsi, r14
    movzx edx, byte [rel tag_message_value]
    call push_record
    test eax, eax
    jnz .record_failed
    mov rax, [rel cipher_length]
    lea rcx, [r14 + ABYTES]
    cmp rax, rcx
    jne .record_failed

    mov edi, [rel output_fd]
    lea rsi, [rel cipher_buffer]
    mov rdx, [rel cipher_length]
    call write_all
    test eax, eax
    jz .write_failed

    xchg r12, r13
    mov r14, r15
    jmp .encrypt_loop

.encrypt_final_record:
    mov rdi, r12
    mov rsi, r14
    movzx edx, byte [rel tag_final_value]
    call push_record
    test eax, eax
    jnz .record_failed
    mov rax, [rel cipher_length]
    lea rcx, [r14 + ABYTES]
    cmp rax, rcx
    jne .record_failed
    jmp .write_final_record

.encrypt_empty:
    lea rdi, [rel plain_a]
    xor esi, esi
    movzx edx, byte [rel tag_final_value]
    call push_record
    test eax, eax
    jnz .record_failed
    cmp qword [rel cipher_length], ABYTES
    jne .record_failed

.write_final_record:
    mov edi, [rel output_fd]
    lea rsi, [rel cipher_buffer]
    mov rdx, [rel cipher_length]
    call write_all
    test eax, eax
    jz .write_failed
    jmp finish_success

.create_failed:
    FAIL_SYS sys_create_output
.read_failed:
    FAIL_SYS sys_read_input
.write_failed:
    FAIL_SYS sys_write_output
.kdf_failed:
    FAIL err_kdf
.crypto_init_failed:
    FAIL err_crypto_init
.record_failed:
    FAIL err_crypto_record

; ---------------------------------------------------------------------------
; Decryption path
; ---------------------------------------------------------------------------
decrypt_file:
    mov edi, [rel input_fd]
    lea rsi, [rel header]
    mov edx, HEADER_SIZE
    call read_chunk
    test rax, rax
    js .decrypt_read_failed
    cmp rax, HEADER_SIZE
    jne .bad_format

    mov rax, [rel magic]
    cmp [rel header], rax
    jne .bad_format
    cmp byte [rel header + 8], FORMAT_VERSION
    jne .bad_format
    cmp byte [rel header + 9], KDF_ID_ARGON2ID13
    jne .bad_format
    cmp byte [rel header + 10], CIPHER_ID_SECRETSTREAM
    jne .bad_format
    cmp byte [rel header + 11], 0
    jne .bad_format
    cmp dword [rel header + 12], CHUNK_SIZE
    jne .bad_format
    cmp qword [rel header + 16], KDF_OPSLIMIT
    jne .bad_format
    cmp qword [rel header + 24], KDF_MEMLIMIT
    jne .bad_format

    mov edi, [rel input_fd]
    xor esi, esi
    mov edx, SEEK_END
    call lseek wrt ..plt
    cmp rax, -1
    je .seek_failed
    cmp rax, (HEADER_SIZE + ABYTES)
    jb .bad_format
    sub rax, HEADER_SIZE
    mov [rel file_remaining], rax

    mov edi, [rel input_fd]
    mov esi, HEADER_SIZE
    mov edx, SEEK_SET
    call lseek wrt ..plt
    cmp rax, -1
    je .seek_failed

    call create_output
    test eax, eax
    jnz .decrypt_create_failed

    xor edi, edi
    call prompt_for_password
    test eax, eax
    jnz .decrypt_password_failed

    call derive_key
    test eax, eax
    jnz .decrypt_kdf_failed

    lea rdi, [rel stream_state]
    lea rsi, [rel header + 48]
    lea rdx, [rel key]
    call crypto_secretstream_xchacha20poly1305_init_pull wrt ..plt
    test eax, eax
    jnz .authentication_failed

    call wipe_password_and_key
    mov r14, [rel file_remaining]

.decrypt_loop:
    cmp r14, CIPHER_CHUNK
    jbe .decrypt_final_record

    mov edi, [rel input_fd]
    lea rsi, [rel cipher_buffer]
    mov edx, CIPHER_CHUNK
    call read_chunk
    test rax, rax
    js .decrypt_read_failed
    cmp rax, CIPHER_CHUNK
    jne .authentication_failed

    mov edi, CIPHER_CHUNK
    call pull_record
    test eax, eax
    jnz .authentication_failed
    mov al, [rel record_tag]
    cmp al, [rel tag_message_value]
    jne .authentication_failed
    cmp qword [rel plain_length], CHUNK_SIZE
    jne .authentication_failed

    mov edi, [rel output_fd]
    lea rsi, [rel plain_a]
    mov rdx, [rel plain_length]
    call write_all
    test eax, eax
    jz .decrypt_write_failed

    sub r14, CIPHER_CHUNK
    jmp .decrypt_loop

.decrypt_final_record:
    cmp r14, ABYTES
    jb .bad_format
    mov edi, [rel input_fd]
    lea rsi, [rel cipher_buffer]
    mov rdx, r14
    call read_chunk
    test rax, rax
    js .decrypt_read_failed
    cmp rax, r14
    jne .authentication_failed

    mov rdi, r14
    call pull_record
    test eax, eax
    jnz .authentication_failed
    mov al, [rel record_tag]
    cmp al, [rel tag_final_value]
    jne .authentication_failed
    mov rax, r14
    sub rax, ABYTES
    cmp [rel plain_length], rax
    jne .authentication_failed

    mov edi, [rel output_fd]
    lea rsi, [rel plain_a]
    mov rdx, [rel plain_length]
    call write_all
    test eax, eax
    jz .decrypt_write_failed

    ; Detect a file that grew after its size was measured.
    mov edi, [rel input_fd]
    lea rsi, [rel cipher_buffer]
    mov edx, 1
    call read_chunk
    test rax, rax
    js .decrypt_read_failed
    jnz .authentication_failed
    jmp finish_success

.decrypt_create_failed:
    FAIL_SYS sys_create_output
.decrypt_read_failed:
    FAIL_SYS sys_read_input
.decrypt_write_failed:
    FAIL_SYS sys_write_output
.seek_failed:
    FAIL_SYS sys_seek_input
.decrypt_password_failed:
    FAIL err_password
.decrypt_kdf_failed:
    FAIL err_kdf
.bad_format:
    FAIL err_bad_format
.authentication_failed:
    FAIL err_auth

; Sync an authenticated anonymous output, then atomically give it its name.
finish_success:
    mov edi, [rel output_fd]
    call fsync wrt ..plt
    test eax, eax
    jnz .sync_failed

    lea rdi, [rel proc_fd_path]
    mov esi, 64
    lea rdx, [rel proc_fd_format]
    mov ecx, [rel output_fd]
    xor eax, eax
    call snprintf wrt ..plt

    mov edi, AT_FDCWD
    lea rsi, [rel proc_fd_path]
    mov edx, [rel directory_fd]
    mov rcx, [rel basename_path]
    mov r8d, AT_SYMLINK_FOLLOW
    call linkat wrt ..plt
    test eax, eax
    jnz .publish_failed

    ; Persist the newly created directory entry as well as the file contents.
    mov edi, [rel directory_fd]
    call fsync wrt ..plt
    test eax, eax
    jnz .directory_sync_failed

    mov edi, [rel output_fd]
    call close wrt ..plt
    mov dword [rel output_fd], -1
    test eax, eax
    jnz .published_close_failed
    mov edi, [rel directory_fd]
    call close wrt ..plt
    mov dword [rel directory_fd], -1
    test eax, eax
    jnz .directory_close_failed

    mov dword [rel exit_code], 0

    mov edi, 1
    cmp dword [rel mode], MODE_ENCRYPT
    jne .print_decrypt_success
    lea rsi, [rel success_encrypt_format]
    jmp .print_success
.print_decrypt_success:
    lea rsi, [rel success_decrypt_format]
.print_success:
    mov rdx, [rel output_path]
    xor eax, eax
    call dprintf wrt ..plt
    jmp cleanup_main

.sync_failed:
    FAIL_SYS sys_sync_output
.publish_failed:
    FAIL_SYS sys_publish_output
.directory_sync_failed:
    FAIL_SYS sys_sync_directory
.published_close_failed:
    FAIL_SYS sys_close_published
.directory_close_failed:
    FAIL_SYS sys_close_directory

; Closing an unpublished O_TMPFILE descriptor deletes it automatically.
cleanup_main:
    cmp dword [rel output_fd], -1
    je .directory_cleanup
    mov edi, [rel output_fd]
    call close wrt ..plt
    mov dword [rel output_fd], -1

.directory_cleanup:
    cmp dword [rel directory_fd], -1
    je .input_cleanup
    mov edi, [rel directory_fd]
    call close wrt ..plt
    mov dword [rel directory_fd], -1

.input_cleanup:
    cmp dword [rel input_fd], -1
    je .free_path_copies
    mov edi, [rel input_fd]
    call close wrt ..plt
    mov dword [rel input_fd], -1

.free_path_copies:
    mov rdi, [rel directory_copy]
    test rdi, rdi
    jz .free_basename_copy
    call free wrt ..plt
    mov qword [rel directory_copy], 0
    mov qword [rel directory_path], 0

.free_basename_copy:
    mov rdi, [rel basename_copy]
    test rdi, rdi
    jz .wipe
    call free wrt ..plt
    mov qword [rel basename_copy], 0
    mov qword [rel basename_path], 0

.wipe:
    lea rdi, [rel password]
    mov esi, PASSWORD_CAP
    call sodium_memzero wrt ..plt
    lea rdi, [rel key]
    mov esi, KEY_SIZE
    call sodium_memzero wrt ..plt
    lea rdi, [rel stream_state]
    mov esi, STATE_CAPACITY
    call sodium_memzero wrt ..plt
    lea rdi, [rel plain_a]
    mov esi, CHUNK_SIZE
    call sodium_memzero wrt ..plt
    lea rdi, [rel plain_b]
    mov esi, CHUNK_SIZE
    call sodium_memzero wrt ..plt

    cmp dword [rel sensitive_locked], 0
    je .return_from_main
    lea rdi, [rel stream_state]
    mov esi, SENSITIVE_SIZE
    call sodium_munlock wrt ..plt
    mov dword [rel sensitive_locked], 0

.return_from_main:
    mov eax, [rel exit_code]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    ret

; ---------------------------------------------------------------------------
; Helpers
; ---------------------------------------------------------------------------

; Return 0 if the linked libsodium exposes the ABI sizes this source expects.
validate_sodium:
    sub rsp, 8
    call crypto_pwhash_saltbytes wrt ..plt
    cmp rax, SALT_SIZE
    jne .bad
    call crypto_secretstream_xchacha20poly1305_statebytes wrt ..plt
    test rax, rax
    jz .bad
    cmp rax, STATE_CAPACITY
    ja .bad
    call crypto_secretstream_xchacha20poly1305_keybytes wrt ..plt
    cmp rax, KEY_SIZE
    jne .bad
    call crypto_secretstream_xchacha20poly1305_headerbytes wrt ..plt
    cmp rax, STREAM_HEADER_SIZE
    jne .bad
    call crypto_secretstream_xchacha20poly1305_abytes wrt ..plt
    cmp rax, ABYTES
    jne .bad
    call crypto_secretstream_xchacha20poly1305_tag_message wrt ..plt
    mov [rel tag_message_value], al
    call crypto_secretstream_xchacha20poly1305_tag_final wrt ..plt
    mov [rel tag_final_value], al
    call crypto_pwhash_alg_argon2id13 wrt ..plt
    test eax, eax
    js .bad
    mov [rel pwhash_algorithm], eax
    xor eax, eax
    add rsp, 8
    ret
.bad:
    mov eax, -1
    add rsp, 8
    ret

; Disable core dumps and lock the password/key/state buffers in RAM.
harden_process:
    sub rsp, 8

    mov edi, PR_SET_DUMPABLE
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor eax, eax
    call prctl wrt ..plt
    test eax, eax
    jnz .hardening_failed

    lea rdi, [rel stream_state]
    mov esi, SENSITIVE_SIZE
    call sodium_mlock wrt ..plt
    test eax, eax
    jnz .hardening_failed

    mov dword [rel sensitive_locked], 1
    xor eax, eax
    add rsp, 8
    ret

.hardening_failed:
    mov eax, -1
    add rsp, 8
    ret

; Create an anonymous file in the destination directory.  It has no pathname
; until finish_success() authenticates, syncs, and publishes it with linkat().
create_output:
    sub rsp, 8

    mov rdi, [rel output_path]
    call strdup wrt ..plt
    test rax, rax
    jz .create_failed
    mov [rel directory_copy], rax
    mov rdi, rax
    call dirname wrt ..plt
    test rax, rax
    jz .create_failed
    mov [rel directory_path], rax

    mov rdi, [rel output_path]
    call strdup wrt ..plt
    test rax, rax
    jz .create_failed
    mov [rel basename_copy], rax
    mov rdi, rax
    call basename wrt ..plt
    test rax, rax
    jz .create_failed
    mov [rel basename_path], rax

    mov rdi, [rel directory_path]
    mov esi, DIRECTORY_FLAGS
    xor edx, edx
    xor eax, eax
    call open wrt ..plt
    test eax, eax
    js .create_failed
    mov [rel directory_fd], eax

    ; Early user-friendly existence check. linkat() is still the authoritative
    ; atomic no-overwrite operation if another file appears later.
    mov edi, [rel directory_fd]
    mov rsi, [rel basename_path]
    lea rdx, [rel stat_scratch]
    mov ecx, AT_SYMLINK_NOFOLLOW
    call fstatat wrt ..plt
    test eax, eax
    jz .target_exists
    call __errno_location wrt ..plt
    cmp dword [rax], ENOENT
    jne .create_failed

    mov edi, [rel directory_fd]
    lea rsi, [rel current_directory]
    mov edx, TEMPORARY_FLAGS
    mov ecx, OUTPUT_MODE
    xor eax, eax
    call openat wrt ..plt
    test eax, eax
    js .create_failed
    mov [rel output_fd], eax
    xor eax, eax
    jmp .create_done

.target_exists:
    call __errno_location wrt ..plt
    mov dword [rax], EEXIST
.create_failed:
    mov eax, -1
.create_done:
    add rsp, 8
    ret

; prompt_for_password(verify)
; Returns 0 on success, 1 on invalid/unavailable input, 2 on mismatch.
prompt_for_password:
    push r12
    push r13
    push r14
    mov r14d, edi

    test r14d, r14d
    jz .decrypt_prompt
    lea rdi, [rel prompt_encrypt]
    jmp .first_prompt
.decrypt_prompt:
    lea rdi, [rel prompt_decrypt]
.first_prompt:
    call getpass wrt ..plt
    test rax, rax
    jz .invalid
    mov r12, rax

    mov rdi, r12
    mov esi, PASSWORD_CAP
    call strnlen wrt ..plt
    mov r13, rax
    test r13, r13
    jz .invalid_with_buffer
    cmp r13, PASSWORD_CAP
    jae .invalid_with_buffer

    lea rdi, [rel password]
    mov rsi, r12
    mov rdx, r13
    call memcpy wrt ..plt
    lea rax, [rel password]
    mov byte [rax + r13], 0
    mov [rel password_length], r13

    mov rdi, r12
    mov rsi, r13
    call sodium_memzero wrt ..plt

    test r14d, r14d
    jz .success

    lea rdi, [rel prompt_confirm]
    call getpass wrt ..plt
    test rax, rax
    jz .invalid
    mov r12, rax
    mov rdi, r12
    mov esi, PASSWORD_CAP
    call strnlen wrt ..plt
    mov r13, rax
    cmp r13, PASSWORD_CAP
    jae .invalid_with_buffer
    cmp r13, [rel password_length]
    jne .mismatch

    lea rdi, [rel password]
    mov rsi, r12
    mov rdx, r13
    call memcmp wrt ..plt
    mov r14d, eax
    mov rdi, r12
    mov rsi, r13
    call sodium_memzero wrt ..plt
    test r14d, r14d
    jnz .return_mismatch

.success:
    xor eax, eax
    jmp .return

.mismatch:
    mov rdi, r12
    mov rsi, r13
    call sodium_memzero wrt ..plt
.return_mismatch:
    mov eax, 2
    jmp .return

.invalid_with_buffer:
    mov rdi, r12
    mov rsi, r13
    call sodium_memzero wrt ..plt
.invalid:
    mov eax, 1
.return:
    pop r14
    pop r13
    pop r12
    ret

; Derive a 32-byte key using the parameters authenticated in the header.
derive_key:
    sub rsp, 24
    lea rdi, [rel key]
    mov esi, KEY_SIZE
    lea rdx, [rel password]
    mov rcx, [rel password_length]
    lea r8, [rel header + 32]
    mov r9, [rel header + 16]
    mov rax, [rel header + 24]
    mov [rsp], rax
    mov eax, [rel pwhash_algorithm]
    mov [rsp + 8], rax
    call crypto_pwhash wrt ..plt
    add rsp, 24
    ret

wipe_password_and_key:
    sub rsp, 8
    lea rdi, [rel password]
    mov esi, PASSWORD_CAP
    call sodium_memzero wrt ..plt
    lea rdi, [rel key]
    mov esi, KEY_SIZE
    call sodium_memzero wrt ..plt
    add rsp, 8
    ret

; push_record(plaintext_pointer, plaintext_length, tag)
push_record:
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi
    mov r14d, edx
    sub rsp, 16
    lea rdi, [rel stream_state]
    lea rsi, [rel cipher_buffer]
    lea rdx, [rel cipher_length]
    mov rcx, r12
    mov r8, r13
    lea r9, [rel header]
    mov qword [rsp], HEADER_SIZE
    mov [rsp + 8], r14
    call crypto_secretstream_xchacha20poly1305_push wrt ..plt
    add rsp, 16
    pop r14
    pop r13
    pop r12
    ret

; pull_record(ciphertext_length)
pull_record:
    push r12
    mov r12, rdi
    sub rsp, 16
    lea rdi, [rel stream_state]
    lea rsi, [rel plain_a]
    lea rdx, [rel plain_length]
    lea rcx, [rel record_tag]
    lea r8, [rel cipher_buffer]
    mov r9, r12
    lea rax, [rel header]
    mov [rsp], rax
    mov qword [rsp + 8], HEADER_SIZE
    call crypto_secretstream_xchacha20poly1305_pull wrt ..plt
    add rsp, 16
    pop r12
    ret

; read_chunk(fd, buffer, maximum) -> byte count, or -1 on error.
; Fills the requested size unless EOF is encountered; retries EINTR.
read_chunk:
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r12d, edi
    mov r13, rsi
    mov r14, rdx
    xor r15d, r15d
.read_loop:
    test r14, r14
    jz .read_done
    mov edi, r12d
    mov rsi, r13
    mov rdx, r14
    call read wrt ..plt
    test rax, rax
    js .read_error
    jz .read_done
    add r13, rax
    sub r14, rax
    add r15, rax
    jmp .read_loop
.read_error:
    call __errno_location wrt ..plt
    cmp dword [rax], EINTR
    je .read_loop
    mov r15, -1
.read_done:
    mov rax, r15
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    ret

; write_all(fd, buffer, length) -> 1 on success, 0 on error.
write_all:
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r12d, edi
    mov r13, rsi
    mov r14, rdx
.write_loop:
    test r14, r14
    jz .write_done
    mov edi, r12d
    mov rsi, r13
    mov rdx, r14
    call write wrt ..plt
    test rax, rax
    js .write_error
    jz .write_zero
    add r13, rax
    sub r14, rax
    jmp .write_loop
.write_error:
    call __errno_location wrt ..plt
    cmp dword [rax], EINTR
    je .write_loop
    xor r15d, r15d
    jmp .write_return
.write_zero:
    call __errno_location wrt ..plt
    mov dword [rax], EIO
    xor r15d, r15d
    jmp .write_return
.write_done:
    mov r15d, 1
.write_return:
    mov eax, r15d
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    ret

; print_error(message)
print_error:
    sub rsp, 8
    mov rdx, rdi
    mov edi, 2
    lea rsi, [rel error_format]
    xor eax, eax
    call dprintf wrt ..plt
    add rsp, 8
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
