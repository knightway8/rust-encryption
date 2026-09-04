# Test catalog

## Exact count

`cargo test --locked --all-targets` discovers **3,291 tests** on each supported
platform. It runs 3,289 by default and leaves two production-cost Argon2id
tests ignored.

| Test group | Declared/generated tests |
| --- | ---: |
| 21 original CLI tests for each of 22 executables | 462 |
| 126 deep CLI tests for each of 21 non-x4x executables | 2,646 |
| x4x internal tests | 126 |
| Shared x3x unit tests | 36 |
| Cross-binary integration tests | 22 |

The source-level rows total 3,292 because
`completed_outputs_are_owner_only_on_unix` is Unix-only and
`case_alias_of_active_key_is_refused` is Windows-only. Exactly one of those is
compiled on a given platform, leaving 3,291 discovered tests everywhere.

The 21 non-x4x applications each have 21 original tests plus 126 deep tests.
x4x has 21 CLI tests plus 126 declared internal tests. That is 147 attributable
tests per application.

Test identifiers below are behavioral descriptions: read underscores as
spaces. For example, `rejects_a_missing_key` verifies that a missing key is
rejected. Shared definitions are documented once and list every app that runs
them.

## Workflow checks

`.github/workflows/rust.yml` runs on Windows, Ubuntu, and macOS. Each job checks
rustfmt, runs Clippy with warnings denied, builds every release binary, and runs
all 3,291 tests. `.github/workflows/audit.yml` runs RustSec on pushes, pull
requests, manual dispatches, and weekly. `.github/dependabot.yml` checks Cargo
and GitHub Actions dependencies weekly.

## Deep CLI suite: 2,646 tests

`tests/deep_apps.rs` expands cases `000` through `125` for:

- `aes`, `aesp`, `cha`, `chap`, `ser`, `serp`, `thf`, `thfp`, `asc`, `ascp`,
  `rabbit`, `rabbitp`, `aegis256`, `aegis256p`, `aegis128l`, `aegis128lp`,
  `keygen`, `keymake`, `key2txt`, `txt2key`, and `otp`.

Every generated test launches the real executable and verifies exit code 1,
empty stdout, an `error: ` prefix on stderr, no panic/backtrace, no unintended
output or temporary file, and no mutation of protected inputs or keys.

### What every deep case does

- `deep_cli_case_000` through `deep_cli_case_015`: pass 0 through 15 user
  arguments. If the count equals the valid arity, add 16. These independently
  test too-few and too-many arguments. Cipher apps expect 3 arguments, size and
  converter apps expect 1, and OTP expects 2.
- Cipher cases `016` through `063`: use a valid three-argument shape with these
  48 invalid operations, in order: `e`, `d`, `encrypt`, `decrypt`, `ENCRYPT`,
  `DECRYPT`, `ED`, `DE`, `E `, ` D`, `+E`, `-D`, `0`, `1`, `?`, `É`, then
  `invalid-operation-16` through `invalid-operation-47`.
- Cipher cases `064` through `094`: put an invalid portable filename in the
  input position. Key-file apps receive a valid key first.
- Cipher cases `095` through `125`: put an invalid portable filename in the
  output position after creating a valid input and, when needed, a valid key.
- `keygen` and `keymake` cases `016` through `125`: cycle through negative
  decimals, doubled plus signs, letter suffixes, hex notation, exponent
  notation, underscores, leading whitespace, trailing whitespace, fractions,
  and integers larger than `u64::MAX`. Each case uses a different numeric value.
- `key2txt` and `txt2key` cases `016` through `125`: cycle through forward- and
  backslash paths, colon, asterisk, question mark, quote, less-than, greater-than,
  pipe, trailing dot, trailing space, and reserved `NUL` basenames.
- `otp` cases `016` through `125`: use the same invalid-name sequence. Even IDs
  invalidate the input name; odd IDs invalidate the key name. Both valid files
  are created first and must remain unchanged.

This ID mapping completely specifies each of the 126 tests in every named app
module.

## Key-file cipher CLI suite: 168 tests

These 21 tests run for each of `aes`, `cha`, `ser`, `thf`, `asc`, `rabbit`,
`aegis256`, and `aegis128l`:

| Test | Assertion |
| --- | --- |
| `reports_usage_for_wrong_argument_counts` | Wrong arities print usage. |
| `rejects_invalid_operations` | Only exact uppercase E/D are accepted. |
| `round_trips_multiple_chunks` | Multi-record data round-trips. |
| `round_trips_empty_files` | Authenticated empty files round-trip. |
| `produces_fresh_ciphertexts` | Re-encryption uses a fresh nonce. |
| `rejects_a_missing_key` | The fixed key file is mandatory. |
| `rejects_wrong_key_sizes` | Short and long keys fail. |
| `rejects_a_missing_input` | Missing input creates no output. |
| `preserves_an_existing_output` | Encryption never overwrites output. |
| `rejects_nonportable_filenames` | Unsafe names and paths fail. |
| `protects_the_active_key_file` | The key cannot be input or output. |
| `rejects_damaged_ciphertext` | Ciphertext damage fails authentication. |
| `rejects_a_wrong_key_without_output` | Wrong-key decryption fails closed. |
| `round_trips_exact_chunk_boundaries_without_modifying_inputs` | Record boundaries and input immutability hold. |
| `rejects_truncated_and_trailing_data_without_artifacts` | Truncation/appends leave no artifacts. |
| `rejects_malformed_headers_without_output` | Structural header damage fails closed. |
| `authenticates_nonce_header_bytes` | Nonce/header bytes are authenticated. |
| `preserves_an_existing_decryption_output` | Decryption never overwrites output. |
| `round_trips_single_byte` | Minimum nonempty input round-trips. |
| `round_trips_every_byte_value` | All 256 byte values round-trip. |
| `successful_round_trip_leaves_only_named_files` | Success leaves no hidden artifacts. |

## Password-cipher CLI suite: 168 tests

These 21 tests run for each of `aesp`, `chap`, `serp`, `thfp`, `ascp`,
`rabbitp`, `aegis256p`, and `aegis128lp`:

| Test | Assertion |
| --- | --- |
| `reports_usage_without_arguments` | Zero arguments print usage. |
| `reports_usage_with_one_argument` | One argument prints usage. |
| `reports_usage_with_two_arguments` | Two arguments print usage. |
| `reports_usage_with_extra_arguments` | Extra arguments print usage. |
| `rejects_lowercase_operations` | Lowercase operations fail. |
| `rejects_operation_words` | Word-form operations fail. |
| `rejects_empty_or_combined_operations` | Empty/combined operations fail. |
| `validates_operation_before_touching_files` | Parsing precedes file access. |
| `rejects_a_missing_input_before_prompting` | Missing decrypt input fails before prompt. |
| `preserves_an_existing_output_before_prompting` | Existing decrypt output fails before prompt. |
| `rejects_nonportable_filenames_before_prompting` | Unsafe names fail before prompt. |
| `rejects_a_missing_encryption_input_before_prompting` | Missing encrypt input fails before prompt. |
| `preserves_an_existing_encryption_output_before_prompting` | Existing encrypt output fails before prompt. |
| `rejects_a_directory_input_before_prompting` | Directories are not input files. |
| `preserves_a_directory_at_the_output_name` | Output directories are never replaced. |
| `rejects_parent_traversal_input_before_prompting` | Parent traversal fails. |
| `rejects_absolute_input_before_prompting` | Absolute input fails. |
| `rejects_absolute_output_before_prompting` | Absolute output fails. |
| `rejects_trailing_dot_input_before_prompting` | Trailing-dot names fail. |
| `rejects_reserved_output_names_before_prompting` | Device names fail. |
| `failed_preflight_emits_no_success_output` | Failure cannot print success. |

The shared-unit section contains one password round-trip/wrong-password test
for every password cipher without needing an interactive terminal.

## Utility CLI suites: 105 tests

Each exact identifier below is one process-level behavioral assertion.

### keygen (21)

`reports_usage_for_wrong_argument_counts`, `rejects_non_decimal_sizes`,
`rejects_sizes_outside_the_documented_range`, `creates_exact_requested_sizes`,
`reports_the_created_size`, `generated_key_is_not_an_all_zero_buffer`,
`separate_runs_use_fresh_randomness`, `refuses_to_overwrite_an_existing_key`,
`successful_run_leaves_only_the_requested_key_file`,
`invalid_sizes_leave_no_output_or_temporary_file`,
`refuses_to_replace_a_directory_at_the_output_name`,
`accepts_a_leading_zero_decimal_size`, `rejects_an_empty_size_argument`,
`accepts_an_explicit_plus_sign`, `rejects_exponent_notation`,
`rejects_values_larger_than_u64`, `success_emits_no_stderr`,
`validation_failure_emits_no_stdout`,
`successful_generation_preserves_unrelated_files`,
`refuses_a_hard_link_at_the_output_name`,
`one_byte_generation_has_no_temporary_artifacts`.

### keymake (21)

`reports_usage_without_arguments`, `reports_usage_with_extra_arguments`,
`rejects_non_decimal_sizes_before_prompting`, `rejects_zero_before_prompting`,
`rejects_too_large_sizes_before_prompting`,
`refuses_an_existing_output_before_prompting`,
`invalid_size_never_creates_an_output`,
`rejects_an_empty_size_argument_before_prompting`,
`accepts_an_explicit_plus_sign_before_existing_output_check`,
`rejects_exponent_notation_before_prompting`,
`rejects_hex_notation_before_prompting`,
`rejects_values_larger_than_u64_before_prompting`,
`rejects_unicode_digits_before_prompting`,
`rejects_embedded_ascii_whitespace_before_prompting`,
`invalid_size_preserves_unrelated_files`,
`invalid_size_leaves_no_temporary_artifacts`,
`validation_failure_emits_no_stdout`,
`refuses_an_existing_empty_output_before_prompting`,
`refuses_an_output_directory_before_prompting`,
`refuses_a_hard_link_output_before_prompting`,
`maximum_size_checks_existing_output_before_prompting`.

### key2txt (21)

`reports_usage_for_wrong_argument_counts`,
`converts_a_binary_key_to_documented_decimal_text`,
`converts_a_short_unicode_filename_without_panicking`,
`converts_every_possible_byte_value`, `converts_an_empty_file_to_an_empty_file`,
`streams_across_the_internal_buffer_boundary`,
`reports_the_source_and_fixed_output_names`,
`rejects_a_missing_input_without_output`,
`rejects_nonlocal_and_nonportable_input_names`,
`refuses_to_overwrite_the_fixed_output`,
`converts_a_single_zero_without_a_comma`,
`converts_representative_decimal_widths`,
`accepts_a_filename_beginning_with_a_hyphen`, `success_emits_no_stderr`,
`missing_input_failure_emits_no_stdout`,
`rejects_a_directory_input_without_output`,
`preserves_a_directory_at_the_output_name`,
`refuses_a_hard_link_at_the_output_name`,
`successful_conversion_preserves_unrelated_files`, `conversion_is_deterministic`,
`source_key_is_unchanged_after_conversion`.

### txt2key (21)

`reports_usage_for_wrong_argument_counts`,
`converts_documented_decimal_text_to_binary`,
`accepts_plain_lines_whitespace_commas_and_crlf`,
`accepts_a_final_line_without_a_newline`,
`converts_an_empty_file_to_an_empty_file`,
`rejects_malformed_values_without_leaving_output`,
`streams_large_decimal_input`, `reports_the_source_and_fixed_output_names`,
`rejects_a_missing_input_without_output`,
`rejects_nonlocal_and_nonportable_input_names`,
`refuses_to_overwrite_the_fixed_output`,
`malformed_data_after_a_written_chunk_leaves_no_output_or_temporary_file`,
`accepts_three_digit_zero_padded_values`,
`accepts_tabs_around_values_and_commas`, `rejects_a_blank_first_line`,
`rejects_a_whitespace_only_final_line`, `rejects_non_ascii_digits`,
`rejects_a_directory_input_without_output`,
`preserves_a_directory_at_the_output_name`,
`refuses_a_hard_link_at_the_output_name`, `success_emits_no_stderr`.

### otp (21)

`reports_usage_for_wrong_argument_counts`, `xors_every_input_byte_with_the_key`,
`running_twice_restores_the_original`,
`streams_across_the_internal_buffer_boundary`,
`accepts_a_key_longer_than_the_input`, `preserves_readonly_permissions`,
`accepts_separate_empty_input_and_key_files`,
`rejects_a_short_key_without_changing_input`,
`rejects_using_the_input_as_its_own_key`,
`rejects_a_hard_link_alias_of_the_input_as_key`, `rejects_missing_input`,
`rejects_missing_key_without_changing_input`,
`rejects_nonlocal_and_nonportable_names`, `reports_the_processed_filename`,
`xors_a_single_byte`, `an_all_zero_key_leaves_the_input_unchanged`,
`an_all_ones_key_inverts_every_bit`, `key_file_is_never_modified`,
`short_key_failure_leaves_no_temporary_artifacts`,
`missing_key_failure_emits_no_stdout`, `success_emits_no_stderr`.

## x4x CLI suite: 21 tests

`help_describes_commands_and_password_file`,
`missing_subcommand_is_a_usage_error`, `cli_round_trip_with_default_paths`,
`cli_wrong_password_reports_one_safe_error_and_leaves_no_output`,
`cli_refuses_to_overwrite_before_doing_crypto`,
`cli_rejects_an_empty_password_file`, `version_flag_reports_the_package_version`,
`test_is_not_misrepresented_as_an_application_subcommand`,
`missing_password_file_is_reported_without_creating_output`,
`malformed_ciphertext_is_rejected_without_output`,
`default_decrypt_path_never_replaces_the_original`,
`both_subcommands_have_complete_help`, `both_subcommands_require_an_input_path`,
`plaintext_password_command_line_option_is_intentionally_unsupported`,
`missing_input_file_reports_context_and_creates_nothing`,
`missing_output_directory_reports_context`,
`repeated_default_encryption_preserves_the_first_ciphertext`,
`double_dash_allows_a_filename_beginning_with_a_hyphen`,
`runtime_failures_use_exit_code_one_and_no_success_output`,
`command_line_usage_failures_use_exit_code_two`,
`output_option_requires_a_value`.

## x4x internal suite: 126 tests

### Default path rules (8)

`encrypted_default_appends_instead_of_replacing_extension`,
`decrypted_default_removes_x4x_extension`,
`decrypted_default_appends_dec_for_unknown_extension`,
`encrypted_default_appends_to_extensionless_name`,
`decrypted_default_handles_multiple_dots`,
`decrypted_extension_match_is_intentionally_case_sensitive`,
`extension_in_parent_directory_does_not_affect_file_name`,
`encrypting_an_already_encrypted_name_still_never_replaces_it`.

### Password bytes and files (15)

`removes_one_lf`, `removes_one_crlf`,
`does_not_trim_spaces_or_multiple_newlines`, `accepts_non_utf8_password_files`,
`rejects_empty_password`, `rejects_oversized_password_without_unbounded_read`,
`missing_password_file_has_context`,
`direct_validation_rejects_too_large_password`, `empty_file_is_rejected`,
`lone_carriage_return_is_password_data`,
`whitespace_only_nonempty_password_is_preserved`,
`exact_maximum_password_length_is_accepted`,
`crlf_only_is_rejected_after_normalization`,
`embedded_nuls_are_preserved_as_password_bytes`,
`only_one_of_two_crlf_endings_is_removed`.

### Container format (30)

`header_round_trip_is_exact`, `rejects_bad_magic`,
`distinguishes_future_version`, `rejects_unknown_cipher`, `rejects_unknown_kdf`,
`rejects_header_flags_and_reserved_bytes`,
`rejects_kdf_and_chunk_values_outside_every_bound`, `frame_round_trip`,
`rejects_oversized_frame`, `rejects_short_non_final_frame`,
`rejects_frame_flags_and_reserved_bytes`, `nonces_change_with_frame_index`,
`associated_data_binds_index_and_final_marker`,
`exact_parameter_bounds_are_accepted`,
`header_encoding_uses_documented_offsets_and_big_endian_values`,
`frame_encoding_is_canonical`, `maximum_frame_counter_has_a_distinct_nonce`,
`associated_data_binds_every_header_field`,
`production_defaults_are_locked_to_the_documented_values`,
`every_unsupported_frame_flag_combination_is_rejected`,
`any_nonzero_frame_reserved_byte_is_rejected`,
`representative_final_frame_lengths_are_all_valid`,
`every_representative_short_nonfinal_length_is_rejected`,
`nonce_layout_is_exact_for_representative_counters`,
`associated_data_layout_is_exact`,
`all_supported_header_fields_survive_serialization`,
`first_ten_thousand_frame_nonces_are_unique`,
`first_ten_thousand_associated_data_values_are_unique`,
`frame_parser_matches_its_invariants_for_many_generated_inputs`,
`each_parameter_validator_accepts_only_its_closed_interval`.

### Streaming crypto and output transactions (73)

`round_trips_empty_file`, `round_trips_single_byte`,
`round_trips_binary_data_including_every_byte_value`,
`round_trips_boundaries_around_every_chunk_transition`,
`wrong_password_never_creates_plaintext_output`,
`salt_and_nonce_make_repeated_encryptions_distinct`,
`encryption_does_not_modify_source`, `tampered_salt_is_detected`,
`tampered_nonce_prefix_is_detected`, `tampered_ciphertext_is_detected`,
`tampered_authentication_tag_is_detected`, `changing_final_marker_is_detected`,
`unknown_frame_flags_are_rejected`,
`oversized_frame_length_is_rejected_before_allocation`,
`hostile_memory_cost_is_rejected_before_kdf`,
`every_representative_truncation_is_rejected_without_output`,
`removing_the_final_frame_is_detected`,
`bytes_appended_after_final_frame_are_rejected`, `reordered_frames_are_detected`,
`duplicated_final_frame_is_rejected_as_trailing_data`,
`malformed_header_only_file_is_rejected`,
`existing_encryption_output_is_never_overwritten`,
`existing_decryption_output_is_never_overwritten`,
`input_and_output_same_path_is_rejected`,
`empty_and_oversized_passwords_are_rejected`,
`missing_input_and_output_directory_report_context`,
`failed_decryption_removes_private_temporary_file`,
`read_chunk_handles_short_and_interrupted_reads`,
`ciphertext_size_matches_the_canonical_frame_layout`,
`empty_ciphertext_contains_an_authenticated_final_frame`,
`valid_but_tampered_memory_cost_is_authenticated`,
`valid_but_tampered_iteration_count_is_authenticated`,
`valid_but_tampered_parallelism_is_authenticated`,
`valid_but_tampered_chunk_size_is_authenticated`,
`every_partial_frame_header_is_rejected`, `every_partial_final_tag_is_rejected`,
`late_chunk_corruption_cleans_partially_written_plaintext`,
`unicode_paths_round_trip`, `decryption_never_modifies_ciphertext`,
`normalized_same_path_is_rejected`,
`malformed_magic_creates_no_output_or_temporary_file`,
`many_deterministic_lengths_round_trip`,
`round_trip_crosses_one_thousand_frame_boundaries`,
`binary_password_with_nuls_and_non_utf8_bytes_round_trips`,
`maximum_length_password_round_trips`,
`subtly_different_passwords_all_fail_closed`,
`every_byte_of_an_empty_encrypted_file_is_integrity_checked`,
`frames_cannot_be_spliced_between_files`,
`header_from_another_file_cannot_be_substituted`,
`removing_a_middle_frame_is_detected`, `duplicating_a_nonfinal_frame_is_detected`,
`concatenating_two_valid_encrypted_files_is_rejected`,
`read_only_input_can_be_encrypted_without_modification`,
`simultaneous_encryptions_publish_exactly_one_complete_file`,
`simultaneous_decryptions_publish_exactly_one_complete_file`,
`hard_link_destination_is_never_overwritten`,
`existing_directory_destination_is_not_touched`,
`read_frame_header_distinguishes_clean_eof_from_partial_header`,
`frame_header_reader_retries_an_interrupted_first_read`,
`low_level_read_errors_keep_operation_and_path_context`,
`ensure_eof_retries_interruption_and_rejects_later_data`,
`read_exact_maps_only_unexpected_eof_to_format_error`,
`derived_key_matches_the_version_one_known_answer`,
`complete_version_one_frame_matches_known_answer`,
`corruption_in_each_frame_is_detected_without_output`,
`truncation_at_every_frame_boundary_is_detected`,
`shrinking_authenticated_final_length_is_detected`,
`expanding_final_length_without_data_is_reported_as_truncation`,
`wrong_password_and_ciphertext_damage_share_the_same_error`,
`successful_operations_leave_no_temporary_files`,
`failed_password_attempt_never_modifies_ciphertext`,
`password_validation_happens_before_any_filesystem_access`,
`completed_outputs_are_owner_only_on_unix` (Unix only).

## Shared x3x unit suite: 36 tests

- Algorithm metadata (3): `identifiers_round_trip_and_reject_unknown_values`,
  `every_app_name_and_key_filename_is_unique`,
  `modes_accept_only_the_documented_uppercase_operations`.
- Container format (5): `key_file_headers_round_trip_for_every_algorithm`,
  `password_header_records_and_parses_its_kdf`,
  `parser_rejects_every_structural_header_mismatch`,
  `chunk_math_covers_empty_exact_and_partial_records`,
  `record_nonce_and_aad_bind_position_length_and_finality`.
- Password crypto (12): the eight
  `aesp|chap|serp|thfp|ascp|rabbitp|aegis256p|aegis128lp_round_trips_and_rejects_wrong_password`
  tests, `production_password_kdf_round_trips` (ignored),
  `password_files_use_fresh_salts_and_authenticate_the_header`,
  `key_file_and_password_containers_cannot_be_mixed`, and
  `key_file_container_compatibility_vectors_are_stable`.
- KDF validation (4): `derivation_is_salt_and_algorithm_separated`,
  `production_parameters_are_deliberately_expensive`,
  `header_parameters_cannot_exceed_the_production_budget`,
  `empty_password_is_rejected`.
- Portable/transactional I/O (6):
  `rejects_characters_that_are_invalid_in_portable_filenames`,
  `accepts_short_unicode_names_without_panicking`,
  `rejects_all_windows_numbered_device_spellings`,
  `dropping_unfinished_output_removes_the_temporary_file`,
  `finish_refuses_a_destination_created_after_preflight`,
  `successful_finish_installs_only_the_requested_file`.
- Key tools (5): `salt_is_deterministic_and_size_separated`,
  `validates_full_size_range`, `keymake_is_deterministic_and_domain_separated`,
  `keymake_streams_exactly_across_its_buffer_boundary`,
  `keymake_rejects_empty_passwords_and_never_clobbers`.
- OTP transaction (1): `replacement_refuses_a_changed_input_path`.

## Cross-binary integration suite: 22 tests

- Key-text conversion (6):
  `converter_binaries_round_trip_and_emit_documented_format`,
  `converters_stream_across_internal_buffer_boundaries`,
  `txt2key_accepts_plain_lines_commas_spaces_and_crlf`,
  `txt2key_rejects_malformed_lines_without_creating_output`,
  `converters_refuse_to_overwrite_fixed_outputs`,
  `empty_key_round_trips_as_empty_files`.
- Password wiring (1):
  `every_password_binary_has_the_expected_standalone_command`.
- All-algorithm behavior (9): `every_algorithm_round_trips_multiple_chunks`,
  `empty_file_is_authenticated_and_round_trips`,
  `tampering_is_rejected_and_creates_no_output`, `wrong_key_is_rejected`,
  `existing_output_is_never_changed`, `fresh_nonces_make_encryptions_different`,
  `paths_and_active_key_input_are_refused`,
  `hard_link_alias_of_active_key_is_refused`,
  `case_alias_of_active_key_is_refused` (Windows only).
- Tools (6): `keygen_writes_exact_size_and_refuses_overwrite`,
  `otp_streams_and_is_its_own_inverse`,
  `short_otp_key_fails_before_input_changes`,
  `otp_refuses_to_use_the_input_as_its_key`,
  `otp_refuses_a_hard_link_alias_of_the_input`,
  `keymake_is_deterministic_and_not_a_repeated_short_block` (ignored).

## Commands

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
.\test-each.bat
.\test-deep-each.bat
```

Run the ignored production-cost tests explicitly:

```text
cargo test --locked --release --lib crypto::tests::production_password_kdf_round_trips -- --ignored --exact
cargo test --locked --test tools keymake_is_deterministic_and_not_a_repeated_short_block -- --ignored --exact
```
