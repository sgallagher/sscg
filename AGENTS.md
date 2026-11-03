# AGENTS.md

## Building
Install the prerequisites (Meson, Ninja, a C compiler, and the OpenSSL >= 3.0, talloc, and popt development packages), then configure and build with `meson setup build` followed by `meson compile -C build`. See the "Getting Started" section of CONTRIBUTING.md for per-distribution package lists.

## Testing
- Always run `meson test` before committing.
- All new functions must have a corresponding unit test.
- All new features (especially command-line arguments) must have an end-to-end integration test.

### Test Conventions

**Framework:** There is no third-party test framework. C tests are standalone programs with a plain `int main()`. Return `0` (i.e., `EOK`) for success, a POSIX `errno` value (e.g., `EINVAL`, `ENOMEM`, `EIO`) for failure, or `77` to signal a skipped test.

**File naming and location:**
- C unit/integration tests: `test/<subject>_test.c`, compiled to a separate executable.
- Shell end-to-end tests: `test/test_<scenario>.sh`, invoked against the built `sscg` binary.

**Structure of a C test:**
Each C test file has one `main()`. Multiple logical checks run sequentially. The canonical pattern for each check is:
```c
printf("Testing sscg_foo(). ");
ret = sscg_foo(tmp_ctx, &out);
if (ret != EOK) { printf("FAILED.\n"); goto done; }
printf("SUCCESS.\n");
```

**Setup and teardown:**
- Allocate a top-level talloc context at the start: `TALLOC_CTX *tmp_ctx = talloc_new(NULL);`
- Every error path jumps to a `done:` label that frees the context and returns `ret`:
```c
done:
  if (ret != EOK) fprintf(stderr, "FAILURE: %s\n", strerror(ret));
  talloc_free(tmp_ctx);
  return ret;
```

**Assertions:** Use the project macros defined in `include/sscg.h`; do not call `assert()`:
- `CHECK_MEM(ptr)` — jumps to `done` with `ENOMEM` if `ptr` is NULL.
- `CHECK_OK(ret)` — jumps to `done` if `ret != EOK`.
- `CHECK_SSL(sslret, fn)` — checks that an OpenSSL call returned 1, extracts the OpenSSL error, sets `ret = EIO` (or `ret = EINVAL` when the error is a passphrase-length UI error, `UI_R_RESULT_TOO_LARGE` or `UI_R_RESULT_TOO_SMALL`), and jumps to `done`.

**Talloc leak detection:** Tests that exercise full certificate or key creation should record the talloc block count at the start and compare it again after the `done:` label, once `tmp_ctx` has been freed. Set `ret = ENOMEM` if the count grew; do not `goto done` from here, since this code already runs after the label:
```c
initial_blocks = talloc_total_blocks(NULL);
TALLOC_CTX *tmp_ctx = talloc_new(NULL);
// ... test body ...

done:
  talloc_free(tmp_ctx);
  final_blocks = talloc_total_blocks(NULL);
  if (final_blocks > initial_blocks) {
    talloc_report_full(NULL, stderr);
    ret = ENOMEM;
  }
  return ret;
```
See `test/create_cert_test.c` or `test/init_bignum_test.c` for complete examples.

**Table-driven tests:** When checking many input/expected-output pairs, define an array of structs and a small `run_*_cases()` helper that loops over them. See `test/dns_name_validation_test.c` for an example.

**No mocking:** Tests call real OpenSSL APIs directly; there is no mock layer. Design new functions so they can be exercised at the library boundary without stubs.

**Shell tests:**
- Use `trap cleanup EXIT` with `rm -Rf "$TMPDIR"` for teardown.
- Check exit codes with `if [ $exit_code -ne 0 ]` and inspect output files with `openssl` commands.
- To assert that a command exits with a specific non-zero code, do not source `test/test_expected_failure.sh`. It is a standalone wrapper: register it in `meson.build` as the test program (via the existing `test_expected_failure = find_program(...)`) and pass the expected exit code followed by the command and its arguments, e.g. `test('name', test_expected_failure, args: ['22', some_test.full_path(), '--flag'], env: test_env)`.
- Set `LC_ALL=C` (done automatically by the Meson `environment()` object) so output parsing is locale-independent.

**Meson registration:** Add each new C test executable to `meson.build` as:
```meson
executable('my_test', 'test/my_test.c', link_with: sscg_lib, ...)
test('my_test', my_test_exe, timeout: 120)
```
Set `timeout` explicitly for tests that involve crypto operations. Use `env: test_env` for shell tests so they receive `MESON_SOURCE_ROOT` and `MESON_BUILD_ROOT`. Gate ML-DSA or other feature-dependent tests with the appropriate `has_*` boolean.

## Code Style
For code style details, see CONTRIBUTING.md.

