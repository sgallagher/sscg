# AGENTS.md

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
- `CHECK_SSL(sslret, fn)` — checks that an OpenSSL call returned 1, extracts the OpenSSL error, sets `ret = EIO`, and jumps to `done`.

**Talloc leak detection:** Tests that exercise full certificate or key creation should record the talloc block count before and after the work and fail with `ENOMEM` if the count grows:
```c
initial_blocks = talloc_total_blocks(NULL);
// ... test body ...
final_blocks = talloc_total_blocks(NULL);
if (final_blocks > initial_blocks) { ret = ENOMEM; goto done; }
```

**Table-driven tests:** When checking many input/expected-output pairs, define an array of structs and a small `run_*_cases()` helper that loops over them. See `test/dns_name_validation_test.c` for an example.

**No mocking:** Tests call real OpenSSL APIs directly; there is no mock layer. Design new functions so they can be exercised at the library boundary without stubs.

**Shell tests:**
- Use `trap cleanup EXIT` with `rm -Rf "$TMPDIR"` for teardown.
- Check exit codes with `if [ $exit_code -ne 0 ]` and inspect output files with `openssl` commands.
- Source the shared helper `test_expected_failure.sh` to assert that a command exits with a specific non-zero code.
- Set `LC_ALL=C` (done automatically by the Meson `environment()` object) so output parsing is locale-independent.

**Meson registration:** Add each new C test executable to `meson.build` as:
```meson
executable('my_test', 'test/my_test.c', link_with: sscg_lib, ...)
test('my_test', my_test_exe, timeout: 120)
```
Set `timeout` explicitly for tests that involve crypto operations. Use `env: test_env` for shell tests so they receive `MESON_SOURCE_ROOT` and `MESON_BUILD_ROOT`. Gate ML-DSA or other feature-dependent tests with the appropriate `has_*` boolean.

## Code Style
For code style details, see CONTRIBUTING.md.

