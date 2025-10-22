# Contributing to SSCG

Thank you for your interest in contributing to SSCG (Simple Signed Certificate Generator)! This document provides guidelines for contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [License and Copyright](#license-and-copyright)
- [Security Issues](#security-issues)
- [Community Guidelines](#community-guidelines)

## Getting Started

### Prerequisites

Before contributing, ensure you have the necessary tools installed:

**Fedora/RHEL/CentOS:**
```bash
sudo dnf install meson ninja-build gcc pkgconf-pkg-config \
                 openssl-devel libtalloc-devel popt-devel \
                 libpath_utils-devel gettext-devel help2man \
                 clang-format git
```

**Ubuntu/Debian:**
```bash
sudo apt-get install meson ninja-build gcc pkg-config libssl-dev \
                           libtalloc-dev libpopt-dev libpath-utils-dev \
                           gettext help2man clang-format git
```

### Setting Up Your Development Environment

1. **Fork and clone the repository:**
Fork the Github repository and then run:

   ```bash
   git clone https://github.com/your-username/sscg.git
   cd sscg
   git remote add upstream https://github.com/sgallagher/sscg.git
   ```

2. **Build the project:**
   ```bash
   meson setup build
   meson compile -C build
   ```

3. **Run tests to ensure everything works:**
   ```bash
   meson test -C build
   ```

### Development Container (Optional)

For a consistent development environment, you can use the provided devcontainer:

1. **Install Podman (recommended) or Docker**
2. **Install VS Code with Dev Containers extension**
3. **Open project in VS Code and select "Reopen in Container"**

See [.devcontainer/README.md](.devcontainer/README.md) for detailed instructions.

## Development Environment

### Project Structure

- `src/` - Main source code
  - `sscg.c` - Main application entry point
  - `arguments.c` - Command-line argument parsing
  - `authority.c` - Certificate Authority management
  - `cert.c` - Certificate creation and signing
  - `x509.c` - X.509 certificate operations
  - `key.c` - Key generation and management
  - `io_utils.c` - File I/O operations
  - `dhparams.c` - Diffie-Hellman parameter generation
- `include/` - Header files
- `test/` - Unit tests and integration tests
- `po/` - Internationalization files

### Memory Management

SSCG uses [talloc](https://talloc.samba.org/) for all dynamic memory allocation:

- **Always use talloc functions** (`talloc_*`) instead of `malloc()`/`free()`
- **Use `TALLOC_CTX`** for hierarchical memory management
- **Follow parent-child relationships** for automatic cleanup
- **Enable leak detection** in tests with `talloc_enable_leak_report_full()`

The most common pattern is to always create a `tmp_ctx` from NULL in each
function that allocates memory and always call `talloc_free(tmp_ctx)`
before returning. If the function needs to return some allocated objects,
use `talloc_steal()` to reassign that memory to a `mem_ctx` passed into the
function just before the function returns.

The purpose of using NULL for the `tmp_ctx` parent is so that leaks will be
detectable if the function exits without calling `talloc_free(tmp_ctx);`. If
it's allocated onto the `mem_ctx` from the beginning, the leak will be
invisible.

Example:
```c
int
my_func(TALLOC_CTX *mem_ctx, struct custom_data **data)
{
  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  struct custom_data *tmp_data = talloc_zero (tmp_ctx, struct custom_data);

  // do stuff here, if errors occur, set `ret` to non-zero and `goto done`
  // CHECK_OK() will call `goto done` on nonzero
  ret = func_that_might_fail()
  CHECK_OK (ret);

  *data = talloc_steal(mem_ctx, tmp_data);
  ret = EOK;

done:
  talloc_free (tmp_ctx);
  return ret;
}
```

When allocating memory, use an appropriate hierarchy. A talloc_free() will
recursively descend and free the memory from the bottom-up, so you want to
have struct members use the struct itself as the parent, array entries use
the array as the parent, etc.

### Error Handling

- **Use `CHECK_OK()` macro** for error propagation
- **Return appropriate errno values** (EOK for success)
- **Clean up resources** on error paths
- **Provide meaningful error messages** to users

Example:
```c
ret = some_function(ctx, &result);
CHECK_OK(ret);  // Automatically handles error propagation
```

## Code Standards

### Code Formatting

SSCG uses `clang-format` with a WebKit-based style:

```bash
# Format all source files
clang-format -i src/*.c include/*.h test/*.c

# Or format specific files
clang-format -i path/to/file.c
```

**Key formatting rules:**
- **Function return types** on separate lines
- **No short functions** on single lines
- **Align function parameters** when wrapping
- **Use spaces, not tabs**
- **80-character line limit** where reasonable

### Coding Conventions

- **Use descriptive variable names**
- **Prefix functions** with `sscg_` for public APIs
- **Use `static`** for internal functions
- **Include proper error checking** for all operations
- **Document complex algorithms** with comments
- **Follow existing patterns** in the codebase

### Header Files

- **Include guards** using `#ifndef`/`#define`/`#endif`
- **Forward declarations** to minimize dependencies
- **Proper copyright headers** (see License section)

## Testing

### Test Structure

SSCG uses a custom testing framework with the following patterns:

- **Unit tests** for individual functions (`test/*_test.c`)
- **Integration tests** for end-to-end functionality (`test/test_*.sh`)
- **Memory leak detection** using talloc reporting
- **Multiple test cases** for different parameters

### Writing Tests

**Unit Test Example:**
```c
int main(int argc, char **argv)
{
    int ret;
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    
    // Enable memory leak detection
    talloc_enable_leak_report_full();
    
    printf("=== Test Description ===\n");
    
    // Test case 1
    printf("Testing basic functionality. ");
    ret = your_function(tmp_ctx, &result);
    if (ret != EOK) {
        printf("FAILED.\n");
        goto done;
    }
    printf("SUCCESS.\n");
    
    // Verify results
    printf("Verifying results. ");
    if (result != expected) {
        printf("FAILED.\n");
        ret = EINVAL;
        goto done;
    }
    printf("SUCCESS.\n");
    
done:
    talloc_free(tmp_ctx);
    return ret;
}
```

### Running Tests

```bash
# Run all tests
meson test -C build

# Run specific test
meson test -C build test_name

# Run with verbose output
meson test -C build --verbose

# Run slow tests (DH parameter generation)
meson setup build -Drun_slow_tests=true
meson test -C build
```

### Test Categories

1. **Fast tests** (< 30 seconds): Basic functionality, key generation, certificate creation
2. **Slow tests** (> 30 seconds): DH parameter generation, large key sizes
3. **Integration tests**: Full certificate chain creation, file I/O operations

## Submitting Changes

### Before Submitting

1. **Ensure all tests pass:**
   ```bash
   meson test -C build
   ```

2. **Format your code:**
   ```bash
   clang-format -i $(find . -name "*.[ch]")
   ```

3. **Check for memory leaks:**
   ```bash
   SSCG_TALLOC_REPORT=true ./build/sscg
   ```

4. **Test on multiple platforms** if possible (Fedora, Ubuntu, etc.)

5. **Update translations** if you added user-facing strings:
   ```bash
   meson compile -C build sscg-pot
   meson compile -C build sscg-update-po
   ```

### Commit Guidelines

**Commit Message Format:**
```
Short summary (50 characters or less)

Detailed explanation of the changes, including:
- What was changed and why
- Any breaking changes
- References to issues or discussions

Signed-off-by: Your Name <your.email@example.com>
```

**Example:**
```
Add support for ECDSA P-384 curve

- Implement P-384 curve support in key generation
- Add curve validation in arguments parsing  
- Update tests to cover P-384 functionality
- Add documentation for new --ec-curve option

Fixes: #123
Signed-off-by: Jane Developer <jane@example.com>
```

### Pull Request Process

1. **Create a feature branch:**
   ```bash
   git checkout -b your-feature-name
   ```

2. **Make your changes** following the guidelines above

3. **Push to your fork:**
   ```bash
   git push origin your-feature-name
   ```

4. **Create a pull request** with:
   - Clear description of changes
   - Rationale for the change
   - Test results
   - Any breaking changes noted
   - References to related issues

5. **Respond to review feedback** promptly

6. **Ensure CI passes** on all platforms

## License and Copyright

### License

SSCG is licensed under **GPL-3.0-or-later WITH OpenSSL-exception**. All contributions must be compatible with this license.

### Copyright Headers

All source files must include the following copyright header:

```c
/*
 * SPDX-License-Identifier: GPL-3.0-or-later WITH cryptsetup-OpenSSL-exception
 * This file is part of sscg.
 *
 * sscg is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * sscg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with sscg.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * Copyright XXXX by Your Name <yourname@yoursite.com>
 */
```

### Developer Certificate of Origin

By contributing to this project, you certify that:

1. The contribution was created in whole or in part by you and you have the right to submit it under the open source license indicated in the file
2. The contribution is based upon previous work that, to the best of your knowledge, is covered under an appropriate open source license
3. You understand and agree that this project and the contribution are public

Add a `Signed-off-by` line to your commits:
```bash
git commit -s -m "Your commit message"
```

## Security Issues

**Do not file public issues for security vulnerabilities.**

For security-related issues, please contact the maintainer directly:
- **Email:** [sgallagh@redhat.com](mailto:sgallagh@redhat.com)
- **Subject:** [SECURITY] SSCG Security Issue

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Community Guidelines

### Bug Reports

When reporting bugs, include:
- **SSCG version:** `sscg --version`
- **Operating system** and version
- **OpenSSL version:** `openssl version`
- **Complete command line** used
- **Expected vs. actual behavior**
- **Error messages** (if any)
- **Steps to reproduce**

### Feature Requests

For feature requests:
- **Describe the use case** clearly
- **Explain why** the feature would be valuable
- **Provide examples** of how it would be used
- **Consider backwards compatibility**

### Communication

- **Be respectful** and professional
- **Stay on topic** in discussions
- **Provide constructive feedback**
- **Help others** when possible
- **Follow the code of conduct**

## Development Tips

### Debugging

**GDB debugging:**
```bash
gdb --args ./build/sscg --debug [options]
```

**Valgrind for memory checking:**
```bash
valgrind --leak-check=full --show-leak-kinds=all ./build/sscg [options]
```

**Talloc memory reporting:**
```bash
SSCG_TALLOC_REPORT=true ./build/sscg [options]
```

### Build Variants

**Debug build:**
```bash
meson setup build --buildtype=debug
```

**Release build:**
```bash
meson setup build --buildtype=release
```

**With additional warnings:**
```bash
meson setup build -Dwarning_level=3
```

### Useful Resources

- [Meson Build System](https://mesonbuild.com/)
- [Talloc Documentation](https://talloc.samba.org/talloc/doc/html/index.html)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [GNU Coding Standards](https://www.gnu.org/prep/standards/)

---

Thank you for contributing to SSCG! Your contributions help make secure certificate generation accessible to everyone.
