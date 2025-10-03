# SSCG Development Container (Fedora 43) - Podman

This devcontainer provides a complete development environment for the SSCG project using Fedora 43, optimized for Podman.

## Features

- **Base Image**: Fedora 43
- **Container Runtime**: Optimized for Podman (also works with Docker)
- **Build System**: Meson + Ninja
- **Compiler**: GCC with C17 support
- **Dependencies**: All required libraries (OpenSSL 3.0+, talloc, popt, path_utils)
- **Development Tools**: 
  - clang-format for code formatting
  - GDB and Valgrind for debugging
  - Git, vim, nano for development
  - VS Code extensions for C/C++ development
- **Security**: SELinux-compatible with proper labeling

## Usage

### Prerequisites

- **Podman** (recommended) or Docker
- VS Code with the "Dev Containers" extension
- For Podman users: Ensure `podman-docker` package is installed for Docker compatibility

### Getting Started

#### Option 1: VS Code Dev Containers (Recommended)

1. **Install Podman and podman-docker**:
   ```bash
   # Fedora/RHEL/CentOS
   sudo dnf install podman podman-docker
   
   # Ubuntu/Debian
   sudo apt install podman podman-docker
   ```

2. **Configure VS Code to use Podman**:
   - Open VS Code settings (Ctrl+,)
   - Search for "dev containers docker path"
   - Set "Dev > Containers: Docker Path" to `podman`

3. **Open the project**:
   - Open the project in VS Code
   - When prompted, click "Reopen in Container" or use Command Palette:
     - `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS)
     - Type "Dev Containers: Reopen in Container"
   - Wait for the container to build and start

#### Option 2: Manual Podman Usage

1. **Build the container**:
   ```bash
   cd .devcontainer
   podman build -t sscg-dev .
   ```

2. **Run the container**:
   ```bash
   podman run -it --rm \
     --userns=keep-id \
     --security-opt label=disable \
     -v $(pwd)/..:/workspace:Z \
     -v ~/.gitconfig:/home/developer/.gitconfig:ro,Z \
     -v ~/.ssh:/home/developer/.ssh:ro,Z \
     sscg-dev
   ```

#### Option 3: Using Podman Compose

1. **Start the development environment**:
   ```bash
   cd .devcontainer
   podman-compose up -d
   podman-compose exec sscg-dev bash
   ```

### Building the Project

Once inside the container:

```bash
# Configure the build
meson setup build

# Build the project
ninja -C build

# Run tests
ninja -C build test

# Run specific tests (optional)
meson test -C build --verbose

# Install (optional)
sudo ninja -C build install
```

### Development Workflow

- **Code Formatting**: Files are automatically formatted on save using clang-format
- **IntelliSense**: Full C/C++ language support with proper include paths
- **Debugging**: GDB integration available through VS Code
- **Git**: Your local git configuration and SSH keys are mounted for convenience

### Container Details

- **User**: `developer` (non-root with sudo access, UID/GID 1000)
- **Working Directory**: `/workspace` (mounted from your local project)
- **Package Manager**: DNF (Fedora's package manager)
- **SELinux**: Compatible with proper volume labeling (`:Z` flag)
- **User Namespace**: Uses `--userns=keep-id` for proper file ownership

### Customization

You can modify the devcontainer configuration by editing:
- `.devcontainer/Dockerfile` - Add additional packages or tools
- `.devcontainer/devcontainer.json` - Modify VS Code settings or extensions

### Troubleshooting

If you encounter issues:

1. **Rebuild Container**: Use Command Palette → "Dev Containers: Rebuild Container"
2. **Check Dependencies**: Ensure all required packages are installed in the Dockerfile
3. **Permissions**: The container runs as a non-root user with sudo access
4. **SELinux Issues**: Ensure volumes are mounted with `:Z` flag for proper labeling
5. **Podman Socket**: If VS Code can't find Podman, ensure podman-docker is installed:
   ```bash
   sudo dnf install podman-docker
   sudo systemctl enable --now podman.socket
   ```
6. **User Namespace**: If file ownership issues occur, verify `--userns=keep-id` is working

### Testing the Setup

To verify everything works correctly:

```bash
# Check compiler
gcc --version

# Check meson
meson --version

# Check dependencies
pkg-config --exists openssl talloc popt path_utils && echo "All dependencies found"

# Build and test
meson setup test_build
ninja -C test_build
ninja -C test_build test
```


