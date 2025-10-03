FROM registry.fedoraproject.org/fedora:43

# Install build dependencies and development tools
RUN dnf update -y && \
    dnf install -y \
        # Build system
        meson \
        ninja-build \
        gcc \
        pkgconf-pkg-config \
        # Core dependencies
        openssl-devel \
        libtalloc-devel \
        popt-devel \
        libpath_utils-devel \
        # Internationalization
        gettext-devel \
        # Documentation
        help2man \
        # Code formatting and development tools
        clang-format \
        clang-tools-extra \
        # Development utilities
        git \
        vim \
        nano \
        gdb \
        valgrind \
        strace \
        # Additional useful tools
        which \
        file \
        diffutils \
        findutils \
        procps-ng \
        shadow-utils \
        sudo \
        # OpenSSL command line tools for testing
        openssl \
    && dnf clean all

# Create a non-root user for development
# Use a fixed UID/GID that works well with Podman's user namespace mapping
ARG USER_UID=1000
ARG USER_GID=1000

RUN groupadd -g ${USER_GID} developer && \
    useradd -u ${USER_UID} -g ${USER_GID} -m -s /bin/bash -G wheel developer && \
    echo "developer ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    # Ensure the developer user owns their home directory
    chown -R developer:developer /home/developer

# Set the working directory
WORKDIR /workspace

# Ensure workspace directory exists and has proper permissions
RUN mkdir -p /workspace && chown developer:developer /workspace

# Switch to the developer user
USER developer

# Set up some useful aliases and environment
RUN echo 'alias ll="ls -la"' >> ~/.bashrc && \
    echo 'alias la="ls -A"' >> ~/.bashrc && \
    echo 'alias l="ls -CF"' >> ~/.bashrc && \
    echo 'export EDITOR=vim' >> ~/.bashrc

# Default command
CMD ["/bin/bash"]


