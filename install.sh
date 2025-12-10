#!/bin/bash
#
# llm-mux installer script
# Usage: curl -fsSL https://raw.githubusercontent.com/nghyane/llm-mux/main/install.sh | bash
#
# Options:
#   -v, --version VERSION   Install specific version (default: latest)
#   -d, --dir DIR           Install directory (default: /usr/local/bin or ~/.local/bin)
#   --no-verify             Skip checksum verification
#   --help                  Show help message

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Globals
REPO="nghyane/llm-mux"
BINARY_NAME="llm-mux"
VERSION=""
INSTALL_DIR=""
VERIFY_CHECKSUM=true
OS=""
ARCH=""

log() { echo -e "${GREEN}[llm-mux]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
info() { echo -e "${BLUE}[INFO]${NC} $*"; }

usage() {
    cat <<EOF
llm-mux installer

Usage: install.sh [options]

Options:
    -v, --version VERSION   Install specific version (default: latest)
    -d, --dir DIR           Install directory (default: /usr/local/bin or ~/.local/bin)
    --no-verify             Skip checksum verification
    -h, --help              Show this help message

Examples:
    # Install latest version
    curl -fsSL https://raw.githubusercontent.com/nghyane/llm-mux/main/install.sh | bash

    # Install specific version
    curl -fsSL https://raw.githubusercontent.com/nghyane/llm-mux/main/install.sh | bash -s -- -v v1.0.0

    # Install to custom directory
    curl -fsSL https://raw.githubusercontent.com/nghyane/llm-mux/main/install.sh | bash -s -- -d ~/.bin
EOF
    exit 0
}

detect_os() {
    case "$(uname -s)" in
        Darwin*) OS="darwin" ;;
        Linux*)  OS="linux" ;;
        MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
        *) error "Unsupported OS: $(uname -s)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) ARCH="amd64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        *) error "Unsupported architecture: $(uname -m)" ;;
    esac
}

detect_install_dir() {
    if [[ -n "$INSTALL_DIR" ]]; then
        return
    fi

    # Try /usr/local/bin first (requires sudo on most systems)
    if [[ -w "/usr/local/bin" ]]; then
        INSTALL_DIR="/usr/local/bin"
    elif [[ -d "$HOME/.local/bin" ]] || mkdir -p "$HOME/.local/bin" 2>/dev/null; then
        INSTALL_DIR="$HOME/.local/bin"
        warn "Installing to ~/.local/bin - make sure it's in your PATH"
    else
        error "Cannot find writable install directory. Use -d to specify one."
    fi
}

check_dependencies() {
    local missing=()

    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        missing+=("curl or wget")
    fi

    if [[ "$OS" == "windows" ]]; then
        if ! command -v unzip &>/dev/null; then
            missing+=("unzip")
        fi
    else
        if ! command -v tar &>/dev/null; then
            missing+=("tar")
        fi
    fi

    if [[ "$VERIFY_CHECKSUM" == "true" ]]; then
        if ! command -v sha256sum &>/dev/null && ! command -v shasum &>/dev/null; then
            warn "sha256sum/shasum not found, skipping checksum verification"
            VERIFY_CHECKSUM=false
        fi
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required dependencies: ${missing[*]}"
    fi
}

get_latest_version() {
    if [[ -n "$VERSION" ]]; then
        return
    fi

    log "Fetching latest version..."

    if command -v curl &>/dev/null; then
        VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        VERSION=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    fi

    if [[ -z "$VERSION" ]]; then
        error "Failed to fetch latest version"
    fi

    log "Latest version: $VERSION"
}

download_file() {
    local url="$1"
    local output="$2"

    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$output"
    else
        wget -q "$url" -O "$output"
    fi
}

verify_checksum() {
    local file="$1"
    local checksums_file="$2"
    local filename
    filename=$(basename "$file")

    if [[ "$VERIFY_CHECKSUM" != "true" ]]; then
        return 0
    fi

    log "Verifying checksum..."

    local expected
    expected=$(grep "$filename" "$checksums_file" | awk '{print $1}')

    if [[ -z "$expected" ]]; then
        warn "Checksum not found for $filename, skipping verification"
        return 0
    fi

    local actual
    if command -v sha256sum &>/dev/null; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    else
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    fi

    if [[ "$expected" != "$actual" ]]; then
        error "Checksum mismatch!\nExpected: $expected\nActual: $actual"
    fi

    log "Checksum verified ✓"
}

install_binary() {
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT

    # Determine file extension and archive name
    local ext="tar.gz"
    local version_num="${VERSION#v}"

    if [[ "$OS" == "windows" ]]; then
        ext="zip"
    fi

    local archive_name="llm-mux_${version_num}_${OS}_${ARCH}.${ext}"
    local download_url="https://github.com/${REPO}/releases/download/${VERSION}/${archive_name}"
    local checksums_url="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

    log "Downloading $archive_name..."
    download_file "$download_url" "$tmp_dir/$archive_name"

    # Download and verify checksum
    if [[ "$VERIFY_CHECKSUM" == "true" ]]; then
        download_file "$checksums_url" "$tmp_dir/checksums.txt"
        verify_checksum "$tmp_dir/$archive_name" "$tmp_dir/checksums.txt"
    fi

    # Extract archive
    log "Extracting..."
    cd "$tmp_dir"

    if [[ "$ext" == "zip" ]]; then
        unzip -q "$archive_name"
    else
        tar -xzf "$archive_name"
    fi

    # Find and install binary
    local binary_path
    binary_path=$(find . -name "$BINARY_NAME" -o -name "${BINARY_NAME}.exe" | head -1)

    if [[ -z "$binary_path" ]]; then
        error "Binary not found in archive"
    fi

    # Install
    log "Installing to $INSTALL_DIR..."

    if [[ -w "$INSTALL_DIR" ]]; then
        cp "$binary_path" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/$BINARY_NAME"*
    else
        info "Requesting sudo access to install to $INSTALL_DIR"
        sudo cp "$binary_path" "$INSTALL_DIR/"
        sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"*
    fi

    log "Installed successfully! ✓"
}

init_config() {
    local config_file="$HOME/.config/llm-mux/config.yaml"

    if [[ -f "$config_file" ]]; then
        info "Config already exists at $config_file"
        return
    fi

    log "Initializing config..."
    "$INSTALL_DIR/$BINARY_NAME" --init 2>/dev/null || true

    if [[ -f "$config_file" ]]; then
        log "Config created at $config_file"
    fi
}

print_success() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  llm-mux ${VERSION} installed successfully!                   ${GREEN}║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Quick start:"
    echo "  1. Login to a provider:"
    echo "     llm-mux --login              # Gemini"
    echo "     llm-mux --claude-login       # Claude"
    echo "     llm-mux --copilot-login      # GitHub Copilot"
    echo ""
    echo "  2. Start the server:"
    echo "     llm-mux"
    echo ""
    echo "  3. Use the API:"
    echo "     curl http://localhost:8318/v1/chat/completions \\"
    echo "       -H 'Content-Type: application/json' \\"
    echo "       -d '{\"model\": \"gemini-2.5-flash\", \"messages\": [{\"role\": \"user\", \"content\": \"Hello\"}]}'"
    echo ""

    # Check if install dir is in PATH
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        warn "$INSTALL_DIR is not in your PATH"
        echo ""
        echo "Add it to your PATH by running:"
        echo "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.bashrc"
        echo "  source ~/.bashrc"
    fi
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            -d|--dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --no-verify)
                VERIFY_CHECKSUM=false
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done

    echo ""
    log "llm-mux installer"
    echo ""

    detect_os
    detect_arch
    info "Detected: $OS/$ARCH"

    check_dependencies
    detect_install_dir
    get_latest_version
    install_binary
    init_config
    print_success
}

main "$@"
