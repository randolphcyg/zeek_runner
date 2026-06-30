#!/bin/bash
set -e

PLATFORM=""
TAG_SUFFIX=""
VERSION="${VERSION:-}"
APT_MIRROR="${APT_MIRROR:-}"
SAVE_IMAGE=1
CLEAN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "  (no options)           Build for native host architecture"
      echo "  --ubuntu                Build linux/amd64 image for Ubuntu 24.04 x86_64"
      echo "  --ubuntu-amd64          Same as --ubuntu"
      echo "  --ubuntu-arm64          Build linux/arm64 image for Ubuntu 24.04 ARM64"
      echo "  --platform PLATFORM     Cross-build for custom platform"
      echo "  --version VERSION       Set version (default: 5.0)"
      echo "  --apt-mirror URL        Override Ubuntu apt mirror"
      echo "  --no-save               Build image but do not save tar.gz"
      echo ""
      echo "Examples:"
      echo "  $0                              Build Docker for native arch"
      echo "  $0 --ubuntu                     Build Docker for Ubuntu 24.04 x86_64"
      echo "  $0 --ubuntu-arm64 --version 5.0 Build Docker for Ubuntu ARM64"
      echo "  $0 --ubuntu --no-save           Build without saving tar.gz"
      exit 0
      ;;
    --version)
      VERSION="$2"; shift 2 ;;
    --ubuntu|--ubuntu-amd64)
      PLATFORM="linux/amd64"; TAG_SUFFIX="-amd64"; shift ;;
    --ubuntu-arm64)
      PLATFORM="linux/arm64"; TAG_SUFFIX="-arm64"; shift ;;
    --platform)
      PLATFORM="$2"
      ARCH_TAG=$(echo "$2" | sed 's|linux/||')
      TAG_SUFFIX="-$ARCH_TAG"; shift 2 ;;
    --apt-mirror)
      APT_MIRROR="$2"; shift 2 ;;
    --no-save)
      SAVE_IMAGE=0; shift ;;
    -c|--clean)
      CLEAN=true; shift ;;
    *)
      echo "Unknown option: $1"; exit 1 ;;
  esac
done

GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DEFAULT_VERSION="5.0"

if [ "$CLEAN" == true ]; then
  echo "Cleaning build artifacts..."
  rm -f zeek_runner*.tar.gz
  echo "Clean complete!"
  exit 0
fi

if [ -z "$VERSION" ] && [ -t 0 ]; then
  read -p "Enter version (default: $DEFAULT_VERSION): " VERSION
fi
VERSION=${VERSION:-$DEFAULT_VERSION}

echo "========================================"
echo "  Zeek Runner Build"
echo "========================================"
echo "Version:    $VERSION"
echo "Git Commit: $GIT_COMMIT"
echo "Build Time: $BUILD_TIME"
if [ -n "$PLATFORM" ]; then
  echo "Platform:   $PLATFORM (cross-build via QEMU)"
else
  echo "Platform:   native ($(uname -m))"
fi
if [ -n "$APT_MIRROR" ]; then
  echo "Apt Mirror: $APT_MIRROR"
fi
echo "========================================"

echo ""
echo "Building Docker image..."
DOCKER_BUILD_CMD="docker build"
IMAGE_NAME="zeek_runner"
IMAGE_TAGS=(-t "${IMAGE_NAME}:${VERSION}")

if [ -n "$PLATFORM" ]; then
  DOCKER_BUILD_CMD="$DOCKER_BUILD_CMD --platform $PLATFORM"
else
  IMAGE_TAGS+=(-t "${IMAGE_NAME}:latest")
fi

APT_MIRROR_ARG=()
if [ -n "$APT_MIRROR" ]; then
  APT_MIRROR_ARG=(--build-arg "APT_MIRROR=$APT_MIRROR")
fi

$DOCKER_BUILD_CMD \
  --build-arg VERSION="$VERSION" \
  --build-arg BUILD_TIME="$BUILD_TIME" \
  --build-arg GIT_COMMIT="$GIT_COMMIT" \
  "${APT_MIRROR_ARG[@]}" \
  "${IMAGE_TAGS[@]}" \
  -f Dockerfile \
  .

TARBALL=""
if [ "$SAVE_IMAGE" -eq 1 ]; then
  echo ""
  echo "Saving image to tarball..."
  TARBALL="zeek_runner-${VERSION}${TAG_SUFFIX}.tar.gz"
  docker save "${IMAGE_NAME}:${VERSION}" | gzip > "$TARBALL"
fi

echo ""
echo "========================================"
echo "Build complete!"
echo "Image tags:"
echo "  ${IMAGE_NAME}:${VERSION}"
if [ -n "$TARBALL" ]; then
  echo "Image file: $TARBALL"
  if [ -n "$PLATFORM" ]; then
    echo "Deploy: scp $TARBALL user@ubuntu-server: && docker load < $TARBALL"
  fi
fi
echo "========================================"
