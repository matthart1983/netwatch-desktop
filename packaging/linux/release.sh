#!/usr/bin/env bash
# Builds, checks and packages the Linux release. release.yml runs one
# subcommand per step, in this order. To make the same files locally, run
# them in an ubuntu:22.04 container with the build tools release.yml
# installs.
#
#   tag vX.Y.Z  fail unless the tag is Cargo.toml's version
#   libpcap     build the static libpcap the binary links in
#   test        cargo test against that libpcap
#   build       cargo build --release, with build paths remapped
#   check       glibc floor, libpcap linked in, no build paths left
#   package     dist/: the .deb, the .rpm, and a tarball of the .deb's files
#
# Then, as root in a clean container with the repo as the working directory
# and cap_net_raw in the bounding set (podman leaves it out by default, so
# pass --cap-add NET_RAW there):
#
#   verify-deb  debian:bookworm. Install, check the grant, draw one frame
#               under Xvfb with only the package's Depends, remove.
#   verify-rpm  fedora. The same, with rpm -V as well.
set -euo pipefail

cd "$(dirname "$0")/../.."

# libpcap is linked in statically. Ubuntu names its library libpcap.so.0.8
# and Fedora libpcap.so.1, so one binary linked against either wouldn't run
# on the other. The hash is of the tarball whose signature checked out
# against the Tcpdump Group's key E089DEF1D9C15D0D on 2026-10-04.
LIBPCAP_VERSION=1.10.7
LIBPCAP_SHA256=0b394ac90dbc0a9838ff97468e05c9c9a3e873dec2514cd58db65d859d296e31

# The oldest glibc the binary may need: Ubuntu 22.04's. The linker binds each
# libc symbol to the newest version the build machine's glibc has, so building
# on 22.04 keeps every symbol at 2.35 or older, and `check` confirms it.
GLIBC_FLOOR=2.35

TARGET=$(realpath -m "${CARGO_TARGET_DIR:-target}")
PCAP_PREFIX=$TARGET/libpcap
BIN=$TARGET/release/netwatch-desktop
ARCH=$(uname -m)
TARBALL=netwatch-desktop-linux-$ARCH

die() {
    echo "release.sh: $*" >&2
    exit 1
}

pcap_env() {
    [ -f "$PCAP_PREFIX/lib/libpcap.a" ] || die "no static libpcap; run release.sh libpcap first"
    export LIBPCAP_LIBDIR=$PCAP_PREFIX/lib LIBPCAP_VER=$LIBPCAP_VERSION
}

cmd_tag() {
    local version
    version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
    [ "${1:-}" = "v$version" ] || die "tag ${1:-<none>} isn't v$version, the version in Cargo.toml"
}

cmd_libpcap() {
    local work=$TARGET/libpcap-build
    local src=$work/libpcap-$LIBPCAP_VERSION
    rm -rf "$work" "$PCAP_PREFIX"
    mkdir -p "$work"
    curl -sSfL -o "$work/libpcap.tar.gz" \
        "https://www.tcpdump.org/release/libpcap-$LIBPCAP_VERSION.tar.gz"
    echo "$LIBPCAP_SHA256  $work/libpcap.tar.gz" | sha256sum -c -
    tar -xzf "$work/libpcap.tar.gz" -C "$work"
    # The packages ship this copy of libpcap's licence, since the binary
    # carries libpcap's code.
    cmp "$src/LICENSE" packaging/linux/LICENSE-libpcap ||
        die "packaging/linux/LICENSE-libpcap differs from libpcap $LIBPCAP_VERSION's LICENSE"
    # AF_PACKET capture only: none of the optional capture sources, so the
    # static library pulls in no other libraries.
    (
        cd "$src"
        CFLAGS="-O2 -fPIC" ./configure --prefix="$PCAP_PREFIX" \
            --with-pcap=linux --disable-shared --disable-dbus \
            --disable-bluetooth --disable-rdma --disable-usb --without-libnl
        make -j"$(nproc)"
        make install
    )
}

cmd_test() {
    pcap_env
    cargo test --locked
}

cmd_build() {
    pcap_env
    # Panic messages carry the source path of the crate that panicked, and
    # for dependencies that's an absolute path into the cargo home. The last
    # matching prefix wins, so the narrower ones come last.
    local cargo_home=${CARGO_HOME:-$HOME/.cargo}
    export RUSTFLAGS="--remap-path-prefix=$HOME=/home --remap-path-prefix=$PWD=/src --remap-path-prefix=$cargo_home=/cargo"
    cargo build --release --locked
}

cmd_check() {
    [ -x "$BIN" ] || die "no $BIN; run release.sh build first"

    local newest
    newest=$(objdump -T "$BIN" | grep -o 'GLIBC_[0-9][0-9.]*' | cut -d_ -f2 | sort -uV | tail -n 1)
    echo "newest glibc symbol version: $newest (floor $GLIBC_FLOOR)"
    [ "$(printf '%s\n%s\n' "$newest" "$GLIBC_FLOOR" | sort -V | tail -n 1)" = "$GLIBC_FLOOR" ] ||
        die "the binary needs glibc $newest, newer than $GLIBC_FLOOR"

    # No `producer | grep -q` here. grep -q exits at the first match, the
    # producer dies of SIGPIPE if it's still writing, and pipefail turns
    # that into a failed pipeline, so the `if` reads a match as no match.
    local needed
    needed=$(readelf -d "$BIN" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')
    echo "shared libraries:"
    sed 's/^/  /' <<<"$needed"
    if grep -q '^libpcap' <<<"$needed"; then
        die "the binary loads libpcap.so; it should have libpcap linked in"
    fi

    local path
    for path in "$HOME" "$PWD" "${CARGO_HOME:-$HOME/.cargo}"; do
        if grep -qaF -- "$path/" "$BIN"; then
            { strings -n 6 "$BIN" | grep -F -- "$path/" | head -n 5; } >&2 || true
            die "the binary still contains the build path $path"
        fi
    done
    echo "no build paths in the binary"
}

cmd_package() {
    [ -x "$BIN" ] || die "no $BIN; run release.sh build first"
    # The files inside the packages are dated from the commit, so the same
    # commit packages the same way. In CI a git failure stops the release,
    # since release.yml promises that date. Locally, with no git to ask,
    # such as in a container without the repo's .git, they get the time now.
    if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
        if ! SOURCE_DATE_EPOCH=$(git log -1 --format=%ct); then
            [ -z "${CI:-}" ] || die "git can't read the commit to date the packages from"
            SOURCE_DATE_EPOCH=$(date +%s)
            echo "release.sh: no git commit to date the files from, so they carry the build time" >&2
        fi
    fi
    export SOURCE_DATE_EPOCH
    echo "files dated $(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%d %H:%M:%S UTC')"
    rm -rf dist "$TARGET/stage"
    mkdir -p dist "$TARGET/stage"

    # The binary goes in as it is: the tarball, the .deb and the .rpm all
    # hold the bytes `check` passed.
    cargo deb --no-build --no-strip --output dist/
    cargo generate-rpm --output dist/

    # The tarball is the .deb's files under bin/ and share/, so copying both
    # into /usr/local installs the same thing the .deb does.
    local deb
    deb=$(ls dist/*.deb)
    dpkg-deb -x "$deb" "$TARGET/stage/root"
    mv "$TARGET/stage/root/usr" "$TARGET/stage/$TARBALL"
    tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
        -C "$TARGET/stage" -czf "dist/$TARBALL.tar.gz" "$TARBALL"

    ls -l dist
}

cmd_verify_deb() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # Depends only, so a missing runtime library shows up below.
    apt-get install -y -qq --no-install-recommends ./dist/netwatch-desktop_*.deb
    expect_grant
    netwatch-desktop --version
    test -f /usr/share/applications/netwatch-desktop.desktop
    test -f /usr/share/icons/hicolor/scalable/apps/netwatch-desktop.svg

    # winit and glutin load the display and GL libraries at run time, which
    # no package tool sees. Drawing a frame checks the Depends cover them.
    apt-get install -y -qq --no-install-recommends xvfb xauth
    timeout 120 xvfb-run -a netwatch-desktop --graph-preview --screenshot /tmp/frame.png
    test -s /tmp/frame.png

    apt-get remove -y -qq netwatch-desktop
    test ! -e /usr/bin/netwatch-desktop
}

cmd_verify_rpm() {
    # Requires only, as for the .deb.
    dnf install -y -q --setopt=install_weak_deps=False ./dist/netwatch-desktop-*.rpm
    expect_grant
    netwatch-desktop --version
    test -f /usr/share/applications/netwatch-desktop.desktop
    # Checks the files against the package, the capability included.
    rpm -V netwatch-desktop

    dnf install -y -q --setopt=install_weak_deps=False xorg-x11-server-Xvfb xvfb-run
    timeout 120 xvfb-run -a netwatch-desktop --graph-preview --screenshot /tmp/frame.png
    test -s /tmp/frame.png

    dnf remove -y -q netwatch-desktop
    test ! -e /usr/bin/netwatch-desktop
}

expect_grant() {
    local caps
    caps=$(getcap /usr/bin/netwatch-desktop)
    echo "getcap: $caps"
    [ "$caps" = "/usr/bin/netwatch-desktop cap_net_raw=ep" ] ||
        die "expected /usr/bin/netwatch-desktop to carry cap_net_raw=ep"
}

case "${1:-}" in
    tag) cmd_tag "${2:-}" ;;
    libpcap | test | build | check | package | verify-deb | verify-rpm) "cmd_${1//-/_}" ;;
    *) die "usage: release.sh tag vX.Y.Z | libpcap | test | build | check | package | verify-deb | verify-rpm" ;;
esac
