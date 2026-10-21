#!/bin/bash
# Download the kernels of kernels.txt and unpack them, without root, into
# DIR/<name>/root/ (boot image and modules). Kernels already unpacked are
# skipped, so the script can be run again after a failed download.
#
# usage: fetch-kernels.sh DIR [NAME...]     (default: every line of kernels.txt)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
[ $# -ge 1 ] || { echo "usage: $0 DIR [NAME...]" >&2; exit 2; }
DIR=$(mkdir -p "$1" && cd "$1" && pwd); shift
MAINLINE=https://kernel.ubuntu.com/mainline

# urls NAME [IMAGE_URL]: the packages to download, one URL per line
urls() {
    local name=$1 image=${2:-}
    if [ -n "$image" ]; then
        echo "$image"
        echo "${image%/*}/$(basename "$image" | sed 's/^linux-image-\(unsigned-\)\?/linux-modules-/')"
    else
        curl -fsS "$MAINLINE/$name/amd64/" |
            grep -oE 'linux-(image-unsigned|modules)-[^"]*-generic_[^"]*_amd64\.deb' | sort -u |
            sed "s|^|$MAINLINE/$name/amd64/|"
    fi
}

want=" $* "
grep -v '^\s*\(#\|$\)' "$HERE/kernels.txt" | while read -r name image; do
    [ $# -eq 0 ] || [[ $want == *" $name "* ]] || continue
    dest=$DIR/$name
    [ -f "$dest/ok" ] && { echo "$name: already there"; continue; }
    rm -rf "$dest"; mkdir -p "$dest/deb"
    list=$(urls "$name" "$image") || true
    [ -n "$list" ] || { echo "$name: no packages found" >&2; continue; }
    ok=1
    for u in $list; do
        curl -fsS -o "$dest/deb/$(basename "$u")" "$u" && dpkg-deb -x "$dest/deb/$(basename "$u")" "$dest/root" ||
            { echo "$name: cannot download $u" >&2; ok=; break; }
    done
    rm -rf "$dest/deb"
    if [ -n "$ok" ] && ls "$dest"/root/boot/vmlinuz-* >/dev/null 2>&1; then
        touch "$dest/ok"; echo "$name: $(basename "$dest"/root/boot/vmlinuz-*)"
    else
        echo "$name: incomplete, run again" >&2
    fi
done
