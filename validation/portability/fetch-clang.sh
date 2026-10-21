#!/bin/bash
# Download the compilers of clang.txt from the Ubuntu archive and unpack them,
# without root, into DIR/<label>/. Writes DIR/bin/<label>, a script that runs
# that clang with its own libraries. Compilers already unpacked are skipped.
#
# usage: fetch-clang.sh DIR [LABEL...]     (default: every line of clang.txt)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
[ $# -ge 1 ] || { echo "usage: $0 DIR [LABEL...]" >&2; exit 2; }
DIR=$(mkdir -p "$1" && cd "$1" && pwd); shift
ARCHIVE=http://archive.ubuntu.com/ubuntu/pool
ARCH=amd64
MULTIARCH=$(gcc -dumpmachine 2>/dev/null || echo x86_64-linux-gnu)

# fetch LABEL SOURCE VERSION PACKAGE...: download and unpack into DIR/LABEL
fetch() {
    local label=$1 source=$2 version=$3; shift 3
    local dest=$DIR/$label letter=${source:0:1}
    [ -f "$dest/ok" ] && { echo "$label: already there"; return 0; }
    case $source in lib*) letter=${source:0:4} ;; esac
    rm -rf "$dest"; mkdir -p "$dest/deb"
    for p in "$@"; do
        local f=${p}_${version}_${ARCH}.deb got=
        for comp in main universe; do
            if curl -fsS -o "$dest/deb/$f" "$ARCHIVE/$comp/$letter/$source/$f" 2>/dev/null; then got=1; break; fi
        done
        [ -n "$got" ] || { echo "$label: $f not found in the archive" >&2; return 1; }
        dpkg-deb -x "$dest/deb/$f" "$dest"
    done
    rm -rf "$dest/deb"
    touch "$dest/ok"
}

want=" $* "
mkdir -p "$DIR/bin"
lines=$(grep -v '^\s*\(#\|$\)' "$HERE/clang.txt")
# the common libraries first: every clang needs them
# shellcheck disable=SC2086
fetch $(echo "$lines" | grep '^common\s')
echo "$lines" | grep -v '^common\s' | while read -r label source version packages; do
    [ $# -eq 0 ] || [[ $want == *" $label "* ]] || continue
    # shellcheck disable=SC2086
    fetch "$label" "$source" "$version" $packages
    major=${source##*-}
    llvm=$DIR/$label/usr/lib/llvm-$major
    cat > "$DIR/bin/$label" <<EOF
#!/bin/sh
LD_LIBRARY_PATH=$llvm/lib:$DIR/$label/usr/lib/$MULTIARCH:$DIR/common/usr/lib/$MULTIARCH exec $llvm/bin/clang -resource-dir=$llvm/lib/clang/$major "\$@"
EOF
    chmod +x "$DIR/bin/$label"
    v=$("$DIR/bin/$label" --version) || { echo "$label: does not run" >&2; exit 1; }
    echo "$label: ${v%%$'\n'*}"
done
