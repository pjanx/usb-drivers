#!/bin/sh -e
# Win64Depends.sh: download dependencies from MSYS2 for cross-compilation.
# Dependencies: AWK, sed, sha256sum, cURL, bsdtar
repository=https://repo.msys2.org/mingw/mingw64/

status() {
	echo "$(tput bold)-- $*$(tput sgr0)"
}

dbsync() {
	status Fetching repository DB
	[ -f db.tsv ] || curl -# "$repository/mingw64.db" | bsdtar -xOf- | awk '
		function flush() { print f["%NAME%"] f["%FILENAME%"] f["%DEPENDS%"] }
		NR > 1 && $0 == "%FILENAME%" { flush(); for (i in f) delete f[i] }
		!/^[^%]/ { field = $0; next } { f[field] = f[field] $0 "\t" }
		field == "%SHA256SUM%" { path = "*packages/" f["%FILENAME%"]
			sub(/\t$/, "", path); print $0, path > "db.sums" } END { flush() }
	' > db.tsv
}

fetch() {
	status Resolving "$@"
	mkdir -p packages
	awk -F'\t' 'function get(name,    i, a) {
		if (visited[name]++ || !(name in filenames)) return
		print filenames[name]; split(deps[name], a); for (i in a) get(a[i])
	} BEGIN { while ((getline < "db.tsv") > 0) {
		filenames[$1] = $2; deps[$1] = ""; for (i = 3; i <= NF; i++) {
			gsub(/[<=>].*/, "", $i); deps[$1] = deps[$1] $i FS }
	} for (i = 0; i < ARGC; i++) get(ARGV[i]) }' "$@" | tee db.want | \
	while IFS= read -r name
	do
		status Fetching "$name"
		[ -f "packages/$name" ] || curl -#o "packages/$name" "$repository/$name"
	done
}

verify() {
	status Verifying checksums
	sha256sum --ignore-missing --quiet -c db.sums
}

extract() {
	status Extracting packages
	for subdir in *
	do [ -d "$subdir" -a "$subdir" != packages ] && rm -rf -- "$subdir"
	done
	while IFS= read -r name
	do bsdtar -xf "packages/$name" --strip-components 1
	done < db.want
}

# This directory name matches the prefix in .pc files, so we don't need to
# modify them (pkgconf has --prefix-variable, but CMake can't pass that option).
mkdir -p mingw64
cd mingw64
dbsync
fetch mingw-w64-x86_64-hidapi mingw-w64-x86_64-libusb
verify
extract

status Success
