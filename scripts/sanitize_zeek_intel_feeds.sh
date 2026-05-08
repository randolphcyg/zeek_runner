#!/bin/sh
set -eu

feed_root="${1:-/usr/local/zeek/share/zeek/site/Zeek-Intelligence-Feeds}"

if [ ! -d "$feed_root" ]; then
	echo "intel feed root not found: $feed_root" >&2
	exit 1
fi

find "$feed_root" -type f -name '*.intel' -print | while IFS= read -r feed_file; do
	tmp_file="${feed_file}.sanitized"
	awk '
	BEGIN {
		FS = OFS = "\t"
		indicator_idx = 1
		type_idx = 2
		removed = 0
	}

	function is_ipv4(value, parts, i, n) {
		n = split(value, parts, ".")
		if (n != 4) {
			return 0
		}
		for (i = 1; i <= 4; i++) {
			if (parts[i] !~ /^[0-9]+$/ || parts[i] < 0 || parts[i] > 255) {
				return 0
			}
		}
		return 1
	}

	function is_ipv6(value) {
		return value ~ /^[0-9A-Fa-f:.]+$/ && value ~ /:/
	}

	function is_addr(value) {
		return is_ipv4(value) || is_ipv6(value)
	}

	/^#fields[ \t]/ {
		for (i = 2; i <= NF; i++) {
			if ($i == "indicator") {
				indicator_idx = i - 1
			}
			if ($i == "indicator_type") {
				type_idx = i - 1
			}
		}
		print
		next
	}

	/^#/ {
		print
		next
	}

	/^[[:space:]]*$/ {
		removed++
		next
	}

	{
		indicator = $indicator_idx
		indicator_type = $type_idx

		if (indicator == "" || indicator_type == "") {
			removed++
			next
		}
		if (indicator ~ /[<>]/) {
			removed++
			next
		}
		if (indicator_type == "Intel::ADDR" && ! is_addr(indicator)) {
			removed++
			next
		}

		print
	}

	END {
		if (removed > 0) {
			printf("%s\t%d\n", FILENAME, removed) > "/dev/stderr"
		}
	}
	' "$feed_file" > "$tmp_file"
	mv "$tmp_file" "$feed_file"
done
