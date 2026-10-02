package com.sandeeprathore.vmpatchagent.match;

import java.util.Arrays;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * A dotted numeric version such as {@code 128.0.6613.120} or a Windows build {@code 10.0.20348.2700}.
 * <p>
 * Only the leading run of numeric segments counts ({@code 115.0esr} is {@code 115.0}); missing trailing segments are
 * zero, so {@code 1.0 == 1.0.0}. Vendors that put letters in the middle of versions are deliberately not supported:
 * an app whose versions do not parse is reported as "cannot assess" rather than guessed at.
 */
public record Version(long[] segments) implements Comparable<Version> {

	private static final Pattern LEADING_NUMERIC = Pattern.compile("^\\s*(\\d+(?:\\.\\d+)*)");

	public static Optional<Version> tryParse(String text) {
		if (text == null) {
			return Optional.empty();
		}
		var matcher = LEADING_NUMERIC.matcher(text);
		if (!matcher.find()) {
			return Optional.empty();
		}
		try {
			return Optional.of(new Version(Arrays.stream(matcher.group(1).split("\\.")).mapToLong(Long::parseLong)
				.toArray()));
		}
		catch (NumberFormatException ex) {
			return Optional.empty();
		}
	}

	public static Version parse(String text) {
		return tryParse(text).orElseThrow(() -> new IllegalArgumentException("Not a version: " + text));
	}

	@Override
	public int compareTo(Version other) {
		var length = Math.max(segments.length, other.segments.length);
		for (var i = 0; i < length; i++) {
			var cmp = Long.compare(segment(i), other.segment(i));
			if (cmp != 0) {
				return cmp;
			}
		}
		return 0;
	}

	public boolean isBefore(Version other) {
		return compareTo(other) < 0;
	}

	private long segment(int index) {
		return index < segments.length ? segments[index] : 0;
	}

	@Override
	public boolean equals(Object other) {
		return other instanceof Version version && compareTo(version) == 0;
	}

	@Override
	public int hashCode() {
		var end = segments.length;
		while (end > 0 && segments[end - 1] == 0) {
			end--;
		}
		return Arrays.hashCode(Arrays.copyOf(segments, end));
	}

	@Override
	public String toString() {
		return String.join(".", Arrays.stream(segments).mapToObj(Long::toString).toList());
	}

}
