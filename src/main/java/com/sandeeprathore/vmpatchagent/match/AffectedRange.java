package com.sandeeprathore.vmpatchagent.match;

import java.util.Optional;

/**
 * Versions of one product a CVE affects, as NVD states them. Any bound may be null. {@code exactVersion} is set when
 * NVD names a single version instead of a range.
 */
public record AffectedRange(String exactVersion, String startIncluding, String startExcluding, String endIncluding,
		String endExcluding) {

	/**
	 * @return empty when a bound in this range cannot be parsed, so the caller can report "cannot assess" instead of
	 * silently treating the app as safe
	 */
	public Optional<Boolean> contains(Version installed) {
		try {
			if (exactVersion != null) {
				return Optional.of(installed.equals(Version.parse(exactVersion)));
			}
			if (startIncluding != null && installed.isBefore(Version.parse(startIncluding))) {
				return Optional.of(false);
			}
			if (startExcluding != null && installed.compareTo(Version.parse(startExcluding)) <= 0) {
				return Optional.of(false);
			}
			if (endIncluding != null && installed.compareTo(Version.parse(endIncluding)) > 0) {
				return Optional.of(false);
			}
			if (endExcluding != null && !installed.isBefore(Version.parse(endExcluding))) {
				return Optional.of(false);
			}
			return Optional.of(true);
		}
		catch (IllegalArgumentException ex) {
			return Optional.empty();
		}
	}

	/** The first version outside this range, when NVD says so; {@code versionEndIncluding} only says "after X". */
	public Optional<String> fixedIn() {
		return Optional.ofNullable(endExcluding);
	}

	public String describe() {
		if (exactVersion != null) {
			return "= " + exactVersion;
		}
		var lower = startIncluding != null ? ">= " + startIncluding : startExcluding != null ? "> " + startExcluding : "";
		var upper = endExcluding != null ? "< " + endExcluding : endIncluding != null ? "<= " + endIncluding : "";
		var text = (lower + " " + upper).strip();
		return text.isEmpty() ? "all versions" : text;
	}

}
