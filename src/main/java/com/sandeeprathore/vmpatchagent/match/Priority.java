package com.sandeeprathore.vmpatchagent.match;

/** Fix order: anything known to be exploited first, then by severity. */
public enum Priority {

	ACTIVELY_EXPLOITED("Exploited"), CRITICAL("Critical"), HIGH("High"), OTHER("Other");

	private final String label;

	Priority(String label) {
		this.label = label;
	}

	public String label() {
		return label;
	}

	static Priority of(String severity, Double cvss, boolean exploited) {
		if (exploited) {
			return ACTIVELY_EXPLOITED;
		}
		if ("Critical".equalsIgnoreCase(severity) || (cvss != null && cvss >= 9.0)) {
			return CRITICAL;
		}
		if ("Important".equalsIgnoreCase(severity) || "High".equalsIgnoreCase(severity)
				|| (cvss != null && cvss >= 7.0)) {
			return HIGH;
		}
		return OTHER;
	}

	static Priority highest(Priority a, Priority b) {
		return a.ordinal() <= b.ordinal() ? a : b;
	}

}
