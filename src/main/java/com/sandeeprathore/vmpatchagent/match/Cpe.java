package com.sandeeprathore.vmpatchagent.match;

import java.util.ArrayList;
import java.util.List;

/**
 * A CPE 2.3 formatted string, split into its 13 fields. Backslash escapes are kept, so
 * {@code cpe:2.3:a:notepad-plus-plus:notepad\+\+} compares equal to itself as NVD writes it.
 */
public record Cpe(List<String> fields) {

	private static final int PART = 2;

	private static final int VENDOR = 3;

	private static final int PRODUCT = 4;

	private static final int VERSION = 5;

	private static final int TARGET_SW = 10;

	public static Cpe parse(String text) {
		var fields = new ArrayList<String>();
		var current = new StringBuilder();
		for (var i = 0; i < text.length(); i++) {
			var c = text.charAt(i);
			if (c == '\\' && i + 1 < text.length()) {
				current.append(c).append(text.charAt(++i));
			}
			else if (c == ':') {
				fields.add(current.toString());
				current.setLength(0);
			}
			else {
				current.append(c);
			}
		}
		fields.add(current.toString());
		while (fields.size() < 13) {
			fields.add("*");
		}
		return new Cpe(List.copyOf(fields));
	}

	/** {@code cpe:2.3:<part>:<vendor>:<product>}, the key the app catalog uses. */
	public String productKey() {
		return "cpe:2.3:" + fields.get(PART) + ":" + fields.get(VENDOR) + ":" + fields.get(PRODUCT);
	}

	public String part() {
		return fields.get(PART);
	}

	public String vendor() {
		return fields.get(VENDOR);
	}

	public String product() {
		return fields.get(PRODUCT);
	}

	/** A concrete version, or null when the field is {@code *} (any) or {@code -} (not applicable). */
	public String specificVersion() {
		var version = fields.get(VERSION);
		return version.equals("*") || version.equals("-") ? null : version;
	}

	/** True unless the CPE is restricted to a non-Windows platform, e.g. {@code target_sw=macos}. */
	public boolean appliesToWindows() {
		var target = fields.get(TARGET_SW).toLowerCase();
		return target.equals("*") || target.equals("-") || target.contains("windows");
	}

}
