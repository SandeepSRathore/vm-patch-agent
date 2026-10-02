package com.sandeeprathore.vmpatchagent.match;

import java.util.Comparator;
import java.util.List;

/**
 * One proposed fix. In M2 the plan is read-only; M3 turns approved items into jobs.
 *
 * @param kb for Windows updates, e.g. {@code KB5122882}
 * @param wingetId for app upgrades; null when the app cannot be upgraded with winget
 * @param targetVersion the Windows build or app version the fix brings; null when NVD names no fixed version
 * @param offeredByWindowsUpdate for Windows updates: whether this VM's own Windows Update scan offers the KB
 * @param note anything the admin should know before approving
 */
public record RemediationItem(Kind kind, String title, String kb, String wingetId, String installedVersion,
		String targetVersion, boolean rebootLikely, boolean offeredByWindowsUpdate, String note,
		List<CveFinding> cves, Priority basePriority) {

	public enum Kind {

		/** The latest Windows cumulative update; carries every older OS fix. */
		WINDOWS_CUMULATIVE,

		/** Any other security update Windows Update offers, e.g. .NET Framework. */
		WINDOWS_UPDATE,

		/** A third-party program upgrade. */
		APP_UPGRADE

	}

	public RemediationItem {
		cves = cves.stream()
			.sorted(Comparator.comparing(CveFinding::priority).thenComparing(CveFinding::cve, Comparator.reverseOrder()))
			.toList();
	}

	/** Identifies this fix across re-computations of the plan, so an approval names exactly what was on screen. */
	public String key() {
		return kind + ":" + (kb != null ? kb : title);
	}

	public Priority priority() {
		return cves.stream().map(CveFinding::priority).reduce(basePriority, Priority::highest);
	}

	public boolean activelyExploited() {
		return cves.stream().anyMatch(CveFinding::activelyExploited);
	}

	public long kevCount() {
		return cves.stream().filter(CveFinding::inKev).count();
	}

}
