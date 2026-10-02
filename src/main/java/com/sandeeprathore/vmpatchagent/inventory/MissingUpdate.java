package com.sandeeprathore.vmpatchagent.inventory;

import java.util.List;

/**
 * An applicable update the Windows Update Agent says is not installed.
 *
 * @param msrcSeverity Critical, Important, Moderate or Low; null for non-security updates
 * @param rebootBehavior 0 never reboots, 1 always requires a reboot, 2 may request one; null (not reported) is treated
 *     as may reboot, never as "no reboot"
 */
public record MissingUpdate(String updateId, String title, List<String> kbs, String msrcSeverity,
		List<String> cveIds, List<String> categories, Integer rebootBehavior, Long sizeBytes) {

	public MissingUpdate {
		kbs = kbs == null ? List.of() : List.copyOf(kbs);
		cveIds = cveIds == null ? List.of() : List.copyOf(cveIds);
		categories = categories == null ? List.of() : List.copyOf(categories);
		sizeBytes = sizeBytes == null ? 0L : sizeBytes;
	}

	/** Security fixes are what this agent exists for; feature and driver updates are shown but never planned. */
	public boolean isSecurityUpdate() {
		return msrcSeverity != null || categories.contains("Security Updates");
	}

	public boolean mayRequireReboot() {
		return rebootBehavior == null || rebootBehavior != 0;
	}

}
