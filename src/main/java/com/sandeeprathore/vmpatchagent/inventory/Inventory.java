package com.sandeeprathore.vmpatchagent.inventory;

import java.time.Instant;
import java.util.List;

/** Everything one scan learned about this VM. */
public record Inventory(Instant collectedAt, SystemInfo system, List<MissingUpdate> missingUpdates,
		List<InstalledApp> apps) {

	public Inventory {
		missingUpdates = List.copyOf(missingUpdates);
		apps = List.copyOf(apps);
	}

	public List<MissingUpdate> missingSecurityUpdates() {
		return missingUpdates.stream().filter(MissingUpdate::isSecurityUpdate).toList();
	}

}
