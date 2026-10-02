package com.sandeeprathore.vmpatchagent.match;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Programs the agent knows how to assess, bound from {@code agent.catalog.apps}. Admins can add entries; anything not
 * listed is shown as "not tracked" and never guessed at.
 */
@ConfigurationProperties("agent.catalog")
public record AppCatalogProperties(List<Entry> apps) {

	public AppCatalogProperties {
		apps = apps == null ? List.of() : List.copyOf(apps);
	}

	/**
	 * @param label shown on the dashboard
	 * @param namePattern regex matched against the uninstall-registry DisplayName; the first matching entry wins
	 * @param cpe {@code cpe:2.3:a:<vendor>:<product>} exactly as NVD writes it, escapes included
	 * @param wingetId how M4 will upgrade it; empty when winget cannot (e.g. VMware Tools, upgraded from vCenter)
	 */
	public record Entry(String label, String namePattern, String cpe, String wingetId) {
	}

}
