package com.sandeeprathore.vmpatchagent.inventory;

import java.time.Instant;
import java.util.List;

/**
 * @param build Windows build number, e.g. 20348 for Server 2022
 * @param ubr update build revision; rises with each cumulative update, e.g. 20348.<b>2700</b>
 * @param installationType {@code Server}, {@code Server Core} or {@code Client}, from the registry
 * @param architecture {@code AMD64}, {@code ARM64} or {@code x86} ({@code PROCESSOR_ARCHITECTURE})
 * @param wsusServer WSUS URL from group policy, or null when the VM uses Microsoft Update directly
 * @param lastBootTime when Windows last started; how the agent notices it was reverted to a snapshot
 */
public record SystemInfo(String hostname, String caption, String displayVersion, int build, int ubr,
		String installationType, String architecture, String wsusServer, Instant lastBootTime,
		List<InstalledUpdate> installedUpdates) {

	public SystemInfo {
		installedUpdates = installedUpdates == null ? List.of() : List.copyOf(installedUpdates);
	}

	public String osBuild() {
		return build + "." + ubr;
	}

	/** The full Windows version MSRC uses for fixed builds, e.g. {@code 10.0.20348.2700}. */
	public String windowsVersion() {
		return "10.0." + osBuild();
	}

	public boolean isServerCore() {
		return "Server Core".equalsIgnoreCase(installationType);
	}

}
