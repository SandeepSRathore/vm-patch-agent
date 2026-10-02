package com.sandeeprathore.vmpatchagent.script;

/**
 * The only PowerShell the agent will ever run. Each one ships inside the jar under {@code scripts/} and writes a
 * single JSON document to stdout.
 */
public enum BundledScript {

	/** Hostname, OS build and UBR, WSUS server (if any) and installed hotfixes. */
	SYSTEM_INFO("system-info"),

	/** Windows Update Agent search for applicable updates that are not installed. */
	WUA_SCAN("wua-scan"),

	/** Installed programs from the machine-wide uninstall registry keys. */
	INSTALLED_APPS("installed-apps");

	private final String baseName;

	BundledScript(String baseName) {
		this.baseName = baseName;
	}

	public String resourcePath() {
		return "scripts/" + baseName + ".ps1";
	}

	public String demoResourcePath() {
		return "demo/" + baseName + ".json";
	}

}
