package com.sandeeprathore.vmpatchagent;

import java.nio.file.Path;
import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Agent settings, bound from {@code agent.*}.
 *
 * @param dataDir where the database and job state live; the installer restricts it to Administrators and SYSTEM
 * @param scripts how bundled PowerShell scripts are run
 * @param inventory how often the VM is rescanned
 */
@ConfigurationProperties("agent")
public record AgentProperties(Path dataDir, Scripts scripts, Inventory inventory) {

	public enum ScriptMode {

		/** Run the bundled scripts with Windows PowerShell. */
		POWERSHELL,

		/** Return canned JSON from {@code classpath:demo/}, for running the dashboard off-Windows. */
		DEMO

	}

	public record Scripts(@DefaultValue("POWERSHELL") ScriptMode mode,
			@DefaultValue("powershell.exe") String powershellPath, @DefaultValue("30m") Duration timeout) {
	}

	public record Inventory(@DefaultValue("1h") Duration refreshInterval, @DefaultValue("50") int keepSnapshots) {
	}

}
