package com.sandeeprathore.vmpatchagent.inventory;

import java.time.Clock;
import java.util.List;

import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import com.sandeeprathore.vmpatchagent.script.BundledScript;
import com.sandeeprathore.vmpatchagent.script.ScriptRunner;

import org.springframework.stereotype.Component;

/** Runs the read-only inventory scripts and assembles one {@link Inventory}. */
@Component
public class InventoryCollector {

	private final ScriptRunner scripts;

	private final JsonMapper json;

	private final Clock clock;

	public InventoryCollector(ScriptRunner scripts, JsonMapper json, Clock clock) {
		this.scripts = scripts;
		this.json = json;
		this.clock = clock;
	}

	public Inventory collect() {
		var collectedAt = clock.instant();
		var system = read(BundledScript.SYSTEM_INFO, new TypeReference<SystemInfo>() {
		});
		var scan = read(BundledScript.WUA_SCAN, new TypeReference<WuaScanResult>() {
		});
		if (!scan.succeeded()) {
			throw new InventoryException("Windows Update search failed with result code " + scan.resultCode());
		}
		var apps = read(BundledScript.INSTALLED_APPS, new TypeReference<List<InstalledApp>>() {
		});
		return new Inventory(collectedAt, system, scan.updates(), apps);
	}

	private <T> T read(BundledScript script, TypeReference<T> type) {
		var output = scripts.run(script);
		try {
			return json.readValue(output, type);
		}
		catch (JacksonException ex) {
			throw new InventoryException(script.resourcePath() + " printed output that is not the expected JSON", ex);
		}
	}

}
