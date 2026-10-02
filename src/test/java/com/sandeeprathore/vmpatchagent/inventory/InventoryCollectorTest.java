package com.sandeeprathore.vmpatchagent.inventory;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Map;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import com.sandeeprathore.vmpatchagent.script.BundledScript;
import com.sandeeprathore.vmpatchagent.script.DemoScriptRunner;
import com.sandeeprathore.vmpatchagent.script.ScriptRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InventoryCollectorTest {

	private static final Instant NOW = Instant.parse("2026-10-02T09:00:00Z");

	private final JsonMapper json = JsonMapper.builder().build();

	private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

	@Test
	void parsesSystemInfoFromScriptOutput() {
		var inventory = new InventoryCollector(new DemoScriptRunner(), json, clock).collect();

		var system = inventory.system();
		assertThat(system.hostname()).isEqualTo("DEMO-APP01");
		assertThat(system.osBuild()).isEqualTo("20348.2700");
		assertThat(system.wsusServer()).isNull();
		assertThat(system.installedUpdates()).hasSize(3)
			.first()
			.isEqualTo(new InstalledUpdate("KB5042349", "Security Update", LocalDate.of(2026, 8, 14)));
		assertThat(system.installedUpdates().get(2).installedOn()).isNull();
		assertThat(inventory.collectedAt()).isEqualTo(NOW);
	}

	@Test
	void keepsAllMissingUpdatesButOnlyCountsSecurityOnesAsFixes() {
		var inventory = new InventoryCollector(new DemoScriptRunner(), json, clock).collect();

		assertThat(inventory.missingUpdates()).hasSize(3);
		assertThat(inventory.missingSecurityUpdates()).extracting(u -> u.kbs().getFirst())
			.containsExactly("KB5122882", "KB5126050");
		var cumulative = inventory.missingUpdates().getFirst();
		assertThat(cumulative.msrcSeverity()).isEqualTo("Critical");
		assertThat(cumulative.mayRequireReboot()).isTrue();
		assertThat(cumulative.cveIds()).isEmpty();
	}

	@Test
	void parsesInstalledApps() {
		var inventory = new InventoryCollector(new DemoScriptRunner(), json, clock).collect();

		assertThat(inventory.apps()).hasSize(5)
			.first()
			.isEqualTo(new InstalledApp("7-Zip 24.08 (x64)", "24.08", "Igor Pavlov", "x64"));
	}

	@Test
	void treatsMissingFieldsInScriptOutputSafely() {
		ScriptRunner runner = (script, parameters) -> switch (script) {
			case SYSTEM_INFO -> """
					{"hostname":"VM1","caption":"Windows Server 2019","build":17763,"ubr":6000,"installedUpdates":null}""";
			case WUA_SCAN -> """
					{"resultCode":2,"updates":[{"updateId":"u1","title":"t","kbs":null,"cveIds":null,"categories":null}]}""";
			case INSTALLED_APPS -> "[]";
		};

		var inventory = new InventoryCollector(runner, json, clock).collect();

		assertThat(inventory.system().installedUpdates()).isEmpty();
		assertThat(inventory.missingUpdates().getFirst().kbs()).isEmpty();
		assertThat(inventory.missingSecurityUpdates()).isEmpty();
		assertThat(inventory.missingUpdates().getFirst().mayRequireReboot()).isTrue();
	}

	@Test
	void failsWhenWindowsUpdateSearchDidNotSucceed() {
		var demo = new DemoScriptRunner();
		ScriptRunner runner = (script, parameters) -> script == BundledScript.WUA_SCAN
				? "{\"resultCode\":4,\"updates\":[]}" : demo.run(script, Map.of());

		assertThatThrownBy(() -> new InventoryCollector(runner, json, clock).collect())
			.isInstanceOf(InventoryException.class)
			.hasMessageContaining("result code 4");
	}

	@Test
	void reportsUnparseableScriptOutput() {
		var demo = new DemoScriptRunner();
		ScriptRunner runner = (script, parameters) -> script == BundledScript.INSTALLED_APPS ? "WARNING: not json"
				: demo.run(script, Map.of());

		assertThatThrownBy(() -> new InventoryCollector(runner, json, clock).collect())
			.isInstanceOf(InventoryException.class)
			.hasMessageContaining("installed-apps");
	}

}
