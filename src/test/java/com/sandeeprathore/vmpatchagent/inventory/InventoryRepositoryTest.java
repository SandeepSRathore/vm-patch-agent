package com.sandeeprathore.vmpatchagent.inventory;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = "agent.inventory.keep-snapshots=2")
@ActiveProfiles("test")
class InventoryRepositoryTest {

	@Autowired
	InventoryRepository repository;

	@Test
	void roundTripsTheLatestInventoryAndPrunesOldSnapshots() {
		assertThat(repository.findLatest()).isEmpty();

		repository.save(inventory("VM-A", "2026-10-01T00:00:00Z"));
		repository.save(inventory("VM-B", "2026-10-02T00:00:00Z"));
		repository.save(inventory("VM-C", "2026-10-03T00:00:00Z"));

		assertThat(repository.count()).isEqualTo(2);
		var latest = repository.findLatest().orElseThrow();
		assertThat(latest.system().hostname()).isEqualTo("VM-C");
		assertThat(latest.missingUpdates().getFirst().cveIds()).containsExactly("CVE-2026-0001");
		assertThat(latest.apps().getFirst().version()).isEqualTo("24.08");
	}

	private static Inventory inventory(String hostname, String collectedAt) {
		var system = new SystemInfo(hostname, "Windows Server 2022", "21H2", 20348, 2700, "Server", "AMD64", null, null,
				List.of());
		var update = new MissingUpdate("u1", "CU", List.of("KB1"), "Critical", List.of("CVE-2026-0001"),
				List.of("Security Updates"), 1, 100L);
		var app = new InstalledApp("7-Zip 24.08 (x64)", "24.08", "Igor Pavlov", "x64");
		return new Inventory(Instant.parse(collectedAt), system, List.of(update), List.of(app));
	}

}
