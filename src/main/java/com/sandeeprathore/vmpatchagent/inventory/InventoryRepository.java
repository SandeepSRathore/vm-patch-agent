package com.sandeeprathore.vmpatchagent.inventory;

import java.sql.Timestamp;
import java.util.Optional;

import tools.jackson.databind.json.JsonMapper;

import com.sandeeprathore.vmpatchagent.AgentProperties;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public class InventoryRepository {

	private final JdbcClient jdbc;

	private final JsonMapper json;

	private final int keepSnapshots;

	public InventoryRepository(JdbcClient jdbc, JsonMapper json, AgentProperties properties) {
		this.jdbc = jdbc;
		this.json = json;
		this.keepSnapshots = properties.inventory().keepSnapshots();
	}

	/** Stores a scan and prunes all but the newest {@code agent.inventory.keep-snapshots}. */
	@Transactional
	public void save(Inventory inventory) {
		jdbc.sql("INSERT INTO inventory_snapshot (collected_at, payload) VALUES (?, ?)")
			.params(Timestamp.from(inventory.collectedAt()), json.writeValueAsString(inventory))
			.update();
		jdbc.sql("""
				DELETE FROM inventory_snapshot WHERE id NOT IN (
				    SELECT id FROM inventory_snapshot ORDER BY collected_at DESC, id DESC LIMIT ?)""")
			.param(keepSnapshots)
			.update();
	}

	public Optional<Inventory> findLatest() {
		return jdbc.sql("SELECT payload FROM inventory_snapshot ORDER BY collected_at DESC, id DESC LIMIT 1")
			.query(String.class)
			.optional()
			.map(payload -> json.readValue(payload, Inventory.class));
	}

	public long count() {
		return jdbc.sql("SELECT COUNT(*) FROM inventory_snapshot").query(Long.class).single();
	}

}
