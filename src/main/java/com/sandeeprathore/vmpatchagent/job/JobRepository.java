package com.sandeeprathore.vmpatchagent.job;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import com.sandeeprathore.vmpatchagent.match.RemediationItem;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Repository;

@Repository
public class JobRepository {

	private static final String COLUMNS = """
			id, status, created_at, updated_at, approved_by, allow_reboot, os_build_at_approval, items, snapshot_name,
			snapshot_requested_at, snapshot_created_at, snapshot_removed_at, status_detail""";

	private final JdbcClient jdbc;

	private final JsonMapper json;

	public JobRepository(JdbcClient jdbc, JsonMapper json) {
		this.jdbc = jdbc;
		this.json = json;
	}

	public long insert(String approvedBy, boolean allowReboot, String osBuild, List<RemediationItem> items, Instant now) {
		var keys = new GeneratedKeyHolder();
		jdbc.sql("""
				INSERT INTO remediation_job (status, created_at, updated_at, approved_by, allow_reboot, os_build_at_approval,
				    items) VALUES (?, ?, ?, ?, ?, ?, ?)""")
			.params(JobStatus.APPROVED.name(), Timestamp.from(now), Timestamp.from(now), approvedBy, allowReboot, osBuild,
					json.writeValueAsString(items))
			.update(keys, "id");
		return keys.getKey().longValue();
	}

	public Optional<RemediationJob> find(long id) {
		return jdbc.sql("SELECT " + COLUMNS + " FROM remediation_job WHERE id = ?").param(id).query(this::map).optional();
	}

	public List<RemediationJob> recent(int limit) {
		return jdbc.sql("SELECT " + COLUMNS + " FROM remediation_job ORDER BY id DESC LIMIT ?")
			.param(limit)
			.query(this::map)
			.list();
	}

	public List<RemediationJob> withStatus(JobStatus status) {
		return jdbc.sql("SELECT " + COLUMNS + " FROM remediation_job WHERE status = ? ORDER BY id")
			.param(status.name())
			.query(this::map)
			.list();
	}

	public Optional<RemediationJob> findActive() {
		return recent(20).stream().filter(job -> job.status().isActive()).findFirst();
	}

	public void updateStatus(long id, JobStatus status, String detail, Instant now) {
		jdbc.sql("UPDATE remediation_job SET status = ?, status_detail = ?, updated_at = ? WHERE id = ?")
			.params(status.name(), truncate(detail), Timestamp.from(now), id)
			.update();
	}

	public void markSnapshotRequested(long id, String snapshotName, Instant now) {
		jdbc.sql("""
				UPDATE remediation_job SET status = ?, snapshot_name = ?, snapshot_requested_at = ?, updated_at = ?
				WHERE id = ?""")
			.params(JobStatus.SNAPSHOTTING.name(), snapshotName, Timestamp.from(now), Timestamp.from(now), id)
			.update();
	}

	public void markSnapshotCreated(long id, Instant now) {
		jdbc.sql("UPDATE remediation_job SET status = ?, snapshot_created_at = ?, updated_at = ? WHERE id = ?")
			.params(JobStatus.AWAITING_INSTALL.name(), Timestamp.from(now), Timestamp.from(now), id)
			.update();
	}

	public void markSnapshotRemoved(long id, Instant now) {
		jdbc.sql("UPDATE remediation_job SET snapshot_removed_at = ?, updated_at = ? WHERE id = ?")
			.params(Timestamp.from(now), Timestamp.from(now), id)
			.update();
	}

	/**
	 * Forces committed changes to disk. Taken right before a snapshot so the snapshot's copy of the database is not
	 * missing the last commits, which may still be in the file cache.
	 */
	public void flushToDisk() {
		jdbc.sql("CHECKPOINT SYNC").update();
	}

	private RemediationJob map(ResultSet rs, int row) throws SQLException {
		return new RemediationJob(rs.getLong("id"), JobStatus.valueOf(rs.getString("status")), instant(rs, "created_at"),
				instant(rs, "updated_at"), rs.getString("approved_by"), rs.getBoolean("allow_reboot"),
				rs.getString("os_build_at_approval"),
				json.readValue(rs.getString("items"), new TypeReference<List<RemediationItem>>() {
				}), rs.getString("snapshot_name"), instant(rs, "snapshot_requested_at"),
				instant(rs, "snapshot_created_at"), instant(rs, "snapshot_removed_at"), rs.getString("status_detail"));
	}

	private static Instant instant(ResultSet rs, String column) throws SQLException {
		var timestamp = rs.getTimestamp(column);
		return timestamp == null ? null : timestamp.toInstant();
	}

	private static String truncate(String text) {
		return text == null || text.length() <= 2000 ? text : text.substring(0, 2000);
	}

}
