package com.sandeeprathore.vmpatchagent.audit;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sandeeprathore.vmpatchagent.audit.EventLogSink.Level;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

@Service
public class AuditLog {

	public static final String SYSTEM = "system";

	private static final Logger log = LoggerFactory.getLogger(AuditLog.class);

	private final JdbcClient jdbc;

	private final EventLogSink eventLog;

	private final Clock clock;

	public AuditLog(JdbcClient jdbc, EventLogSink eventLog, Clock clock) {
		this.jdbc = jdbc;
		this.eventLog = eventLog;
		this.clock = clock;
	}

	public void record(String actor, AuditAction action, Long jobId, String detail) {
		var text = detail != null && detail.length() > 4000 ? detail.substring(0, 4000) : detail;
		jdbc.sql("INSERT INTO audit_event (at, actor, action, job_id, detail) VALUES (?, ?, ?, ?, ?)")
			.params(Timestamp.from(clock.instant()), actor, action.name(), jobId, text)
			.update();
		var message = "%s by %s%s: %s".formatted(action, actor, jobId == null ? "" : " (job " + jobId + ")",
				text == null ? "" : text);
		log.info("AUDIT {}", message);
		eventLog.write(level(action), message);
	}

	public List<AuditEvent> recent(int limit) {
		return jdbc.sql("SELECT id, at, actor, action, job_id, detail FROM audit_event ORDER BY at DESC, id DESC LIMIT ?")
			.param(limit)
			.query((rs, row) -> new AuditEvent(rs.getLong("id"), rs.getTimestamp("at").toInstant(), rs.getString("actor"),
					AuditAction.valueOf(rs.getString("action")), (Long) rs.getObject("job_id"), rs.getString("detail")))
			.list();
	}

	private static Level level(AuditAction action) {
		return switch (action) {
			case SNAPSHOT_FAILED, SNAPSHOT_DELETE_FAILED, JOB_FAILED -> Level.ERROR;
			case SIGN_IN_FAILED, REVERT_DETECTED -> Level.WARNING;
			default -> Level.INFORMATION;
		};
	}

}
