package com.sandeeprathore.vmpatchagent.audit;

import java.time.Instant;

/** @param actor a Windows account, or {@code system} for the agent itself */
public record AuditEvent(long id, Instant at, String actor, AuditAction action, Long jobId, String detail) {
}
