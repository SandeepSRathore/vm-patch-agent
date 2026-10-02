package com.sandeeprathore.vmpatchagent.job;

import java.time.Instant;
import java.util.List;

import com.sandeeprathore.vmpatchagent.match.RemediationItem;

/**
 * @param items the fixes exactly as the approver saw them, frozen at approval
 * @param osBuildAtApproval lets the installer (M4) refuse to act if the VM changed since approval
 * @param snapshotRequestedAt set just before the snapshot is requested; the snapshot captures the database in that
 * state, which is how a later revert is recognised
 */
public record RemediationJob(long id, JobStatus status, Instant createdAt, Instant updatedAt, String approvedBy,
		boolean allowReboot, String osBuildAtApproval, List<RemediationItem> items, String snapshotName,
		Instant snapshotRequestedAt, Instant snapshotCreatedAt, Instant snapshotRemovedAt, String statusDetail) {

	public boolean hasSnapshot() {
		return snapshotCreatedAt != null && snapshotRemovedAt == null;
	}

	public boolean canCancel() {
		return status == JobStatus.APPROVED || status == JobStatus.AWAITING_INSTALL;
	}

	/** A snapshot may only be deleted once nothing depends on it. */
	public boolean canDeleteSnapshot() {
		return hasSnapshot() && !status.isActive();
	}

	public long cveCount() {
		return items.stream().flatMap(i -> i.cves().stream()).map(c -> c.cve()).distinct().count();
	}

}
