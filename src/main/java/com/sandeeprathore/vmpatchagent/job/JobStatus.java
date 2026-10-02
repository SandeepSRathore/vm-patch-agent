package com.sandeeprathore.vmpatchagent.job;

public enum JobStatus {

	/** An approver selected fixes; the snapshot has not started yet. */
	APPROVED("Approved", true),

	/** Asking vSphere for a snapshot of this VM. */
	SNAPSHOTTING("Taking snapshot", true),

	/** Snapshot taken. Installation arrives in M4; until then the job waits here. */
	AWAITING_INSTALL("Snapshot taken, awaiting install", true),

	CANCELLED("Cancelled", false),

	FAILED("Failed", false),

	/** The VM came back up in the state captured by this job's snapshot. */
	REVERTED("Reverted to snapshot", false);

	private final String label;

	private final boolean active;

	JobStatus(String label, boolean active) {
		this.label = label;
		this.active = active;
	}

	public String label() {
		return label;
	}

	/** Only one active job is allowed at a time: one snapshot, one change window. */
	public boolean isActive() {
		return active;
	}

}
