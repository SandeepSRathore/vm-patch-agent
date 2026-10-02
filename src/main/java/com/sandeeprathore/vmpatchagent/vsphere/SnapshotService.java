package com.sandeeprathore.vmpatchagent.vsphere;

/**
 * Snapshots of this VM. There is deliberately no revert: reverting from inside the guest would leave the VM powered
 * off with nothing running to power it back on, and would erase the agent's record of the revert. Admins revert from
 * vCenter; see {@link #revertInstructions(String)}.
 */
public interface SnapshotService {

	/** @param reason why approvals are blocked, when {@code ready} is false */
	record Readiness(boolean ready, String reason) {

		public static Readiness ok() {
			return new Readiness(true, null);
		}

		public static Readiness blocked(String reason) {
			return new Readiness(false, reason);
		}

	}

	Readiness readiness();

	/** Disk-only snapshot (no memory), quiesced when configured. */
	void create(String name, String description);

	void remove(String name);

	/** What an admin runs, from outside this VM, to roll back to the snapshot. */
	String revertInstructions(String name);

}
