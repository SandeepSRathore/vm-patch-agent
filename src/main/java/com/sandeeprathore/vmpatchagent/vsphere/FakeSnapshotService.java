package com.sandeeprathore.vmpatchagent.vsphere;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Pretends to snapshot, so the approval flow can be demoed off-Windows. Never use on a real VM. */
class FakeSnapshotService implements SnapshotService {

	private final Duration delay;

	private final Set<String> snapshots = ConcurrentHashMap.newKeySet();

	FakeSnapshotService(Duration delay) {
		this.delay = delay;
	}

	@Override
	public Readiness readiness() {
		return Readiness.ok();
	}

	@Override
	public void create(String name, String description) {
		pause();
		snapshots.add(name);
	}

	@Override
	public void remove(String name) {
		pause();
		if (!snapshots.remove(name)) {
			throw new SnapshotException("No snapshot named " + name);
		}
	}

	@Override
	public String revertInstructions(String name) {
		return "Demo mode: in vCenter you would revert to snapshot " + name + " and power the VM on.";
	}

	public Set<String> snapshots() {
		return Set.copyOf(snapshots);
	}

	private void pause() {
		try {
			Thread.sleep(delay);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
	}

}
