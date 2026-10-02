package com.sandeeprathore.vmpatchagent.job;

import java.time.Clock;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sandeeprathore.vmpatchagent.audit.AuditAction;
import com.sandeeprathore.vmpatchagent.audit.AuditLog;
import com.sandeeprathore.vmpatchagent.inventory.InventoryRefreshedEvent;
import com.sandeeprathore.vmpatchagent.inventory.InventoryRepository;
import com.sandeeprathore.vmpatchagent.match.ExposureService;
import com.sandeeprathore.vmpatchagent.match.RemediationItem;
import com.sandeeprathore.vmpatchagent.security.WindowsAccount;
import com.sandeeprathore.vmpatchagent.vsphere.SnapshotException;
import com.sandeeprathore.vmpatchagent.vsphere.SnapshotService;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

/**
 * Approvals and the snapshot that must exist before anything changes on the VM.
 * <p>
 * The job is set to {@code SNAPSHOTTING} and flushed to disk before vSphere is asked for the snapshot, so the snapshot
 * holds the database in that state. If the VM is later reverted, it boots with this job still "snapshotting" and a
 * boot time after the request: {@link #reconcile} recognises that as a revert.
 */
@Service
public class JobService {

	private static final Logger log = LoggerFactory.getLogger(JobService.class);

	private static final int MAX_SNAPSHOT_DESCRIPTION = 900;

	private final JobRepository jobs;

	private final ExposureService exposure;

	private final InventoryRepository inventories;

	private final SnapshotService snapshots;

	private final AuditLog audit;

	private final Clock clock;

	private final Executor executor;

	/** Jobs whose snapshot this process is taking right now, as opposed to ones left over from before a restart. */
	private final Set<Long> inFlight = ConcurrentHashMap.newKeySet();

	public JobService(JobRepository jobs, ExposureService exposure, InventoryRepository inventories,
			SnapshotService snapshots, AuditLog audit, Clock clock, @Qualifier("jobExecutor") Executor executor) {
		this.jobs = jobs;
		this.exposure = exposure;
		this.inventories = inventories;
		this.snapshots = snapshots;
		this.audit = audit;
		this.clock = clock;
		this.executor = executor;
	}

	/**
	 * Records the approval of exactly the fixes the approver ticked, then snapshots the VM in the background.
	 * @param itemKeys {@link RemediationItem#key()} of each ticked fix
	 */
	public synchronized long approve(WindowsAccount approver, Collection<String> itemKeys, boolean allowReboot) {
		var keys = new LinkedHashSet<>(itemKeys);
		if (keys.isEmpty()) {
			throw new JobException("Tick at least one fix to approve.");
		}
		var readiness = snapshots.readiness();
		if (!readiness.ready()) {
			throw new JobException("Cannot approve: " + readiness.reason());
		}
		jobs.findActive().ifPresent(active -> {
			throw new JobException("Job #" + active.id() + " is still " + active.status().label().toLowerCase()
					+ ". Finish or cancel it first.");
		});
		var inventory = inventories.findLatest().orElseThrow(() -> new JobException("No inventory scan yet."));
		var report = exposure.current().orElseThrow(() -> new JobException("No inventory scan yet."));
		var selected = report.plan().stream().filter(item -> keys.contains(item.key())).toList();
		if (selected.size() != keys.size()) {
			throw new JobException("The list of fixes changed since the page loaded. Reload and approve again.");
		}
		var rebootNeeded = selected.stream().anyMatch(RemediationItem::rebootLikely);
		if (rebootNeeded && !allowReboot) {
			throw new JobException("A selected fix may restart the VM. Tick \"Allow restart\" to approve it.");
		}

		var id = jobs.insert(approver.name(), allowReboot, inventory.system().windowsVersion(), selected, clock.instant());
		audit.record(approver.name(), AuditAction.JOB_APPROVED, id, "%s; restart %s; %d CVEs".formatted(
				describe(selected), allowReboot ? "allowed" : "not allowed",
				selected.stream().flatMap(i -> i.cves().stream()).map(c -> c.cve()).distinct().count()));
		inFlight.add(id);
		executor.execute(() -> takeSnapshot(id));
		return id;
	}

	void takeSnapshot(long id) {
		try {
			var job = jobs.find(id).orElseThrow();
			var name = "vpa-job-" + id;
			jobs.markSnapshotRequested(id, name, clock.instant());
			jobs.flushToDisk();
			var description = "VmPatchAgent job %d, approved by %s: %s".formatted(id, job.approvedBy(),
					describe(job.items()));
			snapshots.create(name, description.length() > MAX_SNAPSHOT_DESCRIPTION
					? description.substring(0, MAX_SNAPSHOT_DESCRIPTION) + "…" : description);
			jobs.markSnapshotCreated(id, clock.instant());
			audit.record(AuditLog.SYSTEM, AuditAction.SNAPSHOT_CREATED, id, name);
		}
		catch (RuntimeException ex) {
			log.error("Snapshot for job {} failed", id, ex);
			jobs.updateStatus(id, JobStatus.FAILED, "Snapshot failed, nothing was changed: " + ex.getMessage(),
					clock.instant());
			audit.record(AuditLog.SYSTEM, AuditAction.SNAPSHOT_FAILED, id, ex.getMessage());
		}
		finally {
			inFlight.remove(id);
		}
	}

	public synchronized void cancel(WindowsAccount actor, long id) {
		var job = jobs.find(id).orElseThrow(() -> new JobException("No job #" + id));
		if (!job.canCancel()) {
			throw new JobException("Job #" + id + " cannot be cancelled while " + job.status().label().toLowerCase() + ".");
		}
		jobs.updateStatus(id, JobStatus.CANCELLED, "Cancelled by " + actor.name(), clock.instant());
		audit.record(actor.name(), AuditAction.JOB_CANCELLED, id, null);
	}

	public void deleteSnapshot(WindowsAccount actor, long id) {
		var job = jobs.find(id).orElseThrow(() -> new JobException("No job #" + id));
		if (!job.canDeleteSnapshot()) {
			throw new JobException("Job #" + id + " has no snapshot that can be deleted now.");
		}
		try {
			snapshots.remove(job.snapshotName());
		}
		catch (SnapshotException ex) {
			audit.record(actor.name(), AuditAction.SNAPSHOT_DELETE_FAILED, id, ex.getMessage());
			throw new JobException("Could not delete snapshot " + job.snapshotName() + ": " + ex.getMessage());
		}
		jobs.markSnapshotRemoved(id, clock.instant());
		audit.record(actor.name(), AuditAction.SNAPSHOT_DELETED, id, job.snapshotName());
	}

	public String revertInstructions(RemediationJob job) {
		return job.hasSnapshot() ? snapshots.revertInstructions(job.snapshotName()) : null;
	}

	/**
	 * Settles jobs left in {@code SNAPSHOTTING} by an earlier run. Runs after each scan because it needs the boot time.
	 * <ul>
	 * <li>Windows started after the snapshot was requested: the VM most likely came back from this job's snapshot (an
	 * admin reverted it in vCenter).</li>
	 * <li>Otherwise the agent itself restarted mid-snapshot; whether the snapshot exists must be checked in
	 * vCenter.</li>
	 * </ul>
	 */
	@EventListener
	public synchronized void reconcile(InventoryRefreshedEvent event) {
		var bootTime = event.inventory().system().lastBootTime();
		for (var job : jobs.withStatus(JobStatus.SNAPSHOTTING)) {
			if (inFlight.contains(job.id())) {
				continue;
			}
			if (bootTime != null && job.snapshotRequestedAt() != null && bootTime.isAfter(job.snapshotRequestedAt())) {
				var detail = ("Windows started at %s, after snapshot %s was taken: the VM was most likely reverted to it. "
						+ "Records made after the snapshot were lost with the revert; vCenter's task history shows who "
						+ "reverted it.").formatted(bootTime, job.snapshotName());
				jobs.updateStatus(job.id(), JobStatus.REVERTED, detail, clock.instant());
				audit.record(AuditLog.SYSTEM, AuditAction.REVERT_DETECTED, job.id(), detail);
			}
			else {
				var detail = "The agent restarted while snapshot %s was being taken. Check in vCenter whether it exists."
					.formatted(job.snapshotName());
				jobs.updateStatus(job.id(), JobStatus.FAILED, detail, clock.instant());
				audit.record(AuditLog.SYSTEM, AuditAction.JOB_FAILED, job.id(), detail);
			}
		}
	}

	public List<RemediationJob> recent(int limit) {
		return jobs.recent(limit);
	}

	private static String describe(List<RemediationItem> items) {
		return items.stream()
			.map(i -> i.kb() != null ? i.kb()
					: i.title() + (i.targetVersion() != null ? " to " + i.targetVersion() : ""))
			.collect(Collectors.joining(", "));
	}

}
