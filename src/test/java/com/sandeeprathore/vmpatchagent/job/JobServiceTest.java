package com.sandeeprathore.vmpatchagent.job;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sandeeprathore.vmpatchagent.audit.AuditAction;
import com.sandeeprathore.vmpatchagent.audit.AuditEvent;
import com.sandeeprathore.vmpatchagent.audit.AuditLog;
import com.sandeeprathore.vmpatchagent.inventory.Inventory;
import com.sandeeprathore.vmpatchagent.inventory.InventoryRefreshedEvent;
import com.sandeeprathore.vmpatchagent.inventory.InventoryRefresher;
import com.sandeeprathore.vmpatchagent.inventory.InventoryRepository;
import com.sandeeprathore.vmpatchagent.inventory.SystemInfo;
import com.sandeeprathore.vmpatchagent.security.WindowsAccount;
import com.sandeeprathore.vmpatchagent.vsphere.SnapshotException;
import com.sandeeprathore.vmpatchagent.vsphere.SnapshotService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The demo VM offers two security updates through Windows Update: the OS cumulative update KB5122882 (needs a
 * restart) and .NET KB5126050. With no feed data synced, both appear as plain Windows Update fixes.
 */
@SpringBootTest(properties = "spring.main.allow-bean-definition-overriding=true")
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class JobServiceTest {

	static final WindowsAccount ALICE = new WindowsAccount("CORP\\alice", "S-1-5-21-1", Set.of("S-1-5-32-544"));

	static final String CU = "WINDOWS_UPDATE:KB5122882";

	static final String DOTNET = "WINDOWS_UPDATE:KB5126050";

	@TestConfiguration
	static class Doubles {

		@Bean
		@Primary
		RecordingSnapshots recordingSnapshots() {
			return new RecordingSnapshots();
		}

		/** Same name as the production bean: snapshots run inline so tests see the outcome immediately. */
		@Bean
		Executor jobExecutor() {
			return Runnable::run;
		}

	}

	static class RecordingSnapshots implements SnapshotService {

		final List<String> calls = new ArrayList<>();

		String failWith;

		Readiness readiness = Readiness.ok();

		@Override
		public Readiness readiness() {
			return readiness;
		}

		@Override
		public void create(String name, String description) {
			if (failWith != null) {
				throw new SnapshotException(failWith);
			}
			calls.add("create " + name + " | " + description);
		}

		@Override
		public void remove(String name) {
			calls.add("remove " + name);
		}

		@Override
		public String revertInstructions(String name) {
			return "revert " + name;
		}

	}

	@Autowired
	JobService jobs;

	@Autowired
	JobRepository repository;

	@Autowired
	RecordingSnapshots snapshots;

	@Autowired
	AuditLog audit;

	@Autowired
	InventoryRefresher refresher;

	@Autowired
	InventoryRepository inventories;

	@BeforeEach
	void scan() {
		refresher.refresh();
	}

	@Test
	void approvalSnapshotsTheVmAndRecordsWhoApprovedWhat() {
		var id = jobs.approve(ALICE, List.of(CU, DOTNET), true);

		var job = repository.find(id).orElseThrow();
		assertThat(job.status()).isEqualTo(JobStatus.AWAITING_INSTALL);
		assertThat(job.approvedBy()).isEqualTo("CORP\\alice");
		assertThat(job.osBuildAtApproval()).isEqualTo("10.0.20348.2700");
		assertThat(job.items()).extracting(i -> i.kb()).containsExactly("KB5122882", "KB5126050");
		assertThat(job.snapshotName()).isEqualTo("vpa-job-" + id);
		assertThat(job.hasSnapshot()).isTrue();
		assertThat(snapshots.calls).singleElement()
			.asString()
			.startsWith("create vpa-job-" + id)
			.contains("approved by CORP\\alice")
			.contains("KB5122882");
		assertThat(audit.recent(10)).extracting(AuditEvent::action)
			.containsSubsequence(AuditAction.SNAPSHOT_CREATED, AuditAction.JOB_APPROVED);
	}

	@Test
	void aFixThatMayRestartNeedsExplicitConsent() {
		assertThatThrownBy(() -> jobs.approve(ALICE, List.of(CU), false)).isInstanceOf(JobException.class)
			.hasMessageContaining("Allow restart");
		assertThat(repository.recent(10)).isEmpty();
	}

	@Test
	void refusesFixesThatAreNoLongerInThePlan() {
		assertThatThrownBy(() -> jobs.approve(ALICE, List.of("WINDOWS_UPDATE:KB0000000"), true))
			.isInstanceOf(JobException.class)
			.hasMessageContaining("changed since the page loaded");
	}

	@Test
	void allowsOnlyOneActiveJob() {
		var first = jobs.approve(ALICE, List.of(DOTNET), true);

		assertThatThrownBy(() -> jobs.approve(ALICE, List.of(CU), true)).isInstanceOf(JobException.class)
			.hasMessageContaining("Job #" + first);
	}

	@Test
	void refusesToApproveWhenSnapshotsAreUnavailable() {
		snapshots.readiness = SnapshotService.Readiness.blocked("vSphere is not configured");

		assertThatThrownBy(() -> jobs.approve(ALICE, List.of(DOTNET), true)).isInstanceOf(JobException.class)
			.hasMessageContaining("vSphere is not configured");
		assertThat(repository.recent(10)).isEmpty();
	}

	@Test
	void aFailedSnapshotFailsTheJobAndChangesNothing() {
		snapshots.failWith = "insufficient permissions";

		var id = jobs.approve(ALICE, List.of(DOTNET), true);

		var job = repository.find(id).orElseThrow();
		assertThat(job.status()).isEqualTo(JobStatus.FAILED);
		assertThat(job.statusDetail()).contains("nothing was changed").contains("insufficient permissions");
		assertThat(job.hasSnapshot()).isFalse();
		assertThat(audit.recent(5)).extracting(AuditEvent::action).contains(AuditAction.SNAPSHOT_FAILED);
	}

	@Test
	void theSnapshotCanOnlyBeDeletedOnceTheJobIsNoLongerActive() {
		var id = jobs.approve(ALICE, List.of(DOTNET), true);

		assertThatThrownBy(() -> jobs.deleteSnapshot(ALICE, id)).isInstanceOf(JobException.class);

		jobs.cancel(ALICE, id);
		jobs.deleteSnapshot(ALICE, id);

		var job = repository.find(id).orElseThrow();
		assertThat(job.status()).isEqualTo(JobStatus.CANCELLED);
		assertThat(job.hasSnapshot()).isFalse();
		assertThat(snapshots.calls).last().isEqualTo("remove vpa-job-" + id);
		assertThat(audit.recent(5)).extracting(AuditEvent::action, AuditEvent::actor)
			.contains(org.assertj.core.groups.Tuple.tuple(AuditAction.SNAPSHOT_DELETED, "CORP\\alice"),
					org.assertj.core.groups.Tuple.tuple(AuditAction.JOB_CANCELLED, "CORP\\alice"));
	}

	@Test
	void aBootAfterTheSnapshotPointIsRecognisedAsARevert() {
		var id = leftSnapshotting(Instant.parse("2026-10-02T09:00:00Z"));

		jobs.reconcile(eventWithBootTime(Instant.parse("2026-10-02T11:30:00Z")));

		var job = repository.find(id).orElseThrow();
		assertThat(job.status()).isEqualTo(JobStatus.REVERTED);
		assertThat(job.statusDetail()).contains("most likely reverted").contains("vpa-job-" + id);
		assertThat(audit.recent(5)).extracting(AuditEvent::action).contains(AuditAction.REVERT_DETECTED);
	}

	@Test
	void anAgentRestartWithoutARebootIsReportedAsAnInterruptedSnapshot() {
		var id = leftSnapshotting(Instant.parse("2026-10-02T09:00:00Z"));

		jobs.reconcile(eventWithBootTime(Instant.parse("2026-09-20T03:15:00Z")));

		var job = repository.find(id).orElseThrow();
		assertThat(job.status()).isEqualTo(JobStatus.FAILED);
		assertThat(job.statusDetail()).contains("Check in vCenter");
	}

	/** A job as the database looks inside its own snapshot: snapshot requested, outcome never recorded. */
	private long leftSnapshotting(Instant requestedAt) {
		var id = repository.insert("CORP\\alice", true, "10.0.20348.2700", List.of(), requestedAt);
		repository.markSnapshotRequested(id, "vpa-job-" + id, requestedAt);
		return id;
	}

	private InventoryRefreshedEvent eventWithBootTime(Instant bootTime) {
		var latest = inventories.findLatest().orElseThrow();
		var s = latest.system();
		var system = new SystemInfo(s.hostname(), s.caption(), s.displayVersion(), s.build(), s.ubr(), s.installationType(),
				s.architecture(), s.wsusServer(), bootTime, s.installedUpdates());
		return new InventoryRefreshedEvent(new Inventory(latest.collectedAt(), system, latest.missingUpdates(), latest.apps()));
	}

}
