package com.sandeeprathore.vmpatchagent.web;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import java.util.LinkedHashMap;

import com.sandeeprathore.vmpatchagent.audit.AuditLog;
import com.sandeeprathore.vmpatchagent.feed.FeedStatusRepository;
import com.sandeeprathore.vmpatchagent.feed.FeedWatcher;
import com.sandeeprathore.vmpatchagent.inventory.InventoryRefresher;
import com.sandeeprathore.vmpatchagent.inventory.InventoryRepository;
import com.sandeeprathore.vmpatchagent.job.JobService;
import com.sandeeprathore.vmpatchagent.match.ExposureService;
import com.sandeeprathore.vmpatchagent.vsphere.SnapshotService;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
class DashboardController {

	/** Shown in the VM's own time zone, which is what the admin looking at the VM expects. */
	private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm z")
		.withZone(ZoneId.systemDefault());

	private final InventoryRepository inventories;

	private final InventoryRefresher refresher;

	private final ExposureService exposure;

	private final FeedStatusRepository feedStatuses;

	private final FeedWatcher feeds;

	private final JobService jobs;

	private final SnapshotService snapshots;

	private final AuditLog audit;

	DashboardController(InventoryRepository inventories, InventoryRefresher refresher, ExposureService exposure,
			FeedStatusRepository feedStatuses, FeedWatcher feeds, JobService jobs, SnapshotService snapshots,
			AuditLog audit) {
		this.inventories = inventories;
		this.refresher = refresher;
		this.exposure = exposure;
		this.feedStatuses = feedStatuses;
		this.feeds = feeds;
		this.jobs = jobs;
		this.snapshots = snapshots;
		this.audit = audit;
	}

	/** A feed's state, formatted for display. */
	record FeedRow(String title, String lastSuccess, String lastAttempt, String summary, String error) {
	}

	@GetMapping("/")
	String dashboard(Model model) {
		var inventory = inventories.findLatest().orElse(null);
		model.addAttribute("inventory", inventory);
		model.addAttribute("collectedAt", inventory == null ? null : format(inventory.collectedAt()));
		model.addAttribute("report", exposure.current().orElse(null));
		model.addAttribute("scanRunning", refresher.isRunning());
		model.addAttribute("feedSyncRunning", feeds.isRunning());
		var failure = refresher.lastFailure();
		model.addAttribute("lastFailure", failure);
		model.addAttribute("lastFailureAt", failure == null ? null : format(failure.failedAt()));
		model.addAttribute("feeds", feedStatuses.findAll().values().stream()
			.map(s -> new FeedRow(s.feed().title(), format(s.lastSuccess()), format(s.lastAttempt()), s.summary(),
					s.lastError()))
			.toList());
		var recentJobs = jobs.recent(10);
		var activeJob = recentJobs.stream().filter(j -> j.status().isActive()).findFirst().orElse(null);
		var revertInstructions = new LinkedHashMap<Long, String>();
		recentJobs.stream()
			.filter(j -> j.hasSnapshot())
			.forEach(j -> revertInstructions.put(j.id(), jobs.revertInstructions(j)));
		model.addAttribute("jobs", recentJobs);
		model.addAttribute("activeJob", activeJob);
		model.addAttribute("revertInstructions", revertInstructions);
		model.addAttribute("snapshotReadiness", snapshots.readiness());
		model.addAttribute("auditEvents", audit.recent(30));
		return "dashboard";
	}

	@PostMapping("/inventory/refresh")
	String refresh(RedirectAttributes redirect) {
		redirect.addFlashAttribute("notice", refresher.refreshInBackground()
				? "Scan started. Refresh this page in a minute." : "A scan is already running.");
		return "redirect:/";
	}

	@PostMapping("/feeds/refresh")
	String refreshFeeds(RedirectAttributes redirect) {
		redirect.addFlashAttribute("notice", feeds.syncInBackground()
				? "Feed sync started. The first sync downloads about a year of MSRC data and can take several minutes."
				: "A feed sync is already running.");
		return "redirect:/";
	}

	private static String format(Instant instant) {
		return instant == null ? null : TIMESTAMP.format(instant);
	}

}
