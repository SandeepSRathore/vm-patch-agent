package com.sandeeprathore.vmpatchagent.feed;

import java.time.Clock;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sandeeprathore.vmpatchagent.feed.FeedStatus.Feed;
import com.sandeeprathore.vmpatchagent.feed.kev.KevClient;
import com.sandeeprathore.vmpatchagent.feed.kev.KevRepository;
import com.sandeeprathore.vmpatchagent.feed.msrc.MsrcRepository;
import com.sandeeprathore.vmpatchagent.feed.msrc.MsrcSync;
import com.sandeeprathore.vmpatchagent.feed.nvd.NvdSync;
import com.sandeeprathore.vmpatchagent.inventory.InventoryRefreshedEvent;
import com.sandeeprathore.vmpatchagent.inventory.InventoryRepository;

import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Refreshes the three feeds on a schedule, and straight after a scan when the feeds have never run or the VM's build
 * line changed. Feeds fail independently: an NVD outage does not stop Windows findings.
 */
@Service
public class FeedWatcher {

	private static final Logger log = LoggerFactory.getLogger(FeedWatcher.class);

	private final InventoryRepository inventories;

	private final MsrcSync msrc;

	private final MsrcRepository msrcRepository;

	private final NvdSync nvd;

	private final KevClient kevClient;

	private final KevRepository kevRepository;

	private final FeedStatusRepository statuses;

	private final FeedProperties properties;

	private final Clock clock;

	private final AtomicBoolean running = new AtomicBoolean();

	public FeedWatcher(InventoryRepository inventories, MsrcSync msrc, MsrcRepository msrcRepository, NvdSync nvd,
			KevClient kevClient, KevRepository kevRepository, FeedStatusRepository statuses, FeedProperties properties,
			Clock clock) {
		this.inventories = inventories;
		this.msrc = msrc;
		this.msrcRepository = msrcRepository;
		this.nvd = nvd;
		this.kevClient = kevClient;
		this.kevRepository = kevRepository;
		this.statuses = statuses;
		this.properties = properties;
		this.clock = clock;
	}

	@Scheduled(initialDelayString = "${agent.feeds.refresh-interval}", fixedDelayString = "${agent.feeds.refresh-interval}")
	public void scheduledSync() {
		syncAll();
	}

	@EventListener
	public void onInventoryRefreshed(InventoryRefreshedEvent event) {
		if (!properties.syncOnScan()) {
			return;
		}
		var build = event.inventory().system().build();
		var neverSynced = statuses.findAll().values().stream().anyMatch(s -> s.lastSuccess() == null);
		var buildChanged = msrcRepository.documents().values().stream().anyMatch(d -> d.osBuild() != build);
		if (neverSynced || buildChanged) {
			syncInBackground();
		}
	}

	public boolean syncInBackground() {
		if (running.get()) {
			return false;
		}
		Thread.ofVirtual().name("feed-sync").start(this::syncAll);
		return true;
	}

	public boolean isRunning() {
		return running.get();
	}

	/** @return false if a sync was already running */
	public boolean syncAll() {
		if (!running.compareAndSet(false, true)) {
			return false;
		}
		try {
			syncKevIfDue();
			var inventory = inventories.findLatest();
			if (inventory.isEmpty()) {
				log.info("Skipping MSRC and NVD until the first inventory scan completes");
				return true;
			}
			run(Feed.MSRC, () -> msrc.sync(inventory.get().system()));
			run(Feed.NVD, () -> nvd.sync(inventory.get().apps()));
			return true;
		}
		finally {
			running.set(false);
		}
	}

	private void syncKevIfDue() {
		var lastSuccess = statuses.findAll().get(Feed.KEV).lastSuccess();
		if (lastSuccess != null && lastSuccess.plus(properties.kev().refreshInterval()).isAfter(clock.instant())) {
			return;
		}
		run(Feed.KEV, () -> {
			var catalog = kevClient.fetch();
			kevRepository.replaceAll(catalog.vulnerabilities());
			return "catalog %s, %d CVEs".formatted(catalog.catalogVersion(), catalog.vulnerabilities().size());
		});
	}

	@FunctionalInterface
	private interface FeedRun {

		String run() throws Exception;

	}

	private void run(Feed feed, FeedRun sync) {
		try {
			var summary = sync.run();
			statuses.recordSuccess(feed, clock.instant(), summary);
			log.info("{} feed: {}", feed, summary);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			statuses.recordFailure(feed, clock.instant(), "interrupted");
		}
		catch (Exception ex) {
			statuses.recordFailure(feed, clock.instant(), ex.getClass().getSimpleName() + ": " + ex.getMessage());
			log.error("{} feed failed", feed, ex);
		}
	}

}
