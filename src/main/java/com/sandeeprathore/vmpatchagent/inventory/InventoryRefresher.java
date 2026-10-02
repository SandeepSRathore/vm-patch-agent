package com.sandeeprathore.vmpatchagent.inventory;

import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Rescans the VM on a schedule and on demand. Only one scan runs at a time; a Windows Update search is slow and
 * running two in parallel just makes both slower.
 */
@Service
public class InventoryRefresher {

	private static final Logger log = LoggerFactory.getLogger(InventoryRefresher.class);

	private final InventoryCollector collector;

	private final InventoryRepository repository;

	private final Clock clock;

	private final ApplicationEventPublisher events;

	private final AtomicBoolean running = new AtomicBoolean();

	private volatile RefreshStatus lastFailure;

	public InventoryRefresher(InventoryCollector collector, InventoryRepository repository, Clock clock,
			ApplicationEventPublisher events) {
		this.collector = collector;
		this.repository = repository;
		this.clock = clock;
		this.events = events;
	}

	/** A failed scan, kept until the next scan succeeds so the dashboard can show it. */
	public record RefreshStatus(Instant failedAt, String message) {
	}

	@Scheduled(initialDelay = 0, fixedDelayString = "${agent.inventory.refresh-interval}")
	public void scheduledRefresh() {
		refresh();
	}

	/** @return false if a scan was already running and this request was skipped */
	public boolean refresh() {
		if (!running.compareAndSet(false, true)) {
			return false;
		}
		try {
			var inventory = collector.collect();
			repository.save(inventory);
			lastFailure = null;
			events.publishEvent(new InventoryRefreshedEvent(inventory));
			log.info("Inventory refreshed: build {}, {} missing security updates, {} apps",
					inventory.system().osBuild(), inventory.missingSecurityUpdates().size(), inventory.apps().size());
		}
		catch (RuntimeException ex) {
			lastFailure = new RefreshStatus(clock.instant(), ex.getMessage());
			log.error("Inventory refresh failed", ex);
		}
		finally {
			running.set(false);
		}
		return true;
	}

	/** Starts a scan in the background so the dashboard request returns straight away. */
	public boolean refreshInBackground() {
		if (running.get()) {
			return false;
		}
		Thread.ofVirtual().name("inventory-refresh").start(this::refresh);
		return true;
	}

	public boolean isRunning() {
		return running.get();
	}

	public RefreshStatus lastFailure() {
		return lastFailure;
	}

}
