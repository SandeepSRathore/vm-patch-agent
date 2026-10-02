package com.sandeeprathore.vmpatchagent.feed.nvd;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sandeeprathore.vmpatchagent.feed.FeedProperties;
import com.sandeeprathore.vmpatchagent.feed.Sleeper;
import com.sandeeprathore.vmpatchagent.inventory.InstalledApp;
import com.sandeeprathore.vmpatchagent.match.AppCatalog;
import com.sandeeprathore.vmpatchagent.match.NvdApplicability;

import org.springframework.stereotype.Service;

/**
 * Fetches NVD CVEs for each catalogued product installed on this VM: everything on first sight, then only CVEs
 * modified since the last successful sync.
 */
@Service
public class NvdSync {

	private static final Logger log = LoggerFactory.getLogger(NvdSync.class);

	/** NVD rejects modification windows longer than 120 days; beyond that, re-read the product in full. */
	private static final Duration MAX_INCREMENTAL_WINDOW = Duration.ofDays(119);

	/** Overlap with the previous window, so a CVE modified while the last sync ran is not missed. */
	private static final Duration OVERLAP = Duration.ofMinutes(15);

	private final NvdClient client;

	private final NvdRepository repository;

	private final AppCatalog catalog;

	private final Duration requestSpacing;

	private final Clock clock;

	private final Sleeper sleeper;

	public NvdSync(NvdClient client, NvdRepository repository, AppCatalog catalog, FeedProperties properties, Clock clock,
			Sleeper sleeper) {
		this.client = client;
		this.repository = repository;
		this.catalog = catalog;
		this.requestSpacing = properties.nvd().requestSpacing();
		this.clock = clock;
		this.sleeper = sleeper;
	}

	/** @return a one-line summary for the dashboard */
	public String sync(Collection<InstalledApp> apps) throws InterruptedException {
		var products = catalog.productsFor(apps);
		var requests = 0;
		var cves = 0L;
		for (var cpe : products) {
			requests += syncProduct(cpe, requests > 0);
			cves += repository.countFor(cpe);
		}
		return "%d tracked products installed, %d CVEs on record for them".formatted(products.size(), cves);
	}

	private int syncProduct(String cpe, boolean paceFirstRequest) throws InterruptedException {
		var until = clock.instant();
		Instant since = repository.syncedUntil(cpe)
			.map(previous -> previous.minus(OVERLAP))
			.filter(previous -> Duration.between(previous, until).compareTo(MAX_INCREMENTAL_WINDOW) < 0)
			.orElse(null);
		if (since == null) {
			repository.clearProduct(cpe);
		}

		var requests = 0;
		var start = 0;
		while (true) {
			if (requests > 0 || paceFirstRequest) {
				sleeper.sleep(requestSpacing);
			}
			var page = client.page(cpe, since, until, start);
			requests++;
			for (var item : page.vulnerabilities()) {
				repository.replace(cpe, item.cve(), NvdApplicability.affectedRanges(item.cve().configurations(), cpe));
			}
			start += page.vulnerabilities().size();
			if (page.vulnerabilities().isEmpty() || start >= page.totalResults()) {
				break;
			}
		}
		repository.markSynced(cpe, until);
		log.info("NVD {}: {} ({} requests)", cpe, since == null ? "full read" : "changes since " + since, requests);
		return requests;
	}

}
