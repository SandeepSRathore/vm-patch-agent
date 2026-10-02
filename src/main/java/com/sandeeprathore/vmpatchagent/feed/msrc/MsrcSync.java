package com.sandeeprathore.vmpatchagent.feed.msrc;

import java.time.Clock;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sandeeprathore.vmpatchagent.feed.FeedProperties;
import com.sandeeprathore.vmpatchagent.feed.msrc.MsrcRepository.StoredDocument;
import com.sandeeprathore.vmpatchagent.inventory.SystemInfo;

import org.springframework.stereotype.Service;

/**
 * Keeps the last {@code lookbackMonths} MSRC monthly documents, filtered to this VM's Windows build.
 * <p>
 * A document is (re)read when it is new, when MSRC's index shows a newer revision, or when the VM's build line changed.
 * The index has been seen to omit recent months, so months it does not list are probed directly and re-read at most
 * every {@code unindexedRecheck}.
 */
@Service
public class MsrcSync {

	private static final Logger log = LoggerFactory.getLogger(MsrcSync.class);

	private static final String[] MONTHS = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
			"Nov", "Dec" };

	private final MsrcClient client;

	private final MsrcRepository repository;

	private final FeedProperties.Msrc properties;

	private final Clock clock;

	public MsrcSync(MsrcClient client, MsrcRepository repository, FeedProperties properties, Clock clock) {
		this.client = client;
		this.repository = repository;
		this.properties = properties.msrc();
		this.clock = clock;
	}

	/** @return a one-line summary for the dashboard */
	public String sync(SystemInfo system) {
		var now = clock.instant();
		var window = documentIds(YearMonth.now(clock.withZone(ZoneOffset.UTC)), properties.lookbackMonths());
		var index = new HashMap<String, String>();
		client.index().forEach(entry -> index.put(entry.id(), entry.currentReleaseDate()));
		var stored = repository.documents();

		var fetched = 0;
		for (var id : window) {
			var previous = stored.get(id);
			var indexedDate = index.get(id);
			if (previous != null && !isDue(previous, indexedDate, system, now)) {
				continue;
			}
			var document = client.document(id);
			if (document.isEmpty()) {
				continue;
			}
			var fixes = MsrcRelevance.fixesFor(document.get(), id, system);
			var releaseDate = indexedDate != null ? indexedDate
					: document.get().tracking() == null ? null : document.get().tracking().currentReleaseDate();
			repository.replaceDocument(new StoredDocument(id, releaseDate, system.build(), now), fixes);
			log.info("MSRC {}: {} fixes relevant to build {}", id, fixes.size(), system.build());
			fetched++;
		}
		repository.retainOnly(window);

		var documents = repository.documents().size();
		var osFixes = repository.fixes().stream().filter(MsrcFix::osProduct).count();
		return "%d monthly documents (%d updated this run), %d Windows fixes for build %d".formatted(documents, fetched,
				osFixes, system.build());
	}

	private boolean isDue(StoredDocument previous, String indexedDate, SystemInfo system, java.time.Instant now) {
		if (previous.osBuild() != system.build()) {
			return true;
		}
		if (indexedDate != null) {
			return !indexedDate.equals(previous.releaseDate());
		}
		return previous.fetchedAt().plus(properties.unindexedRecheck()).isBefore(now);
	}

	/** MSRC document IDs, newest first, e.g. {@code 2026-Oct, 2026-Sep, ...}. */
	static List<String> documentIds(YearMonth current, int months) {
		var ids = new ArrayList<String>();
		for (var i = 0; i < months; i++) {
			var month = current.minusMonths(i);
			ids.add(month.getYear() + "-" + MONTHS[month.getMonthValue() - 1]);
		}
		return ids;
	}

}
