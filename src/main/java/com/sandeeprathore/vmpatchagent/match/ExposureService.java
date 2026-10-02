package com.sandeeprathore.vmpatchagent.match;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.Optional;

import com.sandeeprathore.vmpatchagent.feed.kev.KevRepository;
import com.sandeeprathore.vmpatchagent.feed.msrc.MsrcRepository;
import com.sandeeprathore.vmpatchagent.feed.nvd.NvdRepository;
import com.sandeeprathore.vmpatchagent.inventory.InventoryRepository;
import com.sandeeprathore.vmpatchagent.match.ExposureMatcher.FeedData;

import org.springframework.stereotype.Service;

/** Assesses the latest inventory against whatever feed data is stored right now. */
@Service
public class ExposureService {

	private final InventoryRepository inventories;

	private final MsrcRepository msrc;

	private final NvdRepository nvd;

	private final KevRepository kev;

	private final ExposureMatcher matcher;

	public ExposureService(InventoryRepository inventories, MsrcRepository msrc, NvdRepository nvd, KevRepository kev,
			AppCatalog catalog) {
		this.inventories = inventories;
		this.msrc = msrc;
		this.nvd = nvd;
		this.kev = kev;
		this.matcher = new ExposureMatcher(catalog);
	}

	public Optional<ExposureReport> current() {
		return inventories.findLatest().map(inventory -> {
			var kevDueDates = new HashMap<String, LocalDate>();
			kev.all().forEach((cve, entry) -> kevDueDates.put(cve, entry.dueDate() != null ? entry.dueDate()
					: entry.dateAdded() != null ? entry.dateAdded() : LocalDate.MIN));
			var feeds = new FeedData(msrc.fixes(), !msrc.documents().isEmpty(), nvd.cvesByProduct(),
					nvd.syncedProducts(), kevDueDates);
			return matcher.assess(inventory, feeds);
		});
	}

}
