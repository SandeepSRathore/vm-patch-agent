package com.sandeeprathore.vmpatchagent.feed.kev;

import java.time.LocalDate;
import java.util.List;

import com.sandeeprathore.vmpatchagent.feed.FeedProperties;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Downloads the CISA Known Exploited Vulnerabilities catalog (one JSON file, a few MB). */
@Component
public class KevClient {

	public record Catalog(String catalogVersion, List<Entry> vulnerabilities) {

		public Catalog {
			vulnerabilities = vulnerabilities == null ? List.of() : vulnerabilities;
		}

	}

	public record Entry(String cveID, String vulnerabilityName, LocalDate dateAdded, LocalDate dueDate,
			String knownRansomwareCampaignUse) {
	}

	private final RestClient http;

	private final FeedProperties.Kev properties;

	public KevClient(@Qualifier("feedRestClient") RestClient http, FeedProperties properties) {
		this.http = http;
		this.properties = properties.kev();
	}

	public Catalog fetch() {
		var catalog = http.get().uri(properties.url()).accept(MediaType.APPLICATION_JSON).retrieve().body(Catalog.class);
		if (catalog == null || catalog.vulnerabilities().isEmpty()) {
			throw new IllegalStateException("CISA KEV catalog was empty");
		}
		return catalog;
	}

}
