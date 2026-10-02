package com.sandeeprathore.vmpatchagent.feed;

import java.net.URI;
import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Vulnerability feed settings, bound from {@code agent.feeds.*}.
 *
 * @param syncOnScan sync straight after an inventory scan when the feeds have never run or the build changed
 */
@ConfigurationProperties("agent.feeds")
public record FeedProperties(@DefaultValue("2h") Duration refreshInterval, @DefaultValue("60s") Duration httpTimeout,
		@DefaultValue("true") boolean syncOnScan,
		@DefaultValue Msrc msrc, @DefaultValue Nvd nvd, @DefaultValue Kev kev) {

	/**
	 * @param lookbackMonths how many monthly documents to keep; a VM more than this far behind still gets its OS
	 * findings from newer documents, because cumulative updates carry every older fix
	 * @param unindexedRecheck how often to re-read a document the MSRC index does not list (the index lags)
	 */
	public record Msrc(@DefaultValue("https://api.msrc.microsoft.com/cvrf/v3.0") URI baseUrl,
			@DefaultValue("12") int lookbackMonths, @DefaultValue("24h") Duration unindexedRecheck) {
	}

	/**
	 * @param apiKey optional; without one NVD allows 5 requests per 30 seconds, so the agent waits 6 seconds between
	 * requests
	 */
	public record Nvd(@DefaultValue("https://services.nvd.nist.gov/rest/json/cves/2.0") URI baseUrl, String apiKey,
			@DefaultValue("2000") int pageSize) {

		public Duration requestSpacing() {
			return apiKey == null || apiKey.isBlank() ? Duration.ofSeconds(6) : Duration.ofMillis(700);
		}

	}

	public record Kev(
			@DefaultValue("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json") URI url,
			@DefaultValue("24h") Duration refreshInterval) {
	}

}
