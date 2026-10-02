package com.sandeeprathore.vmpatchagent.feed;

import java.time.Instant;

/**
 * @param lastError message of the most recent failure; cleared by the next success
 * @param summary what the last successful run holds, e.g. "12 documents, 640 fixes for build 20348"
 */
public record FeedStatus(Feed feed, Instant lastAttempt, Instant lastSuccess, String lastError, String summary) {

	public enum Feed {

		MSRC("Microsoft Security Response Center"), NVD("NIST National Vulnerability Database"),
		KEV("CISA Known Exploited Vulnerabilities");

		private final String title;

		Feed(String title) {
			this.title = title;
		}

		public String title() {
			return title;
		}

	}

}
