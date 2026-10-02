package com.sandeeprathore.vmpatchagent.feed.nvd;

import java.util.List;

/** The parts of an NVD CVE API 2.0 response this agent reads. Unknown fields are ignored. */
public record NvdCveResponse(int resultsPerPage, int startIndex, int totalResults, List<Item> vulnerabilities) {

	public NvdCveResponse {
		vulnerabilities = vulnerabilities == null ? List.of() : vulnerabilities;
	}

	public record Item(Cve cve) {
	}

	public record Cve(String id, String published, String lastModified, String vulnStatus,
			List<Description> descriptions, Metrics metrics, List<Configuration> configurations) {

		public Cve {
			descriptions = descriptions == null ? List.of() : descriptions;
			configurations = configurations == null ? List.of() : configurations;
		}

		public boolean isRejected() {
			return "Rejected".equalsIgnoreCase(vulnStatus);
		}

		public String englishDescription() {
			return descriptions.stream().filter(d -> "en".equals(d.lang())).map(Description::value).findFirst()
				.orElse("");
		}

		/** Highest-version CVSS base score NVD has: v4.0, then v3.1, v3.0, v2. Null if none. */
		public Double baseScore() {
			return metrics == null ? null : metrics.bestBaseScore();
		}

	}

	public record Description(String lang, String value) {
	}

	public record Metrics(List<Metric> cvssMetricV40, List<Metric> cvssMetricV31, List<Metric> cvssMetricV30,
			List<Metric> cvssMetricV2) {

		Double bestBaseScore() {
			for (var metrics : java.util.Arrays.asList(cvssMetricV40, cvssMetricV31, cvssMetricV30, cvssMetricV2)) {
				if (metrics == null || metrics.isEmpty()) {
					continue;
				}
				// Prefer NVD's own ("Primary") score over a CNA's when both exist.
				return metrics.stream().filter(m -> "Primary".equals(m.type())).findFirst().orElse(metrics.getFirst())
					.cvssData()
					.baseScore();
			}
			return null;
		}

	}

	public record Metric(String source, String type, CvssData cvssData) {
	}

	public record CvssData(String version, String vectorString, double baseScore) {
	}

	public record Configuration(String operator, Boolean negate, List<Node> nodes) {

		public Configuration {
			nodes = nodes == null ? List.of() : nodes;
		}

	}

	public record Node(String operator, Boolean negate, List<CpeMatch> cpeMatch) {

		public Node {
			cpeMatch = cpeMatch == null ? List.of() : cpeMatch;
		}

	}

	public record CpeMatch(boolean vulnerable, String criteria, String versionStartIncluding,
			String versionStartExcluding, String versionEndIncluding, String versionEndExcluding) {
	}

}
