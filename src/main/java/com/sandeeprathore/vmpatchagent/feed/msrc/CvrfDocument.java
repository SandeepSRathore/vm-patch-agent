package com.sandeeprathore.vmpatchagent.feed.msrc;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The parts of an MSRC CVRF v3 monthly document (e.g. {@code /cvrf/v3.0/cvrf/2026-Sep}) this agent reads. MSRC uses
 * PascalCase keys; unknown fields are ignored.
 */
public record CvrfDocument(@JsonProperty("DocumentTracking") Tracking tracking,
		@JsonProperty("ProductTree") ProductTree productTree,
		@JsonProperty("Vulnerability") List<Vulnerability> vulnerabilities) {

	public CvrfDocument {
		vulnerabilities = vulnerabilities == null ? List.of() : vulnerabilities;
	}

	public record Text(@JsonProperty("Value") String value) {
	}

	public record Tracking(@JsonProperty("CurrentReleaseDate") String currentReleaseDate) {
	}

	public record ProductTree(@JsonProperty("FullProductName") List<Product> products) {

		public ProductTree {
			products = products == null ? List.of() : products;
		}

	}

	public record Product(@JsonProperty("ProductID") String productId, @JsonProperty("CPE") String cpe,
			@JsonProperty("Value") String name) {
	}

	public record Vulnerability(@JsonProperty("CVE") String cve, @JsonProperty("Title") Text title,
			@JsonProperty("Threats") List<Threat> threats, @JsonProperty("CVSSScoreSets") List<ScoreSet> scoreSets,
			@JsonProperty("Remediations") List<Remediation> remediations) {

		public Vulnerability {
			threats = threats == null ? List.of() : threats;
			scoreSets = scoreSets == null ? List.of() : scoreSets;
			remediations = remediations == null ? List.of() : remediations;
		}

	}

	/** Type 0 is impact, 1 exploit status, 3 severity. */
	public record Threat(@JsonProperty("Type") int type, @JsonProperty("Description") Text description,
			@JsonProperty("ProductID") List<String> productIds) {

		public static final int EXPLOIT_STATUS = 1;

		public static final int SEVERITY = 3;

		public Threat {
			productIds = productIds == null ? List.of() : productIds;
		}

	}

	public record ScoreSet(@JsonProperty("BaseScore") double baseScore, @JsonProperty("Vector") String vector,
			@JsonProperty("ProductID") List<String> productIds) {

		public ScoreSet {
			productIds = productIds == null ? List.of() : productIds;
		}

	}

	/** Type 2 is a vendor fix; its Description holds the KB number for Windows updates. */
	public record Remediation(@JsonProperty("Type") int type, @JsonProperty("SubType") String subType,
			@JsonProperty("Description") Text description, @JsonProperty("URL") String url,
			@JsonProperty("Supercedence") String supersedes, @JsonProperty("FixedBuild") String fixedBuild,
			@JsonProperty("RestartRequired") Text restartRequired,
			@JsonProperty("ProductID") List<String> productIds) {

		public static final int VENDOR_FIX = 2;

		public Remediation {
			productIds = productIds == null ? List.of() : productIds;
		}

	}

}
