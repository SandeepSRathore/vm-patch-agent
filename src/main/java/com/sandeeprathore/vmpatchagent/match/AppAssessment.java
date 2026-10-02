package com.sandeeprathore.vmpatchagent.match;

import com.sandeeprathore.vmpatchagent.inventory.InstalledApp;

/**
 * @param label the catalog's name for the product; null when not tracked
 * @param note why the status is what it is, when that is not obvious
 */
public record AppAssessment(InstalledApp app, String label, Status status, int openCves, String note) {

	public enum Status {

		VULNERABLE("Vulnerable"), OK("No known CVEs"), CANNOT_ASSESS("Cannot assess"),
		AWAITING_FEED("Waiting for NVD"), NOT_TRACKED("Not tracked");

		private final String label;

		Status(String label) {
			this.label = label;
		}

		public String label() {
			return label;
		}

	}

}
