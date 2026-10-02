package com.sandeeprathore.vmpatchagent.match;

import java.time.LocalDate;

/**
 * One open CVE on this VM.
 *
 * @param severity MSRC's rating (Critical/Important/...) or one derived from NVD's CVSS score
 * @param exploitedPerMsrc MSRC reports exploitation detected
 * @param kevDueDate set when the CVE is in CISA's Known Exploited Vulnerabilities catalog
 */
public record CveFinding(String cve, String title, String severity, Double cvss, boolean exploitedPerMsrc,
		LocalDate kevDueDate) {

	public boolean inKev() {
		return kevDueDate != null;
	}

	public boolean activelyExploited() {
		return exploitedPerMsrc || inKev();
	}

	public Priority priority() {
		return Priority.of(severity, cvss, activelyExploited());
	}

	public String nvdUrl() {
		return "https://nvd.nist.gov/vuln/detail/" + cve;
	}

	static String severityFromCvss(Double cvss) {
		if (cvss == null) {
			return null;
		}
		return cvss >= 9.0 ? "Critical" : cvss >= 7.0 ? "High" : cvss >= 4.0 ? "Medium" : cvss > 0 ? "Low" : null;
	}

}
