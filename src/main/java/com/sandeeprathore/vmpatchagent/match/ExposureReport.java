package com.sandeeprathore.vmpatchagent.match;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * What is open on this VM and how to close it.
 *
 * @param warnings coverage gaps the admin must know about, e.g. an OS build MSRC no longer lists
 */
public record ExposureReport(List<RemediationItem> plan, List<AppAssessment> apps, List<String> warnings) {

	public Set<String> openCves() {
		return plan.stream().flatMap(item -> item.cves().stream()).map(CveFinding::cve).collect(Collectors.toSet());
	}

	public long exploitedCount() {
		return plan.stream()
			.flatMap(item -> item.cves().stream())
			.filter(CveFinding::activelyExploited)
			.map(CveFinding::cve)
			.distinct()
			.count();
	}

}
