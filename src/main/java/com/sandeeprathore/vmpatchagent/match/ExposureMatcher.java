package com.sandeeprathore.vmpatchagent.match;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.sandeeprathore.vmpatchagent.feed.msrc.MsrcFix;
import com.sandeeprathore.vmpatchagent.feed.nvd.NvdRepository.ProductCve;
import com.sandeeprathore.vmpatchagent.inventory.InstalledApp;
import com.sandeeprathore.vmpatchagent.inventory.Inventory;
import com.sandeeprathore.vmpatchagent.inventory.MissingUpdate;
import com.sandeeprathore.vmpatchagent.match.AppAssessment.Status;
import com.sandeeprathore.vmpatchagent.match.RemediationItem.Kind;

/**
 * Joins one inventory with the feeds and proposes fixes. Pure and deterministic: the same inputs always give the same
 * plan, and nothing here decides to install anything.
 * <p>
 * Windows is judged two ways:
 * <ul>
 * <li><b>By build.</b> MSRC states the Windows build each CVE is fixed in. If this VM's build is lower, the CVE is
 * open, whether or not Windows Update (or WSUS) currently offers the fix.</li>
 * <li><b>By missing KB.</b> Every security update the VM's own Windows Update scan offers becomes a fix, with the CVEs
 * MSRC attaches to that KB. This covers components such as .NET Framework whose versions MSRC does not state in a
 * comparable form.</li>
 * </ul>
 */
public final class ExposureMatcher {

	/**
	 * @param msrcSynced at least one MSRC document has been read, so an empty fix list means "no product matched"
	 * @param nvdSyncedProducts CPE products NVD has been read for; others are "waiting for NVD"
	 */
	public record FeedData(List<MsrcFix> msrcFixes, boolean msrcSynced, Map<String, List<ProductCve>> nvd,
			Set<String> nvdSyncedProducts, Map<String, LocalDate> kevDueDates) {
	}

	private final AppCatalog catalog;

	public ExposureMatcher(AppCatalog catalog) {
		this.catalog = catalog;
	}

	public ExposureReport assess(Inventory inventory, FeedData feeds) {
		var plan = new ArrayList<RemediationItem>();
		var warnings = new ArrayList<String>();
		var missingByKb = new LinkedHashMap<String, MissingUpdate>();
		inventory.missingSecurityUpdates().forEach(u -> u.kbs().forEach(kb -> missingByKb.putIfAbsent(kb, u)));

		var osItem = windowsCumulative(inventory, feeds, missingByKb, warnings);
		var handledKbs = new HashSet<String>();
		osItem.ifPresent(item -> {
			plan.add(item);
			handledKbs.add(item.kb());
			offeredCumulativeUpdate(missingByKb).ifPresent(u -> handledKbs.addAll(u.kbs()));
		});
		plan.addAll(otherWindowsUpdates(inventory, feeds, handledKbs));

		var apps = new ArrayList<AppAssessment>();
		for (var app : inventory.apps()) {
			assessApp(app, feeds, apps, plan);
		}

		plan.sort(Comparator.comparing(RemediationItem::priority)
			.thenComparing(item -> -item.cves().size())
			.thenComparing(RemediationItem::title));
		apps.sort(Comparator.comparing(AppAssessment::status).thenComparing(a -> a.app().name()));
		return new ExposureReport(List.copyOf(plan), List.copyOf(apps), List.copyOf(warnings));
	}

	private Optional<RemediationItem> windowsCumulative(Inventory inventory, FeedData feeds,
			Map<String, MissingUpdate> missingByKb, List<String> warnings) {
		var system = inventory.system();
		var installed = Version.parse(system.windowsVersion());
		var buildPrefix = "10.0." + system.build() + ".";
		var osFixes = feeds.msrcFixes().stream()
			.filter(MsrcFix::osProduct)
			.filter(f -> f.fixedBuild() != null && f.fixedBuild().startsWith(buildPrefix))
			.toList();
		if (feeds.msrcSynced() && osFixes.isEmpty()) {
			warnings.add(("MSRC lists no fixes for %s build %d in the months read. The OS may be out of support. "
					+ "Windows findings below come only from Windows Update.").formatted(system.caption(), system.build()));
			return Optional.empty();
		}

		// A CVE is closed once the VM reaches the lowest build that fixes it.
		var lowestFix = new LinkedHashMap<String, MsrcFix>();
		for (var fix : osFixes) {
			lowestFix.merge(fix.cve(), fix, (a, b) -> Version.parse(a.fixedBuild()).compareTo(Version.parse(b.fixedBuild())) <= 0 ? a : b);
		}
		var open = lowestFix.values().stream().filter(f -> installed.isBefore(Version.parse(f.fixedBuild()))).toList();
		if (open.isEmpty()) {
			return Optional.empty();
		}

		var latest = osFixes.stream().max(Comparator.comparing(f -> Version.parse(f.fixedBuild()))).orElseThrow();
		var findings = open.stream().map(f -> finding(f, feeds)).toList();
		var offered = missingByKb.containsKey(latest.kb());
		String note = null;
		if (!offered) {
			var alternative = offeredCumulativeUpdate(missingByKb);
			if (alternative.isPresent()) {
				// Only claim the offered update covers these CVEs when MSRC says it reaches the same build.
				var alternativeKbs = String.join(", ", alternative.get().kbs());
				var alternativeBuild = osFixes.stream()
					.filter(f -> alternative.get().kbs().contains(f.kb()))
					.map(f -> Version.parse(f.fixedBuild()))
					.max(Comparator.naturalOrder());
				var latestBuild = Version.parse(latest.fixedBuild());
				if (alternativeBuild.isEmpty()) {
					note = "Windows Update offers " + alternativeKbs + ", which is not in the MSRC data, so whether it "
							+ "fixes these CVEs cannot be verified. Install " + latest.kb() + " or later.";
				}
				else if (alternativeBuild.get().isBefore(latestBuild)) {
					var leftOpen = open.stream()
						.filter(f -> Version.parse(f.fixedBuild()).compareTo(alternativeBuild.get()) > 0)
						.count();
					note = ("Windows Update offers %s (build %s), which is older and leaves %d of these CVEs open. %s")
						.formatted(alternativeKbs, alternativeBuild.get(), leftOpen,
								system.wsusServer() != null ? latest.kb() + " may need approving in WSUS." : "");
				}
				else {
					note = "Windows Update offers " + alternativeKbs + ", which is the same build or newer.";
					offered = true;
				}
			}
			else if (system.wsusServer() != null) {
				note = "WSUS (" + system.wsusServer() + ") does not offer " + latest.kb()
						+ " to this VM yet. It may need approving in WSUS.";
			}
			else {
				note = "Windows Update has not offered " + latest.kb() + " to this VM yet. Rescan later.";
			}
		}
		return Optional.of(new RemediationItem(Kind.WINDOWS_CUMULATIVE, "Windows cumulative update " + latest.kb(),
				latest.kb(), null, system.windowsVersion(), latest.fixedBuild(), true, offered, note, findings,
				Priority.OTHER));
	}

	/**
	 * The OS cumulative update in the Windows Update scan, recognised by title because WUA has no field for it.
	 * .NET Framework cumulative updates are excluded; they are separate fixes.
	 */
	private static Optional<MissingUpdate> offeredCumulativeUpdate(Map<String, MissingUpdate> missingByKb) {
		return missingByKb.values().stream()
			.filter(u -> u.title() != null && u.title().contains("Cumulative Update for")
					&& !u.title().contains(".NET"))
			.findFirst();
	}

	private List<RemediationItem> otherWindowsUpdates(Inventory inventory, FeedData feeds, Set<String> handledKbs) {
		var items = new ArrayList<RemediationItem>();
		for (var update : inventory.missingSecurityUpdates()) {
			if (update.kbs().stream().anyMatch(handledKbs::contains)) {
				continue;
			}
			var findings = new LinkedHashMap<String, CveFinding>();
			feeds.msrcFixes().stream()
				.filter(f -> update.kbs().contains(f.kb()))
				.forEach(f -> findings.putIfAbsent(f.cve(), finding(f, feeds)));
			for (var cve : update.cveIds()) {
				findings.putIfAbsent(cve, new CveFinding(cve, null, update.msrcSeverity(), null, false,
						feeds.kevDueDates().get(cve)));
			}
			var kb = update.kbs().isEmpty() ? null : update.kbs().getFirst();
			items.add(new RemediationItem(Kind.WINDOWS_UPDATE, update.title(), kb, null, null, null,
					update.mayRequireReboot(), true, null, List.copyOf(findings.values()),
					Priority.of(update.msrcSeverity(), null, false)));
		}
		return items;
	}

	private void assessApp(InstalledApp app, FeedData feeds, List<AppAssessment> assessments,
			List<RemediationItem> plan) {
		var entry = catalog.lookup(app);
		if (entry.isEmpty()) {
			assessments.add(new AppAssessment(app, null, Status.NOT_TRACKED, 0, null));
			return;
		}
		var label = entry.get().label();
		var cpe = entry.get().cpe();
		var installed = Version.tryParse(app.version());
		if (installed.isEmpty()) {
			assessments.add(new AppAssessment(app, label, Status.CANNOT_ASSESS, 0,
					"Version \"" + app.version() + "\" is not numeric"));
			return;
		}
		if (!feeds.nvdSyncedProducts().contains(cpe)) {
			assessments.add(new AppAssessment(app, label, Status.AWAITING_FEED, 0, null));
			return;
		}

		var findings = new ArrayList<CveFinding>();
		Version target = null;
		String targetText = null;
		var unboundedFix = false;
		var unassessable = 0;
		for (var cve : feeds.nvd().getOrDefault(cpe, List.of())) {
			var containing = cve.ranges().stream().filter(r -> r.contains(installed.get()).orElse(false)).toList();
			if (containing.isEmpty()) {
				if (cve.ranges().stream().anyMatch(r -> r.contains(installed.get()).isEmpty())) {
					unassessable++;
				}
				continue;
			}
			findings.add(new CveFinding(cve.cve(), cve.summary(), CveFinding.severityFromCvss(cve.cvss()), cve.cvss(),
					false, feeds.kevDueDates().get(cve.cve())));
			// The fix for this CVE is the lowest end bound among ranges containing the installed version.
			// Kept as NVD writes it: 7-Zip's "24.09" must not be shown as "24.9".
			var fixedIn = containing.stream()
				.map(AffectedRange::fixedIn)
				.flatMap(Optional::stream)
				.filter(text -> Version.tryParse(text).isPresent())
				.min(Comparator.comparing(Version::parse));
			if (fixedIn.isEmpty()) {
				unboundedFix = true;
			}
			else if (target == null || target.isBefore(Version.parse(fixedIn.get()))) {
				target = Version.parse(fixedIn.get());
				targetText = fixedIn.get();
			}
		}

		String note = unassessable > 0 ? unassessable + " CVEs have version ranges that could not be compared" : null;
		if (findings.isEmpty()) {
			assessments.add(new AppAssessment(app, label, unassessable > 0 ? Status.CANNOT_ASSESS : Status.OK, 0, note));
			return;
		}
		assessments.add(new AppAssessment(app, label, Status.VULNERABLE, findings.size(), note));

		var wingetId = entry.get().wingetId() == null || entry.get().wingetId().isBlank() ? null : entry.get().wingetId();
		var notes = new ArrayList<String>();
		if (unboundedFix) {
			notes.add("NVD lists no fixed version for some of these CVEs. Upgrade to the latest release.");
		}
		if (wingetId == null) {
			notes.add("No winget package. Upgrade with the vendor's installer or tooling.");
		}
		plan.add(new RemediationItem(Kind.APP_UPGRADE, "Upgrade " + label, null, wingetId, app.version(),
				targetText, false, false, notes.isEmpty() ? null : String.join(" ", notes),
				findings, Priority.OTHER));
	}

	private static CveFinding finding(MsrcFix fix, FeedData feeds) {
		return new CveFinding(fix.cve(), fix.title(), fix.severity(), fix.cvss(), fix.exploited(),
				feeds.kevDueDates().get(fix.cve()));
	}

}
