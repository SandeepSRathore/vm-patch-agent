package com.sandeeprathore.vmpatchagent.match;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.sandeeprathore.vmpatchagent.feed.msrc.MsrcFix;
import com.sandeeprathore.vmpatchagent.feed.nvd.NvdRepository.ProductCve;
import com.sandeeprathore.vmpatchagent.inventory.InstalledApp;
import com.sandeeprathore.vmpatchagent.inventory.Inventory;
import com.sandeeprathore.vmpatchagent.inventory.MissingUpdate;
import com.sandeeprathore.vmpatchagent.inventory.SystemInfo;
import com.sandeeprathore.vmpatchagent.match.AppAssessment.Status;
import com.sandeeprathore.vmpatchagent.match.ExposureMatcher.FeedData;
import com.sandeeprathore.vmpatchagent.match.RemediationItem.Kind;

import static org.assertj.core.api.Assertions.assertThat;

class ExposureMatcherTest {

	private static final String SEVEN_ZIP = "cpe:2.3:a:7-zip:7-zip";

	private static final String VMWARE_TOOLS = "cpe:2.3:a:vmware:tools";

	private final ExposureMatcher matcher = new ExposureMatcher(new AppCatalog(new AppCatalogProperties(List.of(
			new AppCatalogProperties.Entry("7-Zip", "^7-Zip\\b", SEVEN_ZIP, "7zip.7zip"),
			new AppCatalogProperties.Entry("VMware Tools", "^VMware Tools$", VMWARE_TOOLS, "")))));

	@Test
	void osCvesFixedInAHigherBuildAreOpenAndTheLatestCumulativeUpdateFixesThem() {
		var feeds = feeds(List.of(osFix("CVE-A", "KB100", "10.0.20348.2800"), osFix("CVE-B", "KB200", "10.0.20348.3000"),
				osFix("CVE-OLD", "KB050", "10.0.20348.2600")));

		var report = matcher.assess(inventory(2700, List.of(), List.of()), feeds);

		var os = report.plan().getFirst();
		assertThat(os.kind()).isEqualTo(Kind.WINDOWS_CUMULATIVE);
		assertThat(os.kb()).isEqualTo("KB200");
		assertThat(os.targetVersion()).isEqualTo("10.0.20348.3000");
		assertThat(os.cves()).extracting(CveFinding::cve).containsExactlyInAnyOrder("CVE-A", "CVE-B");
		assertThat(os.offeredByWindowsUpdate()).isFalse();
		assertThat(os.note()).contains("has not offered KB200");
	}

	@Test
	void aCveIsClosedOnceTheLowestFixingBuildIsReached() {
		var feeds = feeds(List.of(osFix("CVE-A", "KB100", "10.0.20348.2800"), osFix("CVE-A", "KB200", "10.0.20348.3000")));

		assertThat(matcher.assess(inventory(2800, List.of(), List.of()), feeds).plan()).isEmpty();
	}

	@Test
	void aVmOnTheLatestBuildHasNoWindowsItem() {
		var feeds = feeds(List.of(osFix("CVE-A", "KB100", "10.0.20348.2800")));

		assertThat(matcher.assess(inventory(2800, List.of(), List.of()), feeds).plan()).isEmpty();
	}

	@Test
	void warnsWhenMsrcHasNothingForTheBuild() {
		var report = matcher.assess(inventory(2700, List.of(), List.of()), feeds(List.of()));

		assertThat(report.warnings()).singleElement().asString().contains("out of support");
	}

	@Test
	void anOfferedCumulativeUpdateIsMergedIntoTheWindowsItem() {
		var cu = missing("KB200", "2026-09 Cumulative Update for Microsoft server operating system version 21H2", "Critical");
		var feeds = feeds(List.of(osFix("CVE-A", "KB200", "10.0.20348.3000")));

		var report = matcher.assess(inventory(2700, List.of(cu), List.of()), feeds);

		assertThat(report.plan()).singleElement().satisfies(item -> {
			assertThat(item.kind()).isEqualTo(Kind.WINDOWS_CUMULATIVE);
			assertThat(item.offeredByWindowsUpdate()).isTrue();
			assertThat(item.note()).isNull();
		});
	}

	@Test
	void anOlderOfferedCumulativeUpdateIsNotClaimedToFixNewerCves() {
		var olderCu = missing("KB100", "2026-08 Cumulative Update for Microsoft server operating system version 21H2",
				"Critical");
		var feeds = feeds(List.of(osFix("CVE-A", "KB100", "10.0.20348.2800"), osFix("CVE-B", "KB200", "10.0.20348.3000")));

		var item = matcher.assess(inventory(2700, List.of(olderCu), List.of()), feeds).plan().getFirst();

		assertThat(item.kb()).isEqualTo("KB200");
		assertThat(item.offeredByWindowsUpdate()).isFalse();
		assertThat(item.note()).contains("KB100").contains("older").contains("1 of these CVEs open");
	}

	@Test
	void anOfferedCumulativeUpdateUnknownToMsrcIsFlaggedAsUnverified() {
		var unknownCu = missing("KB999", "2026-10 Cumulative Update for Microsoft server operating system version 21H2",
				"Critical");
		var feeds = feeds(List.of(osFix("CVE-A", "KB200", "10.0.20348.3000")));

		var item = matcher.assess(inventory(2700, List.of(unknownCu), List.of()), feeds).plan().getFirst();

		assertThat(item.offeredByWindowsUpdate()).isFalse();
		assertThat(item.note()).contains("KB999").contains("not in the MSRC data");
	}

	@Test
	void aNewerOfferedCumulativeUpdateCoversTheFixes() {
		var newerCu = missing("KB300", "2026-10 Cumulative Update for Microsoft server operating system version 21H2",
				"Critical");
		var feeds = feeds(List.of(osFix("CVE-A", "KB200", "10.0.20348.3000"), osFix("CVE-X", "KB300", "10.0.20348.3100")));

		var item = matcher.assess(inventory(3000, List.of(newerCu), List.of()), feeds).plan().getFirst();

		assertThat(item.kb()).isEqualTo("KB300");
		assertThat(item.offeredByWindowsUpdate()).isTrue();
	}

	@Test
	void wsusVmsAreToldTheUpdateMayNeedApproving() {
		var system = system(2700, "http://wsus.corp:8530");
		var inventory = new Inventory(Instant.EPOCH, system, List.of(), List.of());

		var item = matcher.assess(inventory, feeds(List.of(osFix("CVE-A", "KB200", "10.0.20348.3000")))).plan().getFirst();

		assertThat(item.note()).contains("WSUS (http://wsus.corp:8530)").contains("approving");
	}

	@Test
	void otherOfferedSecurityUpdatesCarryTheirMsrcCves() {
		var dotnet = missing("KB300", "2026-09 Cumulative Update for .NET Framework 4.8", "Important");
		var componentFix = new MsrcFix("CVE-NET", ".NET RCE", "11676-11923", ".NET on WS2022", false, "KB300", "4.8.4806",
				null, "Maybe", "Important", 8.1, false, "2026-Sep");

		var report = matcher.assess(inventory(3000, List.of(dotnet), List.of()), feeds(List.of(componentFix)));

		assertThat(report.plan()).singleElement().satisfies(item -> {
			assertThat(item.kind()).isEqualTo(Kind.WINDOWS_UPDATE);
			assertThat(item.kb()).isEqualTo("KB300");
			assertThat(item.cves()).extracting(CveFinding::cve).containsExactly("CVE-NET");
			assertThat(item.priority()).isEqualTo(Priority.HIGH);
		});
	}

	@Test
	void kevAndMsrcExploitationRaiseAnItemToTheTop() {
		var feeds = new FeedData(List.of(osFix("CVE-A", "KB200", "10.0.20348.3000")), true,
				Map.of(SEVEN_ZIP, List.of(nvd("CVE-ZIP", 7.0, range(null, "24.09")))), Set.of(SEVEN_ZIP),
				Map.of("CVE-ZIP", LocalDate.of(2026, 10, 20)));

		var report = matcher.assess(inventory(2700, List.of(), List.of(app("7-Zip 24.08 (x64)", "24.08"))), feeds);

		assertThat(report.plan().getFirst().kind()).isEqualTo(Kind.APP_UPGRADE);
		assertThat(report.plan().getFirst().priority()).isEqualTo(Priority.ACTIVELY_EXPLOITED);
		assertThat(report.exploitedCount()).isEqualTo(1);
	}

	@Test
	void appUpgradeTargetsTheHighestFixedVersionAmongOpenCves() {
		var feeds = nvdFeeds(SEVEN_ZIP, nvd("CVE-1", 7.8, range(null, "23.01")), nvd("CVE-2", 7.0, range(null, "24.09")),
				nvd("CVE-OLD", 9.8, range(null, "16.03")));

		var report = matcher.assess(inventory(3000, List.of(), List.of(app("7-Zip 22.01 (x64)", "22.01"))), feeds);

		var item = report.plan().getFirst();
		assertThat(item.title()).isEqualTo("Upgrade 7-Zip");
		assertThat(item.wingetId()).isEqualTo("7zip.7zip");
		assertThat(item.installedVersion()).isEqualTo("22.01");
		assertThat(item.targetVersion()).isEqualTo("24.09");
		assertThat(item.cves()).extracting(CveFinding::cve).containsExactlyInAnyOrder("CVE-1", "CVE-2");
		assertThat(report.apps().getFirst().status()).isEqualTo(Status.VULNERABLE);
	}

	@Test
	void appsAreOkNotTrackedAwaitingOrUnassessable() {
		var feeds = nvdFeeds(SEVEN_ZIP, nvd("CVE-1", 7.8, range(null, "23.01")));
		var apps = List.of(app("7-Zip 24.09 (x64)", "24.09"), app("Notepad++", "8.6.9"), app("VMware Tools", "12.4.0"),
				new InstalledApp("7-Zip beta", "beta", "Igor Pavlov", "x64"));

		var report = matcher.assess(inventory(3000, List.of(), apps), feeds);

		assertThat(report.plan()).isEmpty();
		assertThat(report.apps()).extracting(a -> a.app().name() + "=" + a.status())
			.containsExactlyInAnyOrder("7-Zip 24.09 (x64)=OK", "Notepad++=NOT_TRACKED", "VMware Tools=AWAITING_FEED",
					"7-Zip beta=CANNOT_ASSESS");
	}

	@Test
	void appWithoutWingetPackageSaysHowToUpgrade() {
		var feeds = nvdFeeds(VMWARE_TOOLS, nvd("CVE-T", 7.1, new AffectedRange(null, null, null, "12.4.0", null)));

		var item = matcher.assess(inventory(3000, List.of(), List.of(app("VMware Tools", "12.4.0"))), feeds).plan()
			.getFirst();

		assertThat(item.wingetId()).isNull();
		assertThat(item.targetVersion()).isNull();
		assertThat(item.note()).contains("no fixed version").contains("No winget package");
	}

	private static FeedData feeds(List<MsrcFix> fixes) {
		return new FeedData(fixes, true, Map.of(), Set.of(), Map.of());
	}

	private static FeedData nvdFeeds(String cpe, ProductCve... cves) {
		return new FeedData(List.of(), false, Map.of(cpe, List.of(cves)), Set.of(cpe), Map.of());
	}

	private static MsrcFix osFix(String cve, String kb, String fixedBuild) {
		return new MsrcFix(cve, cve + " title", "11923", "Windows Server 2022", true, kb, fixedBuild, null, "Yes",
				"Important", 7.0, false, "2026-Sep");
	}

	private static ProductCve nvd(String cve, double cvss, AffectedRange range) {
		return new ProductCve("unused", cve, cvss, cve + " summary", List.of(range));
	}

	private static AffectedRange range(String startIncluding, String endExcluding) {
		return new AffectedRange(null, startIncluding, null, null, endExcluding);
	}

	private static MissingUpdate missing(String kb, String title, String severity) {
		return new MissingUpdate("id-" + kb, title, List.of(kb), severity, List.of(), List.of("Security Updates"), 1, 0L);
	}

	private static InstalledApp app(String name, String version) {
		return new InstalledApp(name, version, "vendor", "x64");
	}

	private static Inventory inventory(int ubr, List<MissingUpdate> missing, List<InstalledApp> apps) {
		return new Inventory(Instant.EPOCH, system(ubr, null), missing, apps);
	}

	private static SystemInfo system(int ubr, String wsus) {
		return new SystemInfo("VM1", "Microsoft Windows Server 2022 Standard", "21H2", 20348, ubr, "Server", "AMD64", wsus, null,
				List.of());
	}

}
