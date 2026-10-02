package com.sandeeprathore.vmpatchagent.feed.msrc;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import com.sandeeprathore.vmpatchagent.inventory.SystemInfo;

import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/** Runs against an excerpt of the real September 2026 MSRC document. */
class MsrcRelevanceTest {

	static CvrfDocument document;

	@BeforeAll
	static void load() throws IOException {
		try (var in = new ClassPathResource("msrc/2026-Sep-excerpt.json").getInputStream()) {
			document = JsonMapper.builder().build().readValue(in, CvrfDocument.class);
		}
	}

	@Test
	void findsTheOsProductByBuildAndInstallationType() {
		assertThat(MsrcRelevance.osProductIds(document.productTree().products(), server2022("Server")))
			.containsExactly("11923");
		assertThat(MsrcRelevance.osProductIds(document.productTree().products(), server2022("Server Core")))
			.containsExactly("11924");
	}

	@Test
	void findsNothingForABuildMsrcDoesNotCover() {
		var unsupported = new SystemInfo("OLD", "Windows Server 2012 R2", null, 9600, 0, "Server", "AMD64", null, null,
				List.of());

		assertThat(MsrcRelevance.fixesFor(document, "2026-Sep", unsupported)).isEmpty();
	}

	@Test
	void extractsOsFixesWithFixedBuildSeverityAndKb() {
		var fixes = MsrcRelevance.fixesFor(document, "2026-Sep", server2022("Server"));

		var osFix = fixes.stream().filter(f -> f.cve().equals("CVE-2026-50349")).findFirst().orElseThrow();
		assertThat(osFix.osProduct()).isTrue();
		assertThat(osFix.productName()).isEqualTo("Windows Server 2022");
		assertThat(osFix.kb()).isEqualTo("KB5122882");
		assertThat(osFix.fixedBuild()).isEqualTo("10.0.20348.5622");
		assertThat(osFix.supersedesKb()).isEqualTo("KB5120242");
		assertThat(osFix.severity()).isEqualTo("Important");
		assertThat(osFix.cvss()).isEqualTo(7.0);
		assertThat(osFix.restartRequired()).isEqualTo("Yes");
		assertThat(osFix.exploited()).isFalse();
	}

	@Test
	void includesComponentsInstalledOnTheOsButNotOtherProducts() {
		var fixes = MsrcRelevance.fixesFor(document, "2026-Sep", server2022("Server"));

		assertThat(fixes).extracting(MsrcFix::productId).containsOnly("11923", "11676-11923");
		var dotnet = fixes.stream().filter(f -> f.productId().equals("11676-11923")).findFirst().orElseThrow();
		assertThat(dotnet.osProduct()).isFalse();
		assertThat(dotnet.kb()).isEqualTo("KB5126050");
	}

	@Test
	void flagsCvesMsrcReportsAsExploited() {
		var fixes = MsrcRelevance.fixesFor(document, "2026-Sep", server2022("Server"));

		assertThat(fixes).filteredOn(MsrcFix::exploited).extracting(MsrcFix::cve).containsOnly("CVE-2026-85880");
	}

	private static SystemInfo server2022(String installationType) {
		return new SystemInfo("VM1", "Microsoft Windows Server 2022 Standard", "21H2", 20348, 2700, installationType,
				"AMD64", null, null, List.of());
	}

}
