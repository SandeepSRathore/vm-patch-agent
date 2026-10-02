package com.sandeeprathore.vmpatchagent.match;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.sandeeprathore.vmpatchagent.feed.nvd.NvdCveResponse.Configuration;
import com.sandeeprathore.vmpatchagent.feed.nvd.NvdCveResponse.CpeMatch;
import com.sandeeprathore.vmpatchagent.feed.nvd.NvdCveResponse.Node;

import static org.assertj.core.api.Assertions.assertThat;

class NvdApplicabilityTest {

	private static final String SEVEN_ZIP = "cpe:2.3:a:7-zip:7-zip";

	@Test
	void keepsOnlyRangesForTheRequestedProduct() {
		var config = or(vulnerable("cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*", null, "24.09"),
				vulnerable("cpe:2.3:a:winrar:winrar:*:*:*:*:*:*:*:*", null, "7.0"));

		var ranges = NvdApplicability.affectedRanges(List.of(config), SEVEN_ZIP);

		assertThat(ranges).containsExactly(new AffectedRange(null, null, null, null, "24.09"));
	}

	@Test
	void keepsAnExactVersionNamedInTheCriteria() {
		var config = or(vulnerable("cpe:2.3:a:7-zip:7-zip:9.20:*:*:*:*:*:*:*", null, null));

		assertThat(NvdApplicability.affectedRanges(List.of(config), SEVEN_ZIP))
			.containsExactly(new AffectedRange("9.20", null, null, null, null));
	}

	@Test
	void dropsCriteriaForOtherPlatforms() {
		var config = or(vulnerable("cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:macos:*:*", null, "24.09"));

		assertThat(NvdApplicability.affectedRanges(List.of(config), SEVEN_ZIP)).isEmpty();
	}

	@Test
	void keepsAndConfigurationsWhosePlatformIsWindows() {
		var config = and(or(vulnerable("cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*", null, "16.03")),
				or(platform("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*")));

		assertThat(NvdApplicability.affectedRanges(List.of(config), SEVEN_ZIP)).hasSize(1);
	}

	@Test
	void dropsAndConfigurationsThatOnlyRunOnOtherPlatforms() {
		var config = and(or(vulnerable("cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*", null, "16.03")),
				or(platform("cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"),
						platform("cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*")));

		assertThat(NvdApplicability.affectedRanges(List.of(config), SEVEN_ZIP)).isEmpty();
	}

	@Test
	void matchesProductsWithEscapedCharacters() {
		var config = or(vulnerable("cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:*:*:*:*:*:*:*:*", null, "8.7.1"));

		assertThat(NvdApplicability.affectedRanges(List.of(config), "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+"))
			.hasSize(1);
	}

	@Test
	void rangeContainmentHonoursEachBound() {
		var range = new AffectedRange(null, "23.01", null, null, "24.09");

		assertThat(range.contains(Version.parse("24.08"))).contains(true);
		assertThat(range.contains(Version.parse("24.09"))).contains(false);
		assertThat(range.contains(Version.parse("22.00"))).contains(false);
		assertThat(range.fixedIn()).contains("24.09");
		assertThat(range.describe()).isEqualTo(">= 23.01 < 24.09");
	}

	@Test
	void rangeWithUnparseableBoundCannotBeAssessed() {
		var range = new AffectedRange(null, null, null, "beta", null);

		assertThat(range.contains(Version.parse("1.0"))).isEmpty();
	}

	private static Configuration or(CpeMatch... matches) {
		return new Configuration(null, false, List.of(new Node("OR", false, List.of(matches))));
	}

	private static Configuration and(Configuration... parts) {
		return new Configuration("AND", false, java.util.Arrays.stream(parts).flatMap(c -> c.nodes().stream()).toList());
	}

	private static CpeMatch vulnerable(String criteria, String startIncluding, String endExcluding) {
		return new CpeMatch(true, criteria, startIncluding, null, null, endExcluding);
	}

	private static CpeMatch platform(String criteria) {
		return new CpeMatch(false, criteria, null, null, null, null);
	}

}
