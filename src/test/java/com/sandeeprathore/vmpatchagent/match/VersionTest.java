package com.sandeeprathore.vmpatchagent.match;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class VersionTest {

	@ParameterizedTest
	@CsvSource({
			"24.08, 24.09, -1",
			"24.09, 24.09, 0",
			"128.0.6613.120, 128.0.6613.84, 1",
			"12.4.0.23259341, 12.4.5, -1",
			"8.6.9, 8.6.10, -1",
			"1.0, 1.0.0, 0",
			"0.81, 0.80, 1",
			"10.0.20348.2700, 10.0.20348.5622, -1",
			"7.01, 7.1, 0",
			"115.0esr, 115.0, 0" })
	void comparesNumericSegments(String left, String right, int expected) {
		assertThat(Integer.signum(Version.parse(left).compareTo(Version.parse(right)))).isEqualTo(expected);
	}

	@ParameterizedTest
	@CsvSource({ "''", "'-'", "'*'", "'abc'" })
	void rejectsVersionsWithoutDigits(String text) {
		assertThat(Version.tryParse(text)).isEmpty();
	}

}
