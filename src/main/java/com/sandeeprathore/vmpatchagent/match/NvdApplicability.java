package com.sandeeprathore.vmpatchagent.match;

import java.util.ArrayList;
import java.util.List;

import com.sandeeprathore.vmpatchagent.feed.nvd.NvdCveResponse.Configuration;
import com.sandeeprathore.vmpatchagent.feed.nvd.NvdCveResponse.CpeMatch;
import com.sandeeprathore.vmpatchagent.feed.nvd.NvdCveResponse.Node;

/**
 * Reduces a CVE's NVD configurations to the version ranges of one product that apply on a Windows machine.
 * <p>
 * NVD configurations are trees. A plain configuration is an OR of vulnerable CPEs, which often name several unrelated
 * products. An {@code AND} configuration pairs vulnerable software with a platform it must run on, e.g. "Firefox
 * &lt; 120 running on Linux". Such a configuration counts only if its platform side can be Windows.
 */
public final class NvdApplicability {

	private NvdApplicability() {
	}

	public static List<AffectedRange> affectedRanges(List<Configuration> configurations, String productKey) {
		var ranges = new ArrayList<AffectedRange>();
		for (var configuration : configurations) {
			if (Boolean.TRUE.equals(configuration.negate())) {
				continue;
			}
			var andConfiguration = "AND".equalsIgnoreCase(configuration.operator());
			if (andConfiguration && !platformNodesAllowWindows(configuration.nodes())) {
				continue;
			}
			for (var node : configuration.nodes()) {
				if (Boolean.TRUE.equals(node.negate())) {
					continue;
				}
				for (var match : node.cpeMatch()) {
					if (match.vulnerable()) {
						toRange(match, productKey).ifPresent(ranges::add);
					}
				}
			}
		}
		return ranges;
	}

	private static java.util.Optional<AffectedRange> toRange(CpeMatch match, String productKey) {
		var cpe = Cpe.parse(match.criteria());
		if (!cpe.productKey().equals(productKey) || !cpe.appliesToWindows()) {
			return java.util.Optional.empty();
		}
		return java.util.Optional.of(new AffectedRange(cpe.specificVersion(), match.versionStartIncluding(),
				match.versionStartExcluding(), match.versionEndIncluding(), match.versionEndExcluding()));
	}

	/** Every node made only of non-vulnerable CPEs is a platform condition; each must admit Windows. */
	private static boolean platformNodesAllowWindows(List<Node> nodes) {
		for (var node : nodes) {
			var platformOnly = !node.cpeMatch().isEmpty() && node.cpeMatch().stream().noneMatch(CpeMatch::vulnerable);
			if (platformOnly && node.cpeMatch().stream().noneMatch(NvdApplicability::isWindowsPlatform)) {
				return false;
			}
		}
		return true;
	}

	private static boolean isWindowsPlatform(CpeMatch match) {
		var cpe = Cpe.parse(match.criteria());
		return cpe.part().equals("o") && cpe.vendor().equals("microsoft") && cpe.product().startsWith("windows");
	}

}
