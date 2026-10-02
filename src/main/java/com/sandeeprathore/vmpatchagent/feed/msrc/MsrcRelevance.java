package com.sandeeprathore.vmpatchagent.feed.msrc;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import com.sandeeprathore.vmpatchagent.feed.msrc.CvrfDocument.Product;
import com.sandeeprathore.vmpatchagent.feed.msrc.CvrfDocument.Remediation;
import com.sandeeprathore.vmpatchagent.feed.msrc.CvrfDocument.Threat;
import com.sandeeprathore.vmpatchagent.inventory.SystemInfo;
import com.sandeeprathore.vmpatchagent.match.Cpe;

/**
 * Picks the KB fixes in a CVRF document that apply to this VM.
 * <p>
 * The VM's Windows product is found by its CPE, whose version carries the build line: {@code
 * cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.5622} serves every VM on build 20348. Components installed on
 * that OS appear as composite products whose ID ends in the OS product's ID, e.g. {@code 11676-11923} for .NET on
 * Windows Server 2022 ({@code 11923}).
 */
public final class MsrcRelevance {

	private static final Pattern KB_NUMBER = Pattern.compile("\\d{6,8}");

	private static final String SERVER_CORE_SUFFIX = "(Server Core installation)";

	private MsrcRelevance() {
	}

	public static List<MsrcFix> fixesFor(CvrfDocument document, String documentId, SystemInfo system) {
		var osProductIds = osProductIds(document.productTree().products(), system);
		var products = new HashMap<String, Product>();
		document.productTree().products().forEach(p -> products.put(p.productId(), p));
		var relevant = new HashSet<String>(osProductIds);
		for (var product : document.productTree().products()) {
			var dash = product.productId().indexOf('-');
			if (dash > 0 && osProductIds.contains(product.productId().substring(dash + 1))) {
				relevant.add(product.productId());
			}
		}

		var fixes = new ArrayList<MsrcFix>();
		for (var vulnerability : document.vulnerabilities()) {
			var exploited = vulnerability.threats().stream()
				.anyMatch(t -> t.type() == Threat.EXPLOIT_STATUS && t.description() != null
						&& t.description().value() != null && t.description().value().contains("Exploited:Yes"));
			for (var remediation : vulnerability.remediations()) {
				if (!isKbFix(remediation)) {
					continue;
				}
				for (var productId : remediation.productIds()) {
					if (!relevant.contains(productId)) {
						continue;
					}
					fixes.add(new MsrcFix(vulnerability.cve(),
							vulnerability.title() == null ? null : vulnerability.title().value(), productId,
							products.containsKey(productId) ? products.get(productId).name() : productId,
							osProductIds.contains(productId), "KB" + remediation.description().value().strip(),
							remediation.fixedBuild(), kbOrNull(remediation.supersedes()),
							remediation.restartRequired() == null ? null : remediation.restartRequired().value(),
							severity(vulnerability.threats(), productId), cvss(vulnerability, productId), exploited,
							documentId));
				}
			}
		}
		return fixes;
	}

	/**
	 * Windows products on this VM's build line. Server Core and full-desktop installs are separate MSRC products with
	 * the same build; client SKUs are split by architecture.
	 */
	static Set<String> osProductIds(List<Product> products, SystemInfo system) {
		var buildPrefix = "10.0." + system.build() + ".";
		var ids = new HashSet<String>();
		for (var product : products) {
			if (product.cpe() == null || product.name() == null) {
				continue;
			}
			var cpe = Cpe.parse(product.cpe());
			var version = cpe.specificVersion();
			if (!cpe.part().equals("o") || !cpe.vendor().equals("microsoft") || version == null
					|| !version.startsWith(buildPrefix)) {
				continue;
			}
			if (product.name().contains(SERVER_CORE_SUFFIX) != system.isServerCore()) {
				continue;
			}
			if (!architectureMatches(product.name(), system.architecture())) {
				continue;
			}
			ids.add(product.productId());
		}
		return ids;
	}

	private static boolean architectureMatches(String productName, String architecture) {
		if (architecture == null) {
			return true;
		}
		var name = productName.toLowerCase();
		var named = name.contains("x64-based") || name.contains("32-bit") || name.contains("arm64-based");
		if (!named) {
			return true;
		}
		return switch (architecture.toUpperCase()) {
			case "AMD64" -> name.contains("x64-based");
			case "ARM64" -> name.contains("arm64-based");
			case "X86" -> name.contains("32-bit");
			default -> true;
		};
	}

	private static boolean isKbFix(Remediation remediation) {
		return remediation.type() == Remediation.VENDOR_FIX && remediation.description() != null
				&& remediation.description().value() != null
				&& KB_NUMBER.matcher(remediation.description().value().strip()).matches();
	}

	private static String kbOrNull(String supersedes) {
		if (supersedes == null) {
			return null;
		}
		var first = supersedes.split("[;,\\s]+")[0].strip();
		return KB_NUMBER.matcher(first).matches() ? "KB" + first : null;
	}

	private static String severity(List<Threat> threats, String productId) {
		return threats.stream()
			.filter(t -> t.type() == Threat.SEVERITY && t.productIds().contains(productId) && t.description() != null
					&& t.description().value() != null)
			.map(t -> t.description().value())
			.findFirst()
			.orElse(null);
	}

	private static Double cvss(CvrfDocument.Vulnerability vulnerability, String productId) {
		return vulnerability.scoreSets().stream()
			.filter(s -> s.productIds().contains(productId))
			.map(CvrfDocument.ScoreSet::baseScore)
			.findFirst()
			.orElse(null);
	}

}
