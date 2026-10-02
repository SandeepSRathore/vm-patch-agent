package com.sandeeprathore.vmpatchagent.feed.msrc;

/**
 * One CVE fixed by one KB for one product relevant to this VM.
 *
 * @param osProduct true for the Windows product itself; false for components installed on it, e.g. ".NET Framework
 * 4.8 on Windows Server 2022"
 * @param fixedBuild for OS products, the Windows version that contains the fix, e.g. {@code 10.0.20348.5622}; for
 * components, MSRC's free-text component version
 * @param severity Critical, Important, Moderate or Low; null when MSRC gives none for this product
 * @param exploited MSRC reports exploitation detected
 */
public record MsrcFix(String cve, String title, String productId, String productName, boolean osProduct, String kb,
		String fixedBuild, String supersedesKb, String restartRequired, String severity, Double cvss,
		boolean exploited, String documentId) {
}
