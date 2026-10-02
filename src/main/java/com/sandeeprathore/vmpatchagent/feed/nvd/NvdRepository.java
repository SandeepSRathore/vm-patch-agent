package com.sandeeprathore.vmpatchagent.feed.nvd;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.sandeeprathore.vmpatchagent.match.AffectedRange;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public class NvdRepository {

	private final JdbcClient jdbc;

	public NvdRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	/** A CVE as it applies to one catalogued product, with that product's affected ranges only. */
	public record ProductCve(String cpe, String cve, Double cvss, String summary, List<AffectedRange> ranges) {
	}

	public Optional<Instant> syncedUntil(String cpe) {
		return jdbc.sql("SELECT synced_until FROM nvd_product WHERE cpe = ?")
			.param(cpe)
			.query(Timestamp.class)
			.optional()
			.map(Timestamp::toInstant);
	}

	@Transactional
	public void markSynced(String cpe, Instant until) {
		jdbc.sql("MERGE INTO nvd_product (cpe, synced_until) KEY (cpe) VALUES (?, ?)")
			.params(cpe, Timestamp.from(until))
			.update();
	}

	/** Stores or replaces one CVE for a product; with no ranges the CVE no longer applies and is removed. */
	@Transactional
	public void replace(String cpe, NvdCveResponse.Cve cve, List<AffectedRange> ranges) {
		jdbc.sql("DELETE FROM nvd_range WHERE cpe = ? AND cve = ?").params(cpe, cve.id()).update();
		jdbc.sql("DELETE FROM nvd_cve WHERE cpe = ? AND cve = ?").params(cpe, cve.id()).update();
		if (cve.isRejected() || ranges.isEmpty()) {
			return;
		}
		var summary = cve.englishDescription();
		jdbc.sql("INSERT INTO nvd_cve (cpe, cve, published, last_modified, cvss, summary) VALUES (?, ?, ?, ?, ?, ?)")
			.params(cpe, cve.id(), cve.published(), cve.lastModified(), cve.baseScore(),
					summary.length() > 4000 ? summary.substring(0, 4000) : summary)
			.update();
		for (var range : ranges) {
			jdbc.sql("""
					INSERT INTO nvd_range (cpe, cve, exact_version, start_including, start_excluding, end_including,
					    end_excluding) VALUES (?, ?, ?, ?, ?, ?, ?)""")
				.params(cpe, cve.id(), range.exactVersion(), range.startIncluding(), range.startExcluding(),
						range.endIncluding(), range.endExcluding())
				.update();
		}
	}

	/** Before a full re-read, so CVEs NVD no longer maps to the product do not linger. */
	@Transactional
	public void clearProduct(String cpe) {
		jdbc.sql("DELETE FROM nvd_range WHERE cpe = ?").param(cpe).update();
		jdbc.sql("DELETE FROM nvd_cve WHERE cpe = ?").param(cpe).update();
	}

	public Map<String, List<ProductCve>> cvesByProduct() {
		var ranges = new HashMap<String, List<AffectedRange>>();
		jdbc.sql("""
				SELECT cpe, cve, exact_version, start_including, start_excluding, end_including, end_excluding
				FROM nvd_range""")
			.query((rs, row) -> {
				ranges.computeIfAbsent(rs.getString("cpe") + " " + rs.getString("cve"), k -> new ArrayList<>())
					.add(new AffectedRange(rs.getString("exact_version"), rs.getString("start_including"),
							rs.getString("start_excluding"), rs.getString("end_including"), rs.getString("end_excluding")));
				return null;
			})
			.list();
		var result = new HashMap<String, List<ProductCve>>();
		jdbc.sql("SELECT cpe, cve, cvss, summary FROM nvd_cve")
			.query((rs, row) -> new ProductCve(rs.getString("cpe"), rs.getString("cve"), (Double) rs.getObject("cvss"),
					rs.getString("summary"), ranges.getOrDefault(rs.getString("cpe") + " " + rs.getString("cve"), List.of())))
			.list()
			.forEach(cve -> result.computeIfAbsent(cve.cpe(), k -> new ArrayList<>()).add(cve));
		return result;
	}

	public java.util.Set<String> syncedProducts() {
		return new java.util.HashSet<>(jdbc.sql("SELECT cpe FROM nvd_product").query(String.class).list());
	}

	public long countFor(String cpe) {
		return jdbc.sql("SELECT COUNT(*) FROM nvd_cve WHERE cpe = ?").param(cpe).query(Long.class).single();
	}

}
