package com.sandeeprathore.vmpatchagent.feed.msrc;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public class MsrcRepository {

	private final JdbcClient jdbc;

	public MsrcRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public record StoredDocument(String id, String releaseDate, int osBuild, Instant fetchedAt) {
	}

	public Map<String, StoredDocument> documents() {
		return jdbc.sql("SELECT id, release_date, os_build, fetched_at FROM msrc_document")
			.query((rs, row) -> new StoredDocument(rs.getString("id"), rs.getString("release_date"), rs.getInt("os_build"),
					rs.getTimestamp("fetched_at").toInstant()))
			.list()
			.stream()
			.collect(Collectors.toMap(StoredDocument::id, Function.identity()));
	}

	/** Replaces everything previously stored from this document. */
	@Transactional
	public void replaceDocument(StoredDocument document, List<MsrcFix> fixes) {
		jdbc.sql("DELETE FROM msrc_fix WHERE document_id = ?").param(document.id()).update();
		for (var fix : fixes) {
			jdbc.sql("""
					INSERT INTO msrc_fix (cve, title, product_id, product_name, os_product, kb, fixed_build, supersedes_kb,
					    restart_required, severity, cvss, exploited, document_id)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""")
				.params(fix.cve(), truncate(fix.title(), 500), fix.productId(), truncate(fix.productName(), 300),
						fix.osProduct(), fix.kb(), truncate(fix.fixedBuild(), 300), fix.supersedesKb(),
						fix.restartRequired(), fix.severity(), fix.cvss(), fix.exploited(), document.id())
				.update();
		}
		jdbc.sql("MERGE INTO msrc_document (id, release_date, os_build, fetched_at) KEY (id) VALUES (?, ?, ?, ?)")
			.params(document.id(), document.releaseDate(), document.osBuild(), Timestamp.from(document.fetchedAt()))
			.update();
	}

	/** Drops documents that have fallen out of the look-back window. */
	@Transactional
	public void retainOnly(java.util.Collection<String> documentIds) {
		for (var stored : documents().keySet()) {
			if (!documentIds.contains(stored)) {
				jdbc.sql("DELETE FROM msrc_fix WHERE document_id = ?").param(stored).update();
				jdbc.sql("DELETE FROM msrc_document WHERE id = ?").param(stored).update();
			}
		}
	}

	public List<MsrcFix> fixes() {
		return jdbc.sql("""
				SELECT cve, title, product_id, product_name, os_product, kb, fixed_build, supersedes_kb, restart_required,
				       severity, cvss, exploited, document_id
				FROM msrc_fix""")
			.query((rs, row) -> new MsrcFix(rs.getString("cve"), rs.getString("title"), rs.getString("product_id"),
					rs.getString("product_name"), rs.getBoolean("os_product"), rs.getString("kb"),
					rs.getString("fixed_build"), rs.getString("supersedes_kb"), rs.getString("restart_required"),
					rs.getString("severity"), (Double) rs.getObject("cvss"), rs.getBoolean("exploited"),
					rs.getString("document_id")))
			.list();
	}

	private static String truncate(String text, int max) {
		return text == null || text.length() <= max ? text : text.substring(0, max);
	}

}
