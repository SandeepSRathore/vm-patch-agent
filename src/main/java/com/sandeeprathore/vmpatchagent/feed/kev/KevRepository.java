package com.sandeeprathore.vmpatchagent.feed.kev;

import java.sql.Date;
import java.util.HashMap;
import java.util.Map;

import com.sandeeprathore.vmpatchagent.feed.kev.KevClient.Entry;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public class KevRepository {

	private final JdbcClient jdbc;

	public KevRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	@Transactional
	public void replaceAll(Iterable<Entry> entries) {
		jdbc.sql("DELETE FROM kev").update();
		for (var entry : entries) {
			if (entry.cveID() == null) {
				continue;
			}
			jdbc.sql("MERGE INTO kev (cve, name, date_added, due_date, ransomware) KEY (cve) VALUES (?, ?, ?, ?, ?)")
				.params(entry.cveID(), truncate(entry.vulnerabilityName()),
						entry.dateAdded() == null ? null : Date.valueOf(entry.dateAdded()),
						entry.dueDate() == null ? null : Date.valueOf(entry.dueDate()), entry.knownRansomwareCampaignUse())
				.update();
		}
	}

	public Map<String, Entry> all() {
		var result = new HashMap<String, Entry>();
		jdbc.sql("SELECT cve, name, date_added, due_date, ransomware FROM kev")
			.query((rs, row) -> new Entry(rs.getString("cve"), rs.getString("name"),
					rs.getDate("date_added") == null ? null : rs.getDate("date_added").toLocalDate(),
					rs.getDate("due_date") == null ? null : rs.getDate("due_date").toLocalDate(), rs.getString("ransomware")))
			.list()
			.forEach(entry -> result.put(entry.cveID(), entry));
		return result;
	}

	private static String truncate(String text) {
		return text == null || text.length() <= 500 ? text : text.substring(0, 500);
	}

}
