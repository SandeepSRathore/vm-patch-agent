package com.sandeeprathore.vmpatchagent.feed;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;

import com.sandeeprathore.vmpatchagent.feed.FeedStatus.Feed;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class FeedStatusRepository {

	private static final int MAX_ERROR_LENGTH = 2000;

	private final JdbcClient jdbc;

	public FeedStatusRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public void recordSuccess(Feed feed, Instant at, String summary) {
		upsert(feed);
		jdbc.sql("UPDATE feed_status SET last_attempt = ?, last_success = ?, last_error = NULL, summary = ? WHERE feed = ?")
			.params(Timestamp.from(at), Timestamp.from(at), summary, feed.name())
			.update();
	}

	public void recordFailure(Feed feed, Instant at, String error) {
		upsert(feed);
		var message = error == null ? "unknown error" : error;
		jdbc.sql("UPDATE feed_status SET last_attempt = ?, last_error = ? WHERE feed = ?")
			.params(Timestamp.from(at), message.length() > MAX_ERROR_LENGTH ? message.substring(0, MAX_ERROR_LENGTH)
					: message, feed.name())
			.update();
	}

	public Map<Feed, FeedStatus> findAll() {
		var result = new EnumMap<Feed, FeedStatus>(Feed.class);
		for (var feed : Feed.values()) {
			result.put(feed, new FeedStatus(feed, null, null, null, null));
		}
		jdbc.sql("SELECT feed, last_attempt, last_success, last_error, summary FROM feed_status")
			.query((rs, row) -> new FeedStatus(Feed.valueOf(rs.getString("feed")), instant(rs.getTimestamp("last_attempt")),
					instant(rs.getTimestamp("last_success")), rs.getString("last_error"), rs.getString("summary")))
			.list()
			.forEach(status -> result.put(status.feed(), status));
		return result;
	}

	private void upsert(Feed feed) {
		jdbc.sql("MERGE INTO feed_status (feed) KEY (feed) VALUES (?)").param(feed.name()).update();
	}

	private static Instant instant(Timestamp timestamp) {
		return timestamp == null ? null : timestamp.toInstant();
	}

}
