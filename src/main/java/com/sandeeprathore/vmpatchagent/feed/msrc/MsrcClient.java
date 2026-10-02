package com.sandeeprathore.vmpatchagent.feed.msrc;

import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonProperty;

import com.sandeeprathore.vmpatchagent.feed.FeedProperties;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Reads the MSRC CVRF v3 API. No API key is needed. */
@Component
public class MsrcClient {

	private final RestClient http;

	private final String baseUrl;

	public MsrcClient(@Qualifier("feedRestClient") RestClient http, FeedProperties properties) {
		this.http = http;
		this.baseUrl = properties.msrc().baseUrl().toString();
	}

	public record IndexEntry(@JsonProperty("ID") String id, @JsonProperty("CurrentReleaseDate") String currentReleaseDate) {
	}

	record Index(List<IndexEntry> value) {
	}

	public List<IndexEntry> index() {
		var index = http.get().uri(baseUrl + "/updates").accept(MediaType.APPLICATION_JSON).retrieve().body(Index.class);
		return index == null || index.value() == null ? List.of() : index.value();
	}

	/** @return empty when MSRC has not published the document (yet) */
	public Optional<CvrfDocument> document(String id) {
		return http.get()
			.uri(baseUrl + "/cvrf/{id}", id)
			.accept(MediaType.APPLICATION_JSON)
			.exchange((request, response) -> {
				if (response.getStatusCode().isSameCodeAs(HttpStatus.NOT_FOUND)) {
					return Optional.empty();
				}
				if (!response.getStatusCode().is2xxSuccessful()) {
					throw new IllegalStateException("MSRC returned " + response.getStatusCode() + " for " + id);
				}
				return Optional.ofNullable(response.bodyTo(CvrfDocument.class));
			});
	}

}
