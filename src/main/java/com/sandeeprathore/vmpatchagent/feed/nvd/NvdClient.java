package com.sandeeprathore.vmpatchagent.feed.nvd;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;

import com.sandeeprathore.vmpatchagent.feed.FeedProperties;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

/** Reads the NVD CVE API 2.0. */
@Component
public class NvdClient {

	private static final DateTimeFormatter NVD_TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
		.withZone(ZoneOffset.UTC);

	private final RestClient http;

	private final FeedProperties.Nvd properties;

	public NvdClient(@Qualifier("feedRestClient") RestClient http, FeedProperties properties) {
		this.http = http;
		this.properties = properties.nvd();
	}

	/**
	 * One page of CVEs affecting a product.
	 * @param productKey {@code cpe:2.3:a:<vendor>:<product>}, matched by NVD against every version
	 * @param modifiedSince null for everything; otherwise only CVEs modified in {@code [modifiedSince, modifiedUntil]},
	 * a window NVD caps at 120 days
	 */
	public NvdCveResponse page(String productKey, Instant modifiedSince, Instant modifiedUntil, int startIndex) {
		// Values go in as URI variables so they are strictly encoded: a literal '+' in a CPE such as notepad\+\+
		// would otherwise reach NVD as a space.
		var variables = new HashMap<String, Object>();
		variables.put("cpe", productKey);
		var uri = UriComponentsBuilder.fromUri(properties.baseUrl())
			.queryParam("virtualMatchString", "{cpe}")
			.queryParam("resultsPerPage", properties.pageSize())
			.queryParam("startIndex", startIndex);
		if (modifiedSince != null) {
			uri.queryParam("lastModStartDate", "{since}").queryParam("lastModEndDate", "{until}");
			variables.put("since", NVD_TIMESTAMP.format(modifiedSince));
			variables.put("until", NVD_TIMESTAMP.format(modifiedUntil));
		}
		var apiKey = properties.apiKey();
		var request = http.get()
			.uri(uri.encode().buildAndExpand(variables).toUri())
			.accept(MediaType.APPLICATION_JSON)
			.headers(headers -> {
				if (apiKey != null && !apiKey.isBlank()) {
					headers.set("apiKey", apiKey);
				}
			});
		var response = request.retrieve().body(NvdCveResponse.class);
		if (response == null) {
			throw new IllegalStateException("NVD returned an empty body for " + productKey);
		}
		return response;
	}

}
