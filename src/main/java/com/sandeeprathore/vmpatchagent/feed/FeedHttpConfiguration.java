package com.sandeeprathore.vmpatchagent.feed;

import java.net.http.HttpClient;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Configuration(proxyBeanMethods = false)
class FeedHttpConfiguration {

	/** One client for all feeds. Uses the JVM's proxy settings, so a VM behind a proxy needs only -Dhttps.proxyHost. */
	@Bean
	RestClient feedRestClient(FeedProperties properties) {
		var http = HttpClient.newBuilder()
			.connectTimeout(properties.httpTimeout())
			.followRedirects(HttpClient.Redirect.NORMAL)
			.build();
		var requestFactory = new JdkClientHttpRequestFactory(http);
		requestFactory.setReadTimeout(properties.httpTimeout());
		return RestClient.builder().requestFactory(requestFactory).defaultHeader("User-Agent", "vm-patch-agent").build();
	}

}
