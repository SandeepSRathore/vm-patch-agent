package com.sandeeprathore.vmpatchagent.feed;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sandeeprathore.vmpatchagent.feed.FeedStatus.Feed;
import com.sandeeprathore.vmpatchagent.inventory.InventoryRefresher;
import com.sandeeprathore.vmpatchagent.match.AppAssessment.Status;
import com.sandeeprathore.vmpatchagent.match.CveFinding;
import com.sandeeprathore.vmpatchagent.match.ExposureService;
import com.sandeeprathore.vmpatchagent.match.Priority;
import com.sandeeprathore.vmpatchagent.match.RemediationItem;
import com.sandeeprathore.vmpatchagent.match.RemediationItem.Kind;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Inventory (demo VM: Server 2022 build 20348.2700, 7-Zip 24.08) through all three feeds to the fix plan, with the
 * feeds served from excerpts of real MSRC, NVD and CISA data by a local HTTP server.
 */
@SpringBootTest
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class FeedPipelineTest {

	static final List<String> requests = new CopyOnWriteArrayList<>();

	static final HttpServer server = startServer();

	@DynamicPropertySource
	static void feedUrls(DynamicPropertyRegistry registry) {
		var base = "http://127.0.0.1:" + server.getAddress().getPort();
		registry.add("agent.feeds.msrc.base-url", () -> base + "/msrc");
		registry.add("agent.feeds.nvd.base-url", () -> base + "/nvd");
		registry.add("agent.feeds.kev.url", () -> base + "/kev.json");
	}

	@TestConfiguration
	static class FixedTime {

		@Bean
		@Primary
		Clock fixedClock() {
			return Clock.fixed(Instant.parse("2026-10-02T09:00:00Z"), ZoneOffset.UTC);
		}

		@Bean
		@Primary
		Sleeper noWait() {
			return duration -> {
			};
		}

	}

	@Autowired
	InventoryRefresher refresher;

	@Autowired
	FeedWatcher watcher;

	@Autowired
	ExposureService exposure;

	@Autowired
	FeedStatusRepository statuses;

	@AfterAll
	static void stopServer() {
		server.stop(0);
	}

	@BeforeEach
	void scanAndSync() {
		requests.clear();
		refresher.refresh();
	}

	@Test
	void buildsAPrioritisedPlanFromAllThreeFeeds() {
		watcher.syncAll();

		assertThat(statuses.findAll().values()).allSatisfy(s -> assertThat(s.lastError()).isNull());
		var report = exposure.current().orElseThrow();

		var windows = item(report.plan(), Kind.WINDOWS_CUMULATIVE);
		assertThat(windows.kb()).isEqualTo("KB5122882");
		assertThat(windows.targetVersion()).isEqualTo("10.0.20348.5622");
		assertThat(windows.cves()).extracting(CveFinding::cve)
			.contains("CVE-2026-50349", "CVE-2026-56172", "CVE-2026-85880");
		assertThat(windows.priority()).isEqualTo(Priority.ACTIVELY_EXPLOITED);
		assertThat(windows.kevCount()).isEqualTo(1);

		var sevenZip = item(report.plan(), Kind.APP_UPGRADE);
		assertThat(sevenZip.title()).isEqualTo("Upgrade 7-Zip");
		assertThat(sevenZip.targetVersion()).isEqualTo("24.09");
		assertThat(sevenZip.cves()).extracting(CveFinding::cve).containsExactly("CVE-2025-0411");
		assertThat(sevenZip.cves().getFirst().inKev()).isTrue();

		assertThat(report.apps()).filteredOn(a -> a.app().name().startsWith("Google Chrome"))
			.singleElement()
			.extracting(a -> a.status())
			.isEqualTo(Status.OK);
	}

	@Test
	void encodesCpeSpecialCharactersAndSyncsIncrementallyAfterwards() {
		watcher.syncAll();
		assertThat(requests).anyMatch(r -> r.contains("virtualMatchString=cpe%3A2.3%3Aa%3Anotepad-plus-plus%3Anotepad%5C%2B%5C%2B&"));
		assertThat(requests).filteredOn(r -> r.startsWith("/nvd")).noneMatch(r -> r.contains("lastModStartDate"));

		requests.clear();
		watcher.syncAll();

		// MSRC's index still shows the same revision, so the 20 MB document is not downloaded again.
		assertThat(requests).noneMatch(r -> r.startsWith("/msrc/cvrf/2026-Sep"));
		assertThat(requests).filteredOn(r -> r.startsWith("/nvd")).allMatch(r -> r.contains("lastModStartDate"));
		// KEV is refreshed daily, not on every two-hourly run.
		assertThat(requests).noneMatch(r -> r.startsWith("/kev.json"));
		assertThat(statuses.findAll().get(Feed.MSRC).summary()).contains("build 20348");
	}

	private static RemediationItem item(List<RemediationItem> plan, Kind kind) {
		return plan.stream().filter(i -> i.kind() == kind).findFirst().orElseThrow();
	}

	private static HttpServer startServer() {
		try {
			var http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
			http.createContext("/", FeedPipelineTest::handle);
			http.start();
			return http;
		}
		catch (IOException ex) {
			throw new IllegalStateException(ex);
		}
	}

	private static void handle(HttpExchange exchange) throws IOException {
		var uri = exchange.getRequestURI().getRawPath()
				+ (exchange.getRequestURI().getRawQuery() == null ? "" : "?" + exchange.getRequestURI().getRawQuery());
		requests.add(uri);
		var path = exchange.getRequestURI().getPath();
		String body = null;
		if (path.equals("/msrc/updates")) {
			body = """
					{"value":[{"ID":"2026-Sep","CurrentReleaseDate":"2026-10-13T07:00:00"}]}""";
		}
		else if (path.equals("/msrc/cvrf/2026-Sep")) {
			body = fixture("msrc/2026-Sep-excerpt.json");
		}
		else if (path.equals("/nvd")) {
			body = uri.contains("7-zip") && !uri.contains("lastModStartDate") ? fixture("nvd/7-zip-page.json")
					: "{\"resultsPerPage\":0,\"startIndex\":0,\"totalResults\":0,\"vulnerabilities\":[]}";
		}
		else if (path.equals("/kev.json")) {
			body = fixture("kev/catalog-excerpt.json");
		}
		if (body == null) {
			exchange.sendResponseHeaders(404, -1);
			exchange.close();
			return;
		}
		var bytes = body.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().add("Content-Type", "application/json");
		exchange.sendResponseHeaders(200, bytes.length);
		try (var out = exchange.getResponseBody()) {
			out.write(bytes);
		}
	}

	private static String fixture(String path) throws IOException {
		try (var in = new ClassPathResource(path).getInputStream()) {
			return new String(in.readAllBytes(), StandardCharsets.UTF_8);
		}
	}

}
