package com.sandeeprathore.vmpatchagent.web;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.sandeeprathore.vmpatchagent.inventory.InventoryRefresher;
import com.sandeeprathore.vmpatchagent.security.WindowsAccount;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class DashboardTest {

	static final WindowsAccount ADMIN = new WindowsAccount("CORP\\alice", "S-1-5-21-1", Set.of("S-1-5-32-544"));

	@Autowired
	MockMvc mvc;

	@Autowired
	InventoryRefresher refresher;

	static RequestPostProcessor approver() {
		return authentication(UsernamePasswordAuthenticationToken.authenticated(ADMIN, null,
				List.of(new SimpleGrantedAuthority("ROLE_APPROVER"))));
	}

	@Test
	void showsTheLatestScanToAnApprover() throws Exception {
		refresher.refresh();

		mvc.perform(get("/").with(approver()))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("DEMO-APP01")))
			.andExpect(content().string(containsString("20348.2700")))
			.andExpect(content().string(containsString("KB5122882")))
			.andExpect(content().string(containsString("7-Zip 24.08 (x64)")))
			.andExpect(content().string(containsString("CORP\\alice")))
			.andExpect(content().string(not(containsString("Last scan failed"))));
	}

	@Test
	void refusesRequestsAddressedToANonLoopbackHostBeforeAskingForSignIn() throws Exception {
		mvc.perform(get("/").header("Host", "attacker.example")).andExpect(status().isForbidden());
	}

	@Test
	void refusesCrossSitePostsEvenWithAValidSession() throws Exception {
		mvc.perform(post("/inventory/refresh").with(approver()).with(csrf()).header("Origin", "https://attacker.example"))
			.andExpect(status().isForbidden());
		mvc.perform(post("/inventory/refresh").with(approver()).with(csrf()).header("Sec-Fetch-Site", "cross-site"))
			.andExpect(status().isForbidden());
	}

	@Test
	void refusesPostsWithoutTheCsrfToken() throws Exception {
		mvc.perform(post("/inventory/refresh").with(approver())).andExpect(status().isForbidden());
	}

	@Test
	void acceptsARescanFromTheDashboardItself() throws Exception {
		mvc.perform(post("/inventory/refresh").with(approver())
			.with(csrf())
			.header("Origin", "http://localhost")
			.header("Sec-Fetch-Site", "same-origin")).andExpect(redirectedUrl("/"));
	}

}
