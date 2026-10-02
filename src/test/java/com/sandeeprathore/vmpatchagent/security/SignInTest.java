package com.sandeeprathore.vmpatchagent.security;

import org.junit.jupiter.api.Test;

import com.sandeeprathore.vmpatchagent.audit.AuditAction;
import com.sandeeprathore.vmpatchagent.audit.AuditEvent;
import com.sandeeprathore.vmpatchagent.audit.AuditLog;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Real form sign-in through the demo authenticator (users and groups from application-test.yml). */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class SignInTest {

	@Autowired
	MockMvc mvc;

	@Autowired
	AuditLog audit;

	@Test
	void sendsAnonymousVisitorsToTheSignInPage() throws Exception {
		mvc.perform(get("/")).andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/login"));
		mvc.perform(get("/login")).andExpect(status().isOk());
	}

	@Test
	void signsInAMemberOfTheApproverGroupAndAuditsIt() throws Exception {
		mvc.perform(formLogin().user("admin").password("admin-pass"))
			.andExpect(authenticated().withRoles("APPROVER"))
			.andExpect(redirectedUrl("/"));

		assertThat(audit.recent(5)).extracting(AuditEvent::action, AuditEvent::actor)
			.contains(org.assertj.core.groups.Tuple.tuple(AuditAction.SIGN_IN, "DEMO\\admin"));
	}

	@Test
	void refusesAWrongPassword() throws Exception {
		mvc.perform(formLogin().user("admin").password("wrong")).andExpect(unauthenticated());

		assertThat(audit.recent(5)).extracting(AuditEvent::action).contains(AuditAction.SIGN_IN_FAILED);
	}

	@Test
	void refusesAValidAccountOutsideTheApproverGroup() throws Exception {
		mvc.perform(formLogin().user("user").password("user-pass")).andExpect(unauthenticated());

		assertThat(audit.recent(5)).extracting(AuditEvent::detail)
			.anyMatch(detail -> detail != null && detail.contains("not in the approver group"));
	}

	@Test
	void locksANameOutAfterRepeatedFailuresEvenWithTheRightPassword() throws Exception {
		for (var i = 0; i < 3; i++) {
			mvc.perform(formLogin().user("admin").password("wrong")).andExpect(unauthenticated());
		}

		mvc.perform(formLogin().user("admin").password("admin-pass")).andExpect(unauthenticated());
	}

}
