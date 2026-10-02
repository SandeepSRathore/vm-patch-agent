package com.sandeeprathore.vmpatchagent.audit;

import com.sandeeprathore.vmpatchagent.security.WindowsAccount;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;

@Configuration(proxyBeanMethods = false)
class AuditConfiguration {

	@Bean
	EventLogSink eventLogSink() {
		if (System.getProperty("os.name", "").startsWith("Windows")) {
			return new WindowsEventLogSink();
		}
		return (level, message) -> {
		};
	}

	@Bean
	SignInAuditor signInAuditor(AuditLog audit) {
		return new SignInAuditor(audit);
	}

	/** Dashboard sign-ins are part of the audit trail: who could have approved what, and when. */
	static class SignInAuditor {

		private final AuditLog audit;

		SignInAuditor(AuditLog audit) {
			this.audit = audit;
		}

		@EventListener
		void onSuccess(AuthenticationSuccessEvent event) {
			if (event.getAuthentication().getPrincipal() instanceof WindowsAccount account) {
				audit.record(account.name(), AuditAction.SIGN_IN, null, null);
			}
		}

		@EventListener
		void onFailure(AbstractAuthenticationFailureEvent event) {
			audit.record(String.valueOf(event.getAuthentication().getName()), AuditAction.SIGN_IN_FAILED, null,
					event.getException().getMessage());
		}

	}

}
