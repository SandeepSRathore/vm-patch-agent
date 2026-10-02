package com.sandeeprathore.vmpatchagent.security;

import java.time.Clock;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
class SecurityConfiguration {

	@Bean
	WindowsAuthenticator windowsAuthenticator(SecurityProperties properties) {
		return switch (properties.mode()) {
			case WINDOWS -> new JnaWindowsAuthenticator();
			case DEMO -> new DemoAuthenticator(properties.demoUsers());
		};
	}

	@Bean
	WindowsAuthenticationProvider windowsAuthenticationProvider(WindowsAuthenticator authenticator,
			SecurityProperties properties, Clock clock) {
		return new WindowsAuthenticationProvider(authenticator, properties, clock);
	}

	/**
	 * Spring publishes failure events only for exception types it knows. Without a default, a refusal such as "not in
	 * the approver group" would never reach the audit log.
	 */
	@Bean
	DefaultAuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher events) {
		var publisher = new DefaultAuthenticationEventPublisher(events);
		publisher.setDefaultAuthenticationFailureEvent(AuthenticationFailureBadCredentialsEvent.class);
		return publisher;
	}

	/** Every page needs an approver: exposure data is sensitive too. CSRF protection stays on (Spring default). */
	@Bean
	SecurityFilterChain dashboardSecurity(HttpSecurity http, WindowsAuthenticationProvider provider) throws Exception {
		return http.authenticationProvider(provider)
			.authorizeHttpRequests(requests -> requests.requestMatchers("/login", "/app.css", "/error")
				.permitAll()
				.anyRequest()
				.hasRole(WindowsAuthenticationProvider.APPROVER_ROLE))
			.formLogin(form -> form.loginPage("/login").defaultSuccessUrl("/", true).permitAll())
			.logout(logout -> logout.logoutSuccessUrl("/login?signedOut"))
			.build();
	}

}
