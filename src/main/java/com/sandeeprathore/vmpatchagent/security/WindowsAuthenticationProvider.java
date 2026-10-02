package com.sandeeprathore.vmpatchagent.security;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Signs approvers in with their Windows credentials. After {@code maxFailedSignIns} failures a name is refused for
 * {@code lockout}, so the dashboard cannot be used to guess passwords faster than Windows' own lockout policy allows.
 */
class WindowsAuthenticationProvider implements AuthenticationProvider {

	static final String APPROVER_ROLE = "APPROVER";

	private static final Logger log = LoggerFactory.getLogger(WindowsAuthenticationProvider.class);

	private record Failures(int count, Instant lockedUntil) {
	}

	private final WindowsAuthenticator authenticator;

	private final SecurityProperties properties;

	private final Clock clock;

	private final Map<String, Failures> failures = new ConcurrentHashMap<>();

	WindowsAuthenticationProvider(WindowsAuthenticator authenticator, SecurityProperties properties, Clock clock) {
		this.authenticator = authenticator;
		this.properties = properties;
		this.clock = clock;
	}

	@Override
	public Authentication authenticate(Authentication authentication) {
		var username = String.valueOf(authentication.getName()).strip();
		var key = username.toLowerCase(Locale.ROOT);
		var previous = failures.get(key);
		if (previous != null && previous.lockedUntil() != null && clock.instant().isBefore(previous.lockedUntil())) {
			throw new LockedException("Too many failed sign-ins for " + username + ". Try again later.");
		}

		var password = authentication.getCredentials() == null ? "" : authentication.getCredentials().toString();
		var account = authenticator.authenticate(username, password);
		if (account.isEmpty()) {
			recordFailure(key);
			log.warn("Failed dashboard sign-in for {}", username);
			throw new BadCredentialsException("Windows rejected that user name or password.");
		}
		if (!account.get().isMemberOf(properties.approverGroupSid())) {
			recordFailure(key);
			log.warn("Dashboard sign-in refused for {}: not in approver group {}", account.get().name(),
					properties.approverGroupSid());
			throw new NotAnApproverException(account.get().name());
		}
		failures.remove(key);
		log.info("Dashboard sign-in: {}", account.get().name());
		return UsernamePasswordAuthenticationToken.authenticated(account.get(), null,
				List.of(new SimpleGrantedAuthority("ROLE_" + APPROVER_ROLE)));
	}

	private void recordFailure(String key) {
		failures.compute(key, (k, previous) -> {
			var count = (previous == null || previous.lockedUntil() != null ? 0 : previous.count()) + 1;
			var lockedUntil = count >= properties.maxFailedSignIns() ? clock.instant().plus(properties.lockout()) : null;
			return new Failures(count, lockedUntil);
		});
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
