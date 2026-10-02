package com.sandeeprathore.vmpatchagent.security;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import com.sandeeprathore.vmpatchagent.security.SecurityProperties.DemoUser;

/** Users from configuration, for development off-Windows. Refuses to exist on Windows. */
class DemoAuthenticator implements WindowsAuthenticator {

	private final List<DemoUser> users;

	DemoAuthenticator(List<DemoUser> users) {
		if (System.getProperty("os.name", "").startsWith("Windows")) {
			throw new IllegalStateException(
					"agent.security.mode=DEMO is for development only and cannot be used on Windows");
		}
		this.users = users;
	}

	@Override
	public Optional<WindowsAccount> authenticate(String username, String password) {
		return users.stream()
			.filter(u -> u.username().equalsIgnoreCase(username.strip()))
			.filter(u -> MessageDigest.isEqual(u.password().getBytes(StandardCharsets.UTF_8),
					password.getBytes(StandardCharsets.UTF_8)))
			.findFirst()
			.map(u -> new WindowsAccount("DEMO\\" + u.username(), "S-1-5-21-0-0-0-" + Math.abs(u.username().hashCode()),
					new HashSet<>(u.groupSids() == null ? List.of() : u.groupSids())));
	}

}
