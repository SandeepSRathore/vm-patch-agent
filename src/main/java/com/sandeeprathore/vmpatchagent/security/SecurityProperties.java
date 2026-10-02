package com.sandeeprathore.vmpatchagent.security;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Dashboard sign-in, bound from {@code agent.security.*}.
 *
 * @param approverGroupSid members of this group may sign in and approve; defaults to BUILTIN\Administrators. Set a
 * domain group's SID to narrow it, e.g. to a "Patch Approvers" group
 * @param demoUsers only for {@link Mode#DEMO}, which refuses to start on Windows
 */
@ConfigurationProperties("agent.security")
public record SecurityProperties(@DefaultValue("WINDOWS") Mode mode,
		@DefaultValue("S-1-5-32-544") String approverGroupSid, @DefaultValue("5") int maxFailedSignIns,
		@DefaultValue("5m") Duration lockout, List<DemoUser> demoUsers) {

	public static final String ADMINISTRATORS_SID = "S-1-5-32-544";

	public SecurityProperties {
		demoUsers = demoUsers == null ? List.of() : List.copyOf(demoUsers);
	}

	public enum Mode {

		/** Check credentials and group membership with Windows (LogonUser). */
		WINDOWS,

		/** Fixed users from configuration, for developing off-Windows. */
		DEMO

	}

	public record DemoUser(String username, String password, List<String> groupSids) {
	}

}
