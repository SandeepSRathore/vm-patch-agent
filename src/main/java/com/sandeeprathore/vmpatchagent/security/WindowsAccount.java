package com.sandeeprathore.vmpatchagent.security;

import java.util.Set;

/**
 * A signed-in Windows account.
 *
 * @param name {@code DOMAIN\\user} as Windows reports it, which is what the audit log records
 * @param groupSids every group in the account's logon token, including nested and deny-only ones
 */
public record WindowsAccount(String name, String sid, Set<String> groupSids) {

	public WindowsAccount {
		groupSids = Set.copyOf(groupSids);
	}

	public boolean isMemberOf(String groupSid) {
		return groupSids.contains(groupSid);
	}

}
