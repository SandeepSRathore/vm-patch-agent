package com.sandeeprathore.vmpatchagent.security;

/**
 * How a typed user name splits into what {@code LogonUser} expects: {@code CORP\\alice} gives domain CORP,
 * {@code alice@corp.example} is a UPN with no separate domain, and a bare {@code alice} is a local account (domain
 * {@code .}).
 */
record AccountName(String user, String domain) {

	static AccountName parse(String typed) {
		var name = typed.strip();
		var backslash = name.indexOf('\\');
		if (backslash > 0) {
			return new AccountName(name.substring(backslash + 1), name.substring(0, backslash));
		}
		if (name.contains("@")) {
			return new AccountName(name, null);
		}
		return new AccountName(name, ".");
	}

}
