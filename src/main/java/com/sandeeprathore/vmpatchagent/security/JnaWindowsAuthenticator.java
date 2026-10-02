package com.sandeeprathore.vmpatchagent.security;

import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Collectors;

import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinNT;

/**
 * Asks Windows to check the credentials with {@code LogonUser} and reads the account's groups from the resulting
 * token. A network logon is enough: it validates the password and yields the group list without loading a profile.
 * <p>
 * Under UAC, a local administrator's network-logon token lists Administrators as a deny-only group. The SID is still
 * present, which is all this check needs: it asks "is this person an administrator", not "is this process elevated".
 */
class JnaWindowsAuthenticator implements WindowsAuthenticator {

	@Override
	public Optional<WindowsAccount> authenticate(String username, String password) {
		var name = AccountName.parse(username);
		var token = new WinNT.HANDLEByReference();
		if (!Advapi32.INSTANCE.LogonUser(name.user(), name.domain(), password, WinBase.LOGON32_LOGON_NETWORK,
				WinBase.LOGON32_PROVIDER_DEFAULT, token)) {
			return Optional.empty();
		}
		try {
			var account = Advapi32Util.getTokenAccount(token.getValue());
			var groups = Arrays.stream(Advapi32Util.getTokenGroups(token.getValue()))
				.map(group -> group.sidString)
				.collect(Collectors.toSet());
			return Optional.of(new WindowsAccount(account.fqn, account.sidString, groups));
		}
		finally {
			Kernel32.INSTANCE.CloseHandle(token.getValue());
		}
	}

}
