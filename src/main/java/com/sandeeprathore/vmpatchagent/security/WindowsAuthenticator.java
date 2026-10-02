package com.sandeeprathore.vmpatchagent.security;

import java.util.Optional;

public interface WindowsAuthenticator {

	/** @return empty when Windows rejects the credentials */
	Optional<WindowsAccount> authenticate(String username, String password);

}
