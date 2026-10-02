package com.sandeeprathore.vmpatchagent.security;

import org.springframework.security.core.AuthenticationException;

/** The credentials were right, but the account is not in the approver group. */
class NotAnApproverException extends AuthenticationException {

	NotAnApproverException(String account) {
		super(account + " signed in, but is not in the approver group for this VM.");
	}

}
