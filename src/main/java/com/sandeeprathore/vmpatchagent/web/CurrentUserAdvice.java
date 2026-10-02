package com.sandeeprathore.vmpatchagent.web;

import com.sandeeprathore.vmpatchagent.security.WindowsAccount;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@ControllerAdvice
class CurrentUserAdvice {

	@ModelAttribute("currentUser")
	WindowsAccount currentUser(@AuthenticationPrincipal WindowsAccount account) {
		return account;
	}

}
