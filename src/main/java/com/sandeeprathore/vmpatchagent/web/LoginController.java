package com.sandeeprathore.vmpatchagent.web;

import jakarta.servlet.http.HttpSession;

import com.sandeeprathore.vmpatchagent.inventory.InventoryRepository;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
class LoginController {

	private final InventoryRepository inventories;

	LoginController(InventoryRepository inventories) {
		this.inventories = inventories;
	}

	@GetMapping("/login")
	String login(HttpSession session, Model model) {
		if (session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION) instanceof AuthenticationException ex) {
			model.addAttribute("error", ex.getMessage());
			session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
		}
		model.addAttribute("hostname", inventories.findLatest().map(i -> i.system().hostname()).orElse(null));
		return "login";
	}

}
