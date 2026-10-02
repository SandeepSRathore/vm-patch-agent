package com.sandeeprathore.vmpatchagent.web;

import java.io.IOException;
import java.net.URI;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Binding to 127.0.0.1 keeps the network out, but a web page open in a browser on the VM can still reach
 * localhost. This filter closes the two browser routes in:
 * <ul>
 * <li>DNS rebinding: a request whose Host is not a loopback name is refused.</li>
 * <li>Cross-site form posts: a state-changing request whose Origin is not this dashboard is refused.</li>
 * </ul>
 * It runs before Spring Security, so a foreign Host gets a plain refusal rather than a sign-in page. Who the user is
 * is Spring Security's job (see SecurityConfiguration).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class LocalOnlyRequestFilter extends OncePerRequestFilter {

	private static final Set<String> LOOPBACK_HOSTS = Set.of("localhost", "127.0.0.1", "[::1]");

	private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		if (!LOOPBACK_HOSTS.contains(request.getServerName().toLowerCase())) {
			response.sendError(HttpServletResponse.SC_FORBIDDEN, "The dashboard only answers to localhost");
			return;
		}
		if (!SAFE_METHODS.contains(request.getMethod()) && !isSameOrigin(request)) {
			response.sendError(HttpServletResponse.SC_FORBIDDEN, "Cross-site request refused");
			return;
		}
		chain.doFilter(request, response);
	}

	private static boolean isSameOrigin(HttpServletRequest request) {
		var fetchSite = request.getHeader("Sec-Fetch-Site");
		if (fetchSite != null && !fetchSite.equals("same-origin") && !fetchSite.equals("none")) {
			return false;
		}
		var origin = request.getHeader(HttpHeaders.ORIGIN);
		if (origin == null) {
			// Browsers always send Origin on a POST; its absence means a local tool such as curl.
			return true;
		}
		try {
			var uri = URI.create(origin);
			var port = uri.getPort() != -1 ? uri.getPort() : ("https".equals(uri.getScheme()) ? 443 : 80);
			return uri.getHost() != null && LOOPBACK_HOSTS.contains(uri.getHost().toLowerCase())
					&& port == request.getServerPort();
		}
		catch (IllegalArgumentException ex) {
			return false;
		}
	}

}
