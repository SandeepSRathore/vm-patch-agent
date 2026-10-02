package com.sandeeprathore.vmpatchagent.script;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.sandeeprathore.vmpatchagent.os.ProcessRunner;
import com.sandeeprathore.vmpatchagent.os.ProcessRunner.ProcessRunException;

import org.springframework.core.io.ClassPathResource;

/**
 * Runs bundled scripts with Windows PowerShell.
 * <p>
 * The script text goes in through {@code -EncodedCommand} rather than a {@code .ps1} on disk, so nothing a non-admin
 * user can write to is ever executed as SYSTEM. Parameters travel as environment variables, so they are data and never
 * become code.
 */
public class PowerShellScriptRunner implements ScriptRunner {

	/** Windows rejects longer command lines; leave headroom for the executable path and flags. */
	private static final int MAX_ENCODED_COMMAND_LENGTH = 32_000;

	private static final Pattern PARAMETER_NAME = Pattern.compile("[A-Z][A-Z0-9_]*");

	private final String powershellPath;

	private final Duration timeout;

	public PowerShellScriptRunner(String powershellPath, Duration timeout) {
		this.powershellPath = powershellPath;
		this.timeout = timeout;
	}

	@Override
	public String run(BundledScript script, Map<String, String> parameters) {
		var environment = new HashMap<String, String>();
		parameters.forEach((name, value) -> {
			if (!PARAMETER_NAME.matcher(name).matches()) {
				throw new IllegalArgumentException("Script parameter names must be UPPER_SNAKE_CASE: " + name);
			}
			environment.put("VPA_" + name, value);
		});
		var command = List.of(powershellPath, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
				"-EncodedCommand", encode(script));

		ProcessRunner.Result result;
		try {
			result = ProcessRunner.run(command, environment, timeout);
		}
		catch (ProcessRunException ex) {
			throw new ScriptFailedException(script.resourcePath() + ": " + ex.getMessage(), ex);
		}
		if (!result.succeeded()) {
			throw new ScriptFailedException(
					script.resourcePath() + ": exit code " + result.exitCode() + ": " + result.stderrSummary());
		}
		return result.stdout();
	}

	static String encode(BundledScript script) {
		String source;
		try (var in = new ClassPathResource(script.resourcePath()).getInputStream()) {
			source = new String(in.readAllBytes(), StandardCharsets.UTF_8);
		}
		catch (IOException ex) {
			throw new UncheckedIOException("Bundled script missing from the jar: " + script.resourcePath(), ex);
		}
		var encoded = Base64.getEncoder().encodeToString(source.getBytes(StandardCharsets.UTF_16LE));
		if (encoded.length() > MAX_ENCODED_COMMAND_LENGTH) {
			throw new IllegalStateException(script.resourcePath() + " is too large to pass as -EncodedCommand");
		}
		return encoded;
	}

}
