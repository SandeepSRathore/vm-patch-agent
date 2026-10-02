package com.sandeeprathore.vmpatchagent.script;

import java.util.Map;

public interface ScriptRunner {

	/**
	 * Runs a bundled script and returns its stdout.
	 * @param parameters passed to the script as {@code VPA_<NAME>} environment variables, never spliced into code
	 * @throws ScriptFailedException if the script exits non-zero, times out or cannot be started
	 */
	String run(BundledScript script, Map<String, String> parameters);

	default String run(BundledScript script) {
		return run(script, Map.of());
	}

}
