package com.sandeeprathore.vmpatchagent.script;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.springframework.core.io.ClassPathResource;

/** Serves canned script output so the dashboard can be developed and demoed off-Windows. Never use on a real VM. */
public class DemoScriptRunner implements ScriptRunner {

	@Override
	public String run(BundledScript script, Map<String, String> parameters) {
		try (var in = new ClassPathResource(script.demoResourcePath()).getInputStream()) {
			return new String(in.readAllBytes(), StandardCharsets.UTF_8);
		}
		catch (IOException ex) {
			throw new ScriptFailedException(script.demoResourcePath() + ": no demo output", ex);
		}
	}

}
