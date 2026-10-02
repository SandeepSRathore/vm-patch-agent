package com.sandeeprathore.vmpatchagent.script;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sandeeprathore.vmpatchagent.AgentProperties;
import com.sandeeprathore.vmpatchagent.AgentProperties.ScriptMode;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
class ScriptRunnerConfiguration {

	private static final Logger log = LoggerFactory.getLogger(ScriptRunnerConfiguration.class);

	@Bean
	ScriptRunner scriptRunner(AgentProperties properties) {
		var scripts = properties.scripts();
		if (scripts.mode() == ScriptMode.DEMO) {
			log.warn("agent.scripts.mode=DEMO: showing canned inventory, not this machine. Never use on a real VM.");
			return new DemoScriptRunner();
		}
		return new PowerShellScriptRunner(scripts.powershellPath(), scripts.timeout());
	}

}
