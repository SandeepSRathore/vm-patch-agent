package com.sandeeprathore.vmpatchagent.job;

import java.util.concurrent.Executor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
class JobConfiguration {

	/** Snapshots and (later) installs run off the request thread; the dashboard shows progress. */
	@Bean
	Executor jobExecutor() {
		return task -> Thread.ofVirtual().name("job").start(task);
	}

}
