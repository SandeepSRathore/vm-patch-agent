package com.sandeeprathore.vmpatchagent;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/** Background scans; tests switch this off with {@code agent.scheduling.enabled=false} and drive refreshes directly. */
@Configuration(proxyBeanMethods = false)
@EnableScheduling
@ConditionalOnBooleanProperty(name = "agent.scheduling.enabled", matchIfMissing = true)
class SchedulingConfiguration {

}
