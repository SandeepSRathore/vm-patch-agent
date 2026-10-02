package com.sandeeprathore.vmpatchagent.vsphere;

import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
class VsphereConfiguration {

	private static final Logger log = LoggerFactory.getLogger(VsphereConfiguration.class);

	@Bean
	SnapshotService snapshotService(VsphereProperties properties) {
		return switch (properties.mode()) {
			case GOVC -> new GovcSnapshotService(properties, new VspherePasswordSource(properties.passwordFile()));
			case FAKE -> {
				log.warn("agent.vsphere.mode=FAKE: snapshots are simulated. Never use on a real VM.");
				yield new FakeSnapshotService(Duration.ofSeconds(2));
			}
			case DISABLED -> new SnapshotService() {
				@Override
				public Readiness readiness() {
					return Readiness.blocked("Snapshots are disabled (agent.vsphere.mode=DISABLED), so nothing can be "
							+ "approved: a snapshot is required before any change.");
				}

				@Override
				public void create(String name, String description) {
					throw new SnapshotException("Snapshots are disabled");
				}

				@Override
				public void remove(String name) {
					throw new SnapshotException("Snapshots are disabled");
				}

				@Override
				public String revertInstructions(String name) {
					return "";
				}
			};
		};
	}

}
