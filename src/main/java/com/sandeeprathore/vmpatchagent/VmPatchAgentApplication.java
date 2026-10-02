package com.sandeeprathore.vmpatchagent;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class VmPatchAgentApplication {

	public static void main(String[] args) {
		SpringApplication.run(VmPatchAgentApplication.class, args);
	}

}
