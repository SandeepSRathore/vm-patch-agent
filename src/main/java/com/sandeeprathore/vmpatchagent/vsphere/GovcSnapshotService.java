package com.sandeeprathore.vmpatchagent.vsphere;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.sandeeprathore.vmpatchagent.os.ProcessRunner;
import com.sandeeprathore.vmpatchagent.os.ProcessRunner.ProcessRunException;

/**
 * Snapshots through <a href="https://github.com/vmware/govmomi/tree/main/govc">govc</a>, which works against both
 * vCenter and standalone ESXi.
 */
class GovcSnapshotService implements SnapshotService {

	private final VsphereProperties properties;

	private final VspherePasswordSource passwords;

	GovcSnapshotService(VsphereProperties properties, VspherePasswordSource passwords) {
		this.properties = properties;
		this.passwords = passwords;
	}

	@Override
	public Readiness readiness() {
		if (isBlank(properties.url()) || isBlank(properties.username()) || isBlank(properties.vm())) {
			return Readiness.blocked("vSphere is not configured (agent.vsphere.url, username and vm are required).");
		}
		if (!Files.isExecutable(Path.of(properties.govcPath()))) {
			return Readiness.blocked("govc was not found at " + properties.govcPath() + ".");
		}
		try {
			if (passwords.password().isEmpty()) {
				return Readiness.blocked("No vSphere password stored (" + properties.passwordFile() + ").");
			}
		}
		catch (SnapshotException ex) {
			return Readiness.blocked(ex.getMessage());
		}
		return Readiness.ok();
	}

	@Override
	public void create(String name, String description) {
		run("snapshot.create", List.of("-m=false", "-q=" + properties.quiesce(), "-d", description, name));
	}

	@Override
	public void remove(String name) {
		run("snapshot.remove", List.of(name));
	}

	@Override
	public String revertInstructions(String name) {
		return """
				In vCenter: select VM %1$s, then Snapshots > %2$s > Revert, then power the VM on.
				Or from an admin workstation with govc:
				  govc snapshot.revert -vm '%1$s' '%2$s'
				  govc vm.power -on '%1$s'""".formatted(properties.vm(), name);
	}

	private void run(String subcommand, List<String> arguments) {
		var command = new ArrayList<String>();
		command.add(properties.govcPath());
		command.add(subcommand);
		command.add("-vm");
		command.add(properties.vm());
		command.addAll(arguments);

		ProcessRunner.Result result;
		try {
			result = ProcessRunner.run(command, environment(), properties.timeout());
		}
		catch (ProcessRunException ex) {
			throw new SnapshotException("govc " + subcommand + ": " + ex.getMessage(), ex);
		}
		if (!result.succeeded()) {
			throw new SnapshotException(
					"govc " + subcommand + " failed (exit " + result.exitCode() + "): " + result.stderrSummary());
		}
	}

	private Map<String, String> environment() {
		var environment = new HashMap<String, String>();
		environment.put("GOVC_URL", properties.url());
		environment.put("GOVC_USERNAME", properties.username());
		environment.put("GOVC_PASSWORD",
				passwords.password().orElseThrow(() -> new SnapshotException("No vSphere password stored")));
		environment.put("GOVC_INSECURE", Boolean.toString(properties.insecure()));
		if (properties.tlsCaCerts() != null) {
			environment.put("GOVC_TLS_CA_CERTS", properties.tlsCaCerts().toString());
		}
		return environment;
	}

	private static boolean isBlank(String value) {
		return value == null || value.isBlank();
	}

}
