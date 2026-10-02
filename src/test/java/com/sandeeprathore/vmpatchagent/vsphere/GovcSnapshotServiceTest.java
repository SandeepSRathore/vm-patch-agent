package com.sandeeprathore.vmpatchagent.vsphere;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** A stub shell script stands in for govc and records its arguments and environment. */
@DisabledOnOs(OS.WINDOWS)
class GovcSnapshotServiceTest {

	@TempDir
	Path tempDir;

	@Test
	void createsADiskOnlyQuiescedSnapshotOfThisVm() throws IOException {
		var service = service(stub("exit 0"), "/DC1/vm/Apps/APP01");

		service.create("vpa-job-7", "VmPatchAgent job 7, approved by CORP\\alice: KB5122882");

		assertThat(Files.readAllLines(tempDir.resolve("args"))).containsExactly("snapshot.create", "-vm",
				"/DC1/vm/Apps/APP01", "-m=false", "-q=true", "-d", "VmPatchAgent job 7, approved by CORP\\alice: KB5122882",
				"vpa-job-7");
	}

	@Test
	void passesCredentialsInTheEnvironmentNeverOnTheCommandLine() throws IOException {
		var service = service(stub("exit 0"), "/DC1/vm/APP01");

		service.remove("vpa-job-7");

		assertThat(Files.readString(tempDir.resolve("args"))).doesNotContain("s3cret");
		assertThat(Files.readAllLines(tempDir.resolve("env"))).contains("GOVC_URL=https://vcenter.corp.example/sdk",
				"GOVC_USERNAME=svc-vpa@vsphere.local", "GOVC_PASSWORD=s3cret", "GOVC_INSECURE=false");
	}

	@Test
	void reportsGovcErrors() throws IOException {
		var service = service(stub("echo 'ServerFaultCode: Permission to perform this operation was denied.' >&2; exit 1"),
				"/DC1/vm/APP01");

		assertThatThrownBy(() -> service.create("vpa-job-7", "d")).isInstanceOf(SnapshotException.class)
			.hasMessageContaining("snapshot.create")
			.hasMessageContaining("Permission to perform this operation was denied");
	}

	@Test
	void blocksApprovalsUntilFullyConfigured() throws IOException {
		var govc = stub("exit 0");

		assertThat(service(govc, null).readiness().reason()).contains("not configured");
		assertThat(new GovcSnapshotService(properties(tempDir.resolve("missing-govc").toString(), "/DC1/vm/APP01"),
				passwords("s3cret")).readiness().reason()).contains("govc was not found");
		assertThat(new GovcSnapshotService(properties(govc.toString(), "/DC1/vm/APP01"), passwords(null)).readiness()
			.reason()).contains("No vSphere password");
		assertThat(service(govc, "/DC1/vm/APP01").readiness().ready()).isTrue();
	}

	@Test
	void revertInstructionsRunFromOutsideTheVmAndPowerItBackOn() throws IOException {
		var instructions = service(stub("exit 0"), "/DC1/vm/APP01").revertInstructions("vpa-job-7");

		assertThat(instructions).contains("govc snapshot.revert -vm '/DC1/vm/APP01' 'vpa-job-7'")
			.contains("govc vm.power -on '/DC1/vm/APP01'");
	}

	private GovcSnapshotService service(Path govc, String vm) {
		return new GovcSnapshotService(properties(govc.toString(), vm), passwords("s3cret"));
	}

	private VsphereProperties properties(String govcPath, String vm) {
		return new VsphereProperties(VsphereProperties.Mode.GOVC, govcPath, "https://vcenter.corp.example/sdk",
				"svc-vpa@vsphere.local", null, vm, null, false, true, Duration.ofSeconds(10));
	}

	private static VspherePasswordSource passwords(String password) {
		return new VspherePasswordSource(null) {
			@Override
			Optional<String> password() {
				return Optional.ofNullable(password);
			}
		};
	}

	private Path stub(String body) throws IOException {
		var script = tempDir.resolve("govc");
		Files.writeString(script, """
				#!/bin/sh
				printf '%%s\\n' "$@" > "%1$s/args"
				env | grep '^GOVC_' > "%1$s/env"
				%2$s
				""".formatted(tempDir, body));
		Files.setPosixFilePermissions(script, PosixFilePermissions.fromString("rwx------"));
		return script;
	}

}
