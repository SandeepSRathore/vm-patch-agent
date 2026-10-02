package com.sandeeprathore.vmpatchagent.script;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Process handling is exercised with a stub shell script standing in for powershell.exe, so these run on any POSIX
 * build machine. The real scripts are checked on a Windows VM.
 */
@DisabledOnOs(OS.WINDOWS)
class PowerShellScriptRunnerTest {

	@TempDir
	Path tempDir;

	@Test
	void returnsStdoutOfASuccessfulRun() throws IOException {
		var runner = runnerWithStub("echo '{\"ok\":true}'", Duration.ofSeconds(10));

		assertThat(runner.run(BundledScript.SYSTEM_INFO).strip()).isEqualTo("{\"ok\":true}");
	}

	@Test
	void sendsTheBundledScriptAsAnEncodedCommand() throws IOException {
		var runner = runnerWithStub("for a in \"$@\"; do echo \"$a\"; done", Duration.ofSeconds(10));

		var args = runner.run(BundledScript.SYSTEM_INFO).strip().split("\n");

		assertThat(args).startsWith("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand");
		var decoded = new String(Base64.getDecoder().decode(args[args.length - 1]), StandardCharsets.UTF_16LE);
		assertThat(decoded).contains("ConvertTo-Json");
	}

	@Test
	void passesParametersAsPrefixedEnvironmentVariables() throws IOException {
		var runner = runnerWithStub("echo \"$VPA_KB_IDS\"", Duration.ofSeconds(10));

		assertThat(runner.run(BundledScript.SYSTEM_INFO, Map.of("KB_IDS", "KB1;KB2")).strip()).isEqualTo("KB1;KB2");
	}

	@Test
	void rejectsParameterNamesThatAreNotPlainIdentifiers() throws IOException {
		var runner = runnerWithStub("echo ok", Duration.ofSeconds(10));

		assertThatIllegalArgumentException().isThrownBy(() -> runner.run(BundledScript.SYSTEM_INFO, Map.of("PATH=x", "y")));
	}

	@Test
	void reportsExitCodeAndStderrOnFailure() throws IOException {
		var runner = runnerWithStub("echo 'Access is denied' >&2; exit 5", Duration.ofSeconds(10));

		assertThatThrownBy(() -> runner.run(BundledScript.WUA_SCAN)).isInstanceOf(ScriptFailedException.class)
			.hasMessageContaining("wua-scan")
			.hasMessageContaining("exit code 5")
			.hasMessageContaining("Access is denied");
	}

	@Test
	void killsAScriptThatRunsPastTheTimeout() throws IOException {
		var runner = runnerWithStub("sleep 30", Duration.ofMillis(300));

		assertThatThrownBy(() -> runner.run(BundledScript.WUA_SCAN)).isInstanceOf(ScriptFailedException.class)
			.hasMessageContaining("timed out");
	}

	@Test
	void reportsAMissingExecutable() {
		var runner = new PowerShellScriptRunner(tempDir.resolve("no-such-powershell").toString(), Duration.ofSeconds(5));

		assertThatThrownBy(() -> runner.run(BundledScript.SYSTEM_INFO)).isInstanceOf(ScriptFailedException.class)
			.hasMessageContaining("could not start");
	}

	private PowerShellScriptRunner runnerWithStub(String body, Duration timeout) throws IOException {
		var stub = tempDir.resolve("fake-powershell");
		Files.writeString(stub, "#!/bin/sh\n" + body + "\n");
		Files.setPosixFilePermissions(stub, PosixFilePermissions.fromString("rwx------"));
		return new PowerShellScriptRunner(stub.toString(), timeout);
	}

}
