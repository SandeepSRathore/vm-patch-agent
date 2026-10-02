package com.sandeeprathore.vmpatchagent.os;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * Runs an external program with a timeout, capturing stdout and stderr. Secrets belong in {@code environment}: the
 * command line of a running process is visible to every user on the machine, its environment is not.
 */
public final class ProcessRunner {

	private static final int MAX_STDERR_IN_MESSAGE = 2_000;

	private ProcessRunner() {
	}

	public record Result(int exitCode, String stdout, String stderr) {

		public boolean succeeded() {
			return exitCode == 0;
		}

		/** stderr trimmed to a length that fits in a log line or the dashboard. */
		public String stderrSummary() {
			var text = stderr.strip();
			return text.length() <= MAX_STDERR_IN_MESSAGE ? text : text.substring(0, MAX_STDERR_IN_MESSAGE) + "…";
		}

	}

	/** The program could not be started, timed out, or the wait was interrupted. */
	public static class ProcessRunException extends RuntimeException {

		ProcessRunException(String message, Throwable cause) {
			super(message, cause);
		}

	}

	public static Result run(List<String> command, Map<String, String> environment, Duration timeout) {
		var builder = new ProcessBuilder(command);
		builder.environment().putAll(environment);
		Process process;
		try {
			process = builder.start();
			// Some programs (PowerShell among them) wait on stdin under certain hosts; give them EOF straight away.
			process.getOutputStream().close();
		}
		catch (IOException ex) {
			throw new ProcessRunException("could not start " + command.getFirst(), ex);
		}
		var stdout = readAsync(process.getInputStream());
		var stderr = readAsync(process.getErrorStream());
		try {
			if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
				process.descendants().forEach(ProcessHandle::destroyForcibly);
				process.destroyForcibly();
				throw new ProcessRunException("timed out after " + timeout, null);
			}
			return new Result(process.exitValue(), stdout.get(), stderr.get());
		}
		catch (InterruptedException ex) {
			process.destroyForcibly();
			Thread.currentThread().interrupt();
			throw new ProcessRunException("interrupted", ex);
		}
		catch (ExecutionException ex) {
			throw new ProcessRunException("could not read output", ex.getCause());
		}
	}

	private static CompletableFuture<String> readAsync(InputStream stream) {
		return CompletableFuture.supplyAsync(() -> {
			try (stream) {
				return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
			}
			catch (IOException ex) {
				throw new UncheckedIOException(ex);
			}
		}, Thread.ofVirtual()::start);
	}

}
