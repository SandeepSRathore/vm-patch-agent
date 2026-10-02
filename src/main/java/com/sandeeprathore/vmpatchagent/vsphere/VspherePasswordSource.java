package com.sandeeprathore.vmpatchagent.vsphere;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import com.sun.jna.platform.win32.Crypt32Util;

/**
 * The vSphere password: on Windows, a DPAPI-encrypted file only Administrators and SYSTEM can read; elsewhere (dev),
 * the {@code VPA_VSPHERE_PASSWORD} environment variable. The password is passed to govc in its environment, never on
 * its command line.
 */
class VspherePasswordSource {

	private final Path passwordFile;

	VspherePasswordSource(Path passwordFile) {
		this.passwordFile = passwordFile;
	}

	Optional<String> password() {
		if (passwordFile != null && Files.isRegularFile(passwordFile)
				&& System.getProperty("os.name", "").startsWith("Windows")) {
			try {
				var plain = Crypt32Util.cryptUnprotectData(Files.readAllBytes(passwordFile));
				return Optional.of(new String(plain, StandardCharsets.UTF_8));
			}
			catch (IOException | RuntimeException ex) {
				throw new SnapshotException("Could not decrypt " + passwordFile + ": " + ex.getMessage(), ex);
			}
		}
		return Optional.ofNullable(System.getenv("VPA_VSPHERE_PASSWORD")).filter(p -> !p.isBlank());
	}

}
