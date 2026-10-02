package com.sandeeprathore.vmpatchagent.vsphere;

import java.nio.file.Path;
import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * How the agent snapshots its own VM, bound from {@code agent.vsphere.*}.
 *
 * @param url vCenter or ESXi SDK URL, e.g. {@code https://vcenter.corp.example/sdk}
 * @param username a service account whose role allows only "Create snapshot" and "Remove snapshot" on this VM
 * @param passwordFile the password, encrypted with Windows DPAPI (machine scope) by the installer
 * @param vm this VM's inventory path, e.g. {@code /DC1/vm/Apps/APP01} (vCenter) or {@code /ha-datacenter/vm/APP01}
 * (standalone ESXi)
 * @param tlsCaCerts PEM file trusted for the server's certificate; leave empty if Windows already trusts it
 * @param insecure skip certificate checks; for labs only
 * @param quiesce ask VMware Tools to flush the guest file system (VSS) so the snapshot is application-consistent
 */
@ConfigurationProperties("agent.vsphere")
public record VsphereProperties(@DefaultValue("GOVC") Mode mode,
		@DefaultValue("C:/Program Files/VmPatchAgent/govc.exe") String govcPath, String url, String username,
		Path passwordFile, String vm, Path tlsCaCerts, @DefaultValue("false") boolean insecure,
		@DefaultValue("true") boolean quiesce, @DefaultValue("30m") Duration timeout) {

	public enum Mode {

		/** Snapshot through govc against vCenter or ESXi. */
		GOVC,

		/** Pretend; for the off-Windows demo. */
		FAKE,

		/** No snapshots: approvals are refused, because the snapshot is the safety net. */
		DISABLED

	}

}
