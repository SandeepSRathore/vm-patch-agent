package com.sandeeprathore.vmpatchagent.inventory;

/** @param architecture x64 or x86, from which uninstall registry view the entry came */
public record InstalledApp(String name, String version, String publisher, String architecture) {
}
