package com.sandeeprathore.vmpatchagent.inventory;

import java.time.LocalDate;

/** A hotfix Windows reports as installed. {@code installedOn} is null when Windows did not record a usable date. */
public record InstalledUpdate(String kb, String description, LocalDate installedOn) {
}
