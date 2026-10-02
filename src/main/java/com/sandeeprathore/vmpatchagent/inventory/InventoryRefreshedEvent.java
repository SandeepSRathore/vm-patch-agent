package com.sandeeprathore.vmpatchagent.inventory;

/** Published after a scan is stored. */
public record InventoryRefreshedEvent(Inventory inventory) {
}
