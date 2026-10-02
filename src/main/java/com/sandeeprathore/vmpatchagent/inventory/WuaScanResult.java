package com.sandeeprathore.vmpatchagent.inventory;

import java.util.List;

/** Output of {@code wua-scan.ps1}. {@code resultCode} is the WUA OperationResultCode. */
record WuaScanResult(int resultCode, List<MissingUpdate> updates) {

	private static final int SUCCEEDED = 2;

	private static final int SUCCEEDED_WITH_ERRORS = 3;

	WuaScanResult {
		updates = updates == null ? List.of() : List.copyOf(updates);
	}

	boolean succeeded() {
		return resultCode == SUCCEEDED || resultCode == SUCCEEDED_WITH_ERRORS;
	}

}
