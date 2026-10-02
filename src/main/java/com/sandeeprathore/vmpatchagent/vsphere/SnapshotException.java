package com.sandeeprathore.vmpatchagent.vsphere;

public class SnapshotException extends RuntimeException {

	public SnapshotException(String message) {
		super(message);
	}

	public SnapshotException(String message, Throwable cause) {
		super(message, cause);
	}

}
