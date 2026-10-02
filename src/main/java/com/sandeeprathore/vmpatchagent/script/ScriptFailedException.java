package com.sandeeprathore.vmpatchagent.script;

public class ScriptFailedException extends RuntimeException {

	public ScriptFailedException(String message) {
		super(message);
	}

	public ScriptFailedException(String message, Throwable cause) {
		super(message, cause);
	}

}
