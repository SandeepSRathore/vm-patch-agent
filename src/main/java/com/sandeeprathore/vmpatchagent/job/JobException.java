package com.sandeeprathore.vmpatchagent.job;

/** An approval or job action that cannot go ahead; the message is shown to the approver. */
public class JobException extends RuntimeException {

	public JobException(String message) {
		super(message);
	}

}
