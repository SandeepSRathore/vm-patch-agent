package com.sandeeprathore.vmpatchagent.audit;

/** Copies audit events somewhere outside the agent's own database. */
public interface EventLogSink {

	enum Level {

		INFORMATION, WARNING, ERROR

	}

	void write(Level level, String message);

}
