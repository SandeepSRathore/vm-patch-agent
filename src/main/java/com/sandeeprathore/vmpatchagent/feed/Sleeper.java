package com.sandeeprathore.vmpatchagent.feed;

import java.time.Duration;

/** Waits between requests to stay inside a feed's rate limit. Swapped for a no-op in tests. */
@FunctionalInterface
public interface Sleeper {

	void sleep(Duration duration) throws InterruptedException;

	static Sleeper real() {
		return Thread::sleep;
	}

}
