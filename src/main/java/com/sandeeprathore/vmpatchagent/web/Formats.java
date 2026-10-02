package com.sandeeprathore.vmpatchagent.web;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import org.springframework.stereotype.Component;

/** Timestamp formatting for templates ({@code ${@fmt.at(instant)}}), in the VM's own time zone. */
@Component("fmt")
public class Formats {

	private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm z")
		.withZone(ZoneId.systemDefault());

	public String at(Instant instant) {
		return instant == null ? null : TIMESTAMP.format(instant);
	}

}
