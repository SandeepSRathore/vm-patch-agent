package com.sandeeprathore.vmpatchagent.audit;

import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.WinNT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Writes to the Windows Application log under source {@code VmPatchAgent}. The installer registers the source; until
 * then Windows still records the event, prefixed with a "description not found" note.
 */
class WindowsEventLogSink implements EventLogSink {

	static final String SOURCE = "VmPatchAgent";

	private static final int EVENT_ID = 1000;

	private static final Logger log = LoggerFactory.getLogger(WindowsEventLogSink.class);

	@Override
	public void write(Level level, String message) {
		var type = switch (level) {
			case INFORMATION -> WinNT.EVENTLOG_INFORMATION_TYPE;
			case WARNING -> WinNT.EVENTLOG_WARNING_TYPE;
			case ERROR -> WinNT.EVENTLOG_ERROR_TYPE;
		};
		try {
			var handle = Advapi32.INSTANCE.RegisterEventSource(null, SOURCE);
			if (handle == null) {
				log.warn("Could not open the Windows Event Log; audit event kept in the agent database only");
				return;
			}
			try {
				Advapi32.INSTANCE.ReportEvent(handle, type, 0, EVENT_ID, null, 1, 0, new String[] { message }, null);
			}
			finally {
				Advapi32.INSTANCE.DeregisterEventSource(handle);
			}
		}
		catch (RuntimeException | LinkageError ex) {
			// An audit copy failing must not stop the action it describes; the database record already exists.
			log.warn("Could not write to the Windows Event Log", ex);
		}
	}

}
