package com.sandeeprathore.vmpatchagent.web;

import java.util.List;

import com.sandeeprathore.vmpatchagent.job.JobException;
import com.sandeeprathore.vmpatchagent.job.JobService;
import com.sandeeprathore.vmpatchagent.security.WindowsAccount;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
class JobController {

	private final JobService jobs;

	JobController(JobService jobs) {
		this.jobs = jobs;
	}

	@PostMapping("/jobs")
	String approve(@AuthenticationPrincipal WindowsAccount approver,
			@RequestParam(name = "items", required = false) List<String> items,
			@RequestParam(name = "allowReboot", defaultValue = "false") boolean allowReboot, RedirectAttributes redirect) {
		return act(redirect, () -> {
			var id = jobs.approve(approver, items == null ? List.of() : items, allowReboot);
			return "Job #" + id + " approved. Taking a snapshot of this VM before anything changes.";
		});
	}

	@PostMapping("/jobs/{id}/cancel")
	String cancel(@AuthenticationPrincipal WindowsAccount actor, @PathVariable long id, RedirectAttributes redirect) {
		return act(redirect, () -> {
			jobs.cancel(actor, id);
			return "Job #" + id + " cancelled. Its snapshot is kept until you delete it.";
		});
	}

	@PostMapping("/jobs/{id}/delete-snapshot")
	String deleteSnapshot(@AuthenticationPrincipal WindowsAccount actor, @PathVariable long id,
			RedirectAttributes redirect) {
		return act(redirect, () -> {
			jobs.deleteSnapshot(actor, id);
			return "Snapshot for job #" + id + " deleted.";
		});
	}

	private interface Action {

		String run();

	}

	private static String act(RedirectAttributes redirect, Action action) {
		try {
			redirect.addFlashAttribute("notice", action.run());
		}
		catch (JobException ex) {
			redirect.addFlashAttribute("problem", ex.getMessage());
		}
		return "redirect:/";
	}

}
