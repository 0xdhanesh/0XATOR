package burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;

/**
 * Official session-handling action. The name is {@code ATOR}.
 * Burp session rules, including rules written by burp-mcp
 * {@code set_project_options}, invoke this before the request is sent.
 */
public final class AtorSessionAction implements SessionHandlingAction {
    static final String NAME = "ATOR";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public ActionResult performAction(SessionHandlingActionData actionData) {
        HttpRequest request = actionData.request();
        try {
            if (request.hasHeader(AtorHttpHandler.COMMAND_HEADER)
                    || request.hasHeader(AtorHttpHandler.MACRO_HEADER)) {
                AtorActivityLog.record("Session action", "Session rule", request, "Skipped", "ATOR control request");
            } else if (RepeaterLabelFilter.isEnabled() && RepeaterLabelFilter.skipReason(request) != null) {
                AtorActivityLog.record("Session action", "Session rule", request, "Skipped",
                        RepeaterLabelFilter.skipReason(request));
            } else if (!PreviewPanel.isPreviewEnabled && AtorHttpHandler.domainAllowed(request)) {
                String label = request.hasHeader(RepeaterLabelFilter.HEADER)
                        ? request.headerValue(RepeaterLabelFilter.HEADER) : null;
                AtorEngine.ensureTokens();
                HttpRequest updated = AtorEngine.apply(request);
                if (updated != null && label != null) {
                    updated = updated.withHeader(RepeaterLabelFilter.HEADER, label);
                }
                AtorActivityLog.record("Session action", "Session rule", request,
                        updated != null && !updated.toString().equals(request.toString()) ? "Updated" : "Unchanged",
                        "ATOR session action invoked");
                if (updated != null) {
                    request = updated;
                }
            } else {
                AtorActivityLog.record("Session action", "Session rule", request, "Skipped",
                        PreviewPanel.isPreviewEnabled ? "Preview enabled" : "Domain not selected");
            }
        } catch (Exception e) {
            BurpExtender.log("ATOR session action: " + e.getMessage());
            AtorActivityLog.record("Session action", "Session rule", request, "Error", "Action failed");
        }
        if (actionData.annotations() == null) {
            return ActionResult.actionResult(request);
        }
        return ActionResult.actionResult(request, actionData.annotations());
    }
}
