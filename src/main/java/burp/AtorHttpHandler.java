package burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Live ATOR hook for every Burp tool, including requests that burp-mcp sends
 * through {@code api.http().sendRequest} (tool type Extensions).
 *
 * <p>Control plane, accepted only from Extensions, Burp AI, and Repeater so a
 * proxied browser cannot invoke it. Add header {@code X-ATOR-Command} with
 * {@code status}, {@code refresh}, {@code export}, {@code import}, or
 * {@code domains}. The request is not forwarded. {@code import} reads the
 * HTTP body as an ATOR export document. {@code domains} replaces the host list.
 */
public final class AtorHttpHandler implements HttpHandler {
    static final String COMMAND_HEADER = "X-ATOR-Command";
    static final String MACRO_HEADER = "X-ATOR-Macro";
    private static final ConcurrentHashMap<Integer, String> REPEATER_DECISIONS = new ConcurrentHashMap<>();
    private static final String ALLOWED = "Allowed";

    private static final ThreadLocal<Integer> DEPTH = ThreadLocal.withInitial(() -> 0);

    static void enter() {
        DEPTH.set(DEPTH.get() + 1);
    }

    static void exit() {
        int next = DEPTH.get() - 1;
        if (next <= 0) {
            DEPTH.remove();
        } else {
            DEPTH.set(next);
        }
    }

    static boolean inCall() {
        return DEPTH.get() > 0;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        try {
            if (inCall() || request.hasHeader(MACRO_HEADER)) {
                HttpRequest stripped = request.hasHeader(MACRO_HEADER)
                        ? request.withRemovedHeader(MACRO_HEADER)
                        : request;
                if (stripped.hasHeader(RepeaterLabelFilter.HEADER)) {
                    stripped = stripped.withRemovedHeader(RepeaterLabelFilter.HEADER);
                }
                AtorActivityLog.record("HTTP request", request.toolSource(), request, "Passed", "ATOR internal request");
                return RequestToBeSentAction.continueWith(stripped);
            }
            if (request.hasHeader(COMMAND_HEADER) && controlPlane(request.toolSource())) {
                AtorActivityLog.record("HTTP request", request.toolSource(), request, "Command", "ATOR command handled locally");
                return RequestToBeSentAction.spoof(AtorCommands.execute(request));
            }
            boolean repeater = isRepeater(request.toolSource());
            String labelReason = repeater ? RepeaterLabelFilter.skipReason(request) : null;
            if (repeater) {
                if (REPEATER_DECISIONS.size() > 2048) {
                    REPEATER_DECISIONS.clear();
                }
                REPEATER_DECISIONS.put(request.messageId(), labelReason == null ? ALLOWED : labelReason);
            }
            HttpRequest outgoing = request.hasHeader(RepeaterLabelFilter.HEADER)
                    ? request.withRemovedHeader(RepeaterLabelFilter.HEADER) : request;
            String skipReason = skipReason(request.toolSource(), outgoing);
            if (skipReason == null) {
                skipReason = labelReason;
            }
            if (skipReason != null) {
                AtorActivityLog.record("HTTP request", request.toolSource(), request, "Skipped", skipReason);
                return RequestToBeSentAction.continueWith(outgoing);
            }
            HttpRequest updated = AtorEngine.apply(outgoing);
            if (updated != null && !updated.toString().equals(outgoing.toString())) {
                String tool = request.toolSource() == null || request.toolSource().toolType() == null
                        ? "Burp"
                        : request.toolSource().toolType().toString();
                BurpExtender.log("ATOR updated " + tool + " " + request.method() + " " + request.path());
                AtorActivityLog.record("HTTP request", request.toolSource(), request, "Updated", "Replacement applied");
            } else {
                AtorActivityLog.record("HTTP request", request.toolSource(), request, "Unchanged", "No replacement applied");
            }
            return RequestToBeSentAction.continueWith(updated == null ? outgoing : updated);
        } catch (Exception e) {
            BurpExtender.log("ATOR request handler: " + e.getMessage());
            AtorActivityLog.record("HTTP request", request.toolSource(), request, "Error", "Handler failed");
            try {
                return RequestToBeSentAction.continueWith(request.hasHeader(RepeaterLabelFilter.HEADER)
                        ? request.withRemovedHeader(RepeaterLabelFilter.HEADER) : request);
            } catch (RuntimeException stripError) {
                BurpExtender.log("ATOR could not remove Repeater label header: " + stripError.getMessage());
                return RequestToBeSentAction.drop();
            }
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            String repeaterDecision = REPEATER_DECISIONS.remove(response.messageId());
            if (inCall() || response.hasHeader(MACRO_HEADER)) {
                return ResponseReceivedAction.continueWith(response);
            }
            HttpRequest initiating = response.initiatingRequest();
            if (initiating != null && initiating.hasHeader(COMMAND_HEADER)) {
                return ResponseReceivedAction.continueWith(response);
            }
            String skipReason = skipReason(response.toolSource(), initiating);
            if (skipReason == null && isRepeater(response.toolSource())
                    && (repeaterDecision != null || RepeaterLabelFilter.isEnabled())) {
                skipReason = repeaterDecision == null ? "Repeater label decision unavailable"
                        : ALLOWED.equals(repeaterDecision) ? null : repeaterDecision;
            }
            if (skipReason != null) {
                AtorActivityLog.record("HTTP response", response.toolSource(), initiating, "Skipped", skipReason);
                return ResponseReceivedAction.continueWith(response);
            }
            if (!CheckCondition.matches(response)) {
                AtorActivityLog.record("HTTP response", response.toolSource(), initiating, "Unchanged", "Error condition not met");
                return ResponseReceivedAction.continueWith(response);
            }
            HttpResponse refreshed = AtorEngine.refreshAndRetry(initiating);
            if (refreshed == null) {
                AtorActivityLog.record("HTTP response", response.toolSource(), initiating, "Unchanged", "Refresh did not return a response");
                return ResponseReceivedAction.continueWith(response);
            }
            AtorActivityLog.record("HTTP response", response.toolSource(), initiating, "Refreshed", "Error condition met; retried request");
            Annotations notes = response.annotations() == null
                    ? Annotations.annotations("ATOR refreshed this response")
                    : response.annotations().withNotes("ATOR refreshed this response");
            return ResponseReceivedAction.continueWith(refreshed, notes);
        } catch (Exception e) {
            BurpExtender.log("ATOR response handler: " + e.getMessage());
            AtorActivityLog.record("HTTP response", response.toolSource(), response.initiatingRequest(),
                    "Error", "Handler failed; original response passed");
            return ResponseReceivedAction.continueWith(response);
        }
    }

    static boolean controlPlane(ToolSource source) {
        if (source == null) {
            return false;
        }
        ToolType tool = source.toolType();
        return tool == ToolType.EXTENSIONS || tool == ToolType.BURP_AI || tool == ToolType.REPEATER;
    }

    private static boolean isRepeater(ToolSource source) {
        return source != null && source.toolType() == ToolType.REPEATER;
    }

    private static String skipReason(ToolSource source, HttpRequest request) {
        if (PreviewPanel.isPreviewEnabled) {
            return "Preview enabled";
        }
        if (source == null || !SetttingsTab.isToolEnabled(source.toolType())) {
            return "Tool disabled";
        }
        if (SetttingsTab.inScope != null && SetttingsTab.inScope.isSelected()) {
            try {
                if (request == null || !request.isInScope()) {
                    return "Out of scope";
                }
            } catch (Exception e) {
                return "Scope check failed";
            }
        }
        return domainAllowed(request) ? null : "Domain not selected";
    }

    static boolean domainAllowed(HttpRequest request) {
        if (!DomainFilter.isEnabled()) {
            return true;
        }
        try {
            if (request == null || request.httpService() == null) {
                return false;
            }
            return DomainFilter.allows(request.httpService().host(), request.httpService().port());
        } catch (RuntimeException e) {
            return false;
        }
    }
}
