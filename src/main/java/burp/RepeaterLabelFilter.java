package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.Preferences;

import javax.swing.SwingUtilities;
import java.util.regex.Pattern;

/** Regex gate for an explicit label on a Repeater request. */
public final class RepeaterLabelFilter {
    public static final String HEADER = "X-ATOR-Repeater-Tab";
    private static final String SETTING = "ator.repeater.labelRegex";
    private static volatile String regex = "";
    private static volatile Pattern pattern;
    private static volatile Runnable listener;
    private static boolean loaded;

    private RepeaterLabelFilter() {
    }

    public static synchronized void ensureLoaded() {
        if (loaded) {
            return;
        }
        MontoyaApi api = BurpExtender.api;
        IBurpExtenderCallbacks callbacks = BurpExtender.callbacks;
        if (api == null && callbacks == null) {
            return;
        }
        String saved = null;
        try {
            if (api != null) {
                saved = api.persistence().preferences().getString(SETTING);
            }
            if (saved == null && callbacks != null) {
                saved = callbacks.loadExtensionSetting(SETTING);
            }
            if (saved != null && !saved.isBlank()) {
                pattern = Pattern.compile(saved);
                regex = saved;
            }
        } catch (RuntimeException e) {
            BurpExtender.log("ATOR could not load Repeater label regex: " + e.getMessage());
            if (saved != null && !saved.isBlank()) {
                regex = saved;
                pattern = Pattern.compile("(?!)");
            }
        }
        loaded = true;
    }

    public static String regex() {
        ensureLoaded();
        return regex;
    }

    public static void setListener(Runnable value) {
        listener = value;
    }

    public static boolean isEnabled() {
        ensureLoaded();
        return pattern != null;
    }

    public static synchronized void setRegex(String value) {
        String next = value == null ? "" : value.trim();
        Pattern compiled = next.isEmpty() ? null : Pattern.compile(next);
        regex = next;
        pattern = compiled;
        loaded = true;
        MontoyaApi api = BurpExtender.api;
        if (api != null) {
            try {
                Preferences preferences = api.persistence().preferences();
                if (next.isEmpty()) {
                    preferences.deleteString(SETTING);
                } else {
                    preferences.setString(SETTING, next);
                }
            } catch (RuntimeException e) {
                BurpExtender.log("ATOR could not save Repeater label regex: " + e.getMessage());
            }
        }
        IBurpExtenderCallbacks callbacks = BurpExtender.callbacks;
        if (callbacks != null) {
            try {
                callbacks.saveExtensionSetting(SETTING, next.isEmpty() ? null : next);
            } catch (RuntimeException e) {
                BurpExtender.log("ATOR could not save Repeater label regex: " + e.getMessage());
            }
        }
        Runnable current = listener;
        if (current != null) {
            SwingUtilities.invokeLater(current);
        }
    }

    /** Returns null if allowed, otherwise a reason suitable for the activity log. */
    public static String skipReason(HttpRequest request) {
        ensureLoaded();
        Pattern current = pattern;
        if (current == null) {
            return null;
        }
        String label = request == null ? null : request.headerValue(HEADER);
        if (label == null || label.isBlank()) {
            return "Repeater label missing";
        }
        return current.matcher(label).find() ? null : "Repeater label does not match regex";
    }
}
