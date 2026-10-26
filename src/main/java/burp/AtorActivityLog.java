package burp;

import burp.api.montoya.core.ToolSource;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.awt.BorderLayout;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

/** A small, metadata-only record of decisions made by ATOR's live hooks. */
public final class AtorActivityLog {
    private static final int LIMIT = 500;
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    private static final Object LOCK = new Object();
    private static final ArrayDeque<String[]> ENTRIES = new ArrayDeque<>();
    private static volatile DefaultTableModel model;
    private static boolean refreshQueued;

    private AtorActivityLog() {
    }

    public static JPanel createPanel() {
        DefaultTableModel tableModel = new DefaultTableModel(
                new String[] {"Time", "Hook", "Tool", "Method", "Host", "Decision", "Reason"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        JButton clear = new JButton("Clear activity");
        clear.addActionListener(event -> {
            synchronized (LOCK) {
                ENTRIES.clear();
            }
            refresh();
        });
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        panel.add(clear, BorderLayout.SOUTH);
        model = tableModel;
        refresh();
        return panel;
    }

    public static void record(String hook, ToolSource source, HttpRequest request, String decision, String reason) {
        String tool = source == null || source.toolType() == null ? "Unknown" : source.toolType().toString();
        record(hook, tool, request, decision, reason);
    }

    public static void record(String hook, String tool, HttpRequest request, String decision, String reason) {
        String method = request == null ? "" : safe(request::method);
        String host = request == null ? ""
                : safe(() -> request.httpService() == null ? "" : request.httpService().host());
        String[] entry = {LocalTime.now().format(TIME), hook, tool, method, host, decision, reason};
        synchronized (LOCK) {
            ENTRIES.addLast(entry);
            while (ENTRIES.size() > LIMIT) {
                ENTRIES.removeFirst();
            }
            if (model != null && !refreshQueued) {
                refreshQueued = true;
                SwingUtilities.invokeLater(AtorActivityLog::refresh);
            }
        }
    }

    private static String safe(java.util.function.Supplier<String> supplier) {
        try {
            String value = supplier.get();
            return value == null ? "" : value;
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static void refresh() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(AtorActivityLog::refresh);
            return;
        }
        List<String[]> snapshot;
        synchronized (LOCK) {
            snapshot = new ArrayList<>(ENTRIES);
            refreshQueued = false;
        }
        DefaultTableModel current = model;
        if (current == null) {
            return;
        }
        current.setRowCount(0);
        for (String[] entry : snapshot) {
            current.addRow(entry);
        }
    }
}
