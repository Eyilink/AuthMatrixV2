package authmatrix;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.core.ByteArray;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;

/**
 * AuthMatrix – Burp Suite Extension (Montoya API)
 *
 * Build:
 *   javac -cp montoya-api.jar -d build src/authmatrix/AuthMatrix.java
 *   jar cf AuthMatrix.jar -C build .
 *
 * Install:
 *   Burp → Extensions → Add → Java → AuthMatrix.jar
 */
public class AuthMatrix implements BurpExtension {

    private MontoyaApi api;

    // ── Data ──────────────────────────────────────────────────────────────────
    private final List<UserEntry>    users    = new ArrayList<>();
    private final List<RequestEntry> requests = new ArrayList<>();
    private TestResult[][] resultStore = new TestResult[0][0];

    // ── Table models ──────────────────────────────────────────────────────────
    private DefaultTableModel userModel;
    private DefaultTableModel requestModel;
    private DefaultTableModel resultModel;
    private JTable            resultTable;

    // ── Detail pane ───────────────────────────────────────────────────────────
    private JSplitPane mainSplit;
    private JPanel     detailPanel;
    private JTextPane  detailRequestPane;
    private JTextPane  detailResponsePane;
    private boolean    detailVisible = false;

    // ── Dark theme palette ────────────────────────────────────────────────────
    private static final Color BG         = new Color(0x1E, 0x1E, 0x1E);
    private static final Color FG         = new Color(0xD4, 0xD4, 0xD4);
    private static final Color METHOD_COL = new Color(0x56, 0x9C, 0xD6);
    private static final Color HEADER_KEY = new Color(0x9C, 0xDC, 0xFE);
    private static final Color HEADER_VAL = new Color(0xCE, 0x91, 0x78);
    private static final Color BODY_COL   = new Color(0xD4, 0xD4, 0xD4);
    private static final Color SEP_COL    = new Color(0x3C, 0x3C, 0x3C);

    // =========================================================================
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("AuthMatrix");
        SwingUtilities.invokeLater(this::buildUI);
        registerContextMenu();
        api.logging().logToOutput("AuthMatrix loaded (Montoya API).");
    }

    // =========================================================================
    // Context menu
    // =========================================================================
    private void registerContextMenu() {
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> items = new ArrayList<>();

                var selected = event.selectedRequestResponses();
                if (!selected.isEmpty()) {
                    JMenuItem mi = new JMenuItem("Send to AuthMatrix");
                    mi.addActionListener(e ->
                        selected.forEach(rr -> addRequest(rr.request(), rr.httpService())));
                    items.add(mi);
                    return items;
                }

                event.messageEditorRequestResponse().ifPresent(editor -> {
                    JMenuItem mi = new JMenuItem("Send to AuthMatrix");
                    mi.addActionListener(e -> {
                        var rr = editor.requestResponse();
                        addRequest(rr.request(), rr.httpService());
                    });
                    items.add(mi);
                });

                return items;
            }
        });
    }

    // =========================================================================
    // UI
    // =========================================================================
    private void buildUI() {
        JPanel root = new JPanel(new BorderLayout(4, 4));
        root.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        // ── Toolbar ───────────────────────────────────────────────────────────
        JToolBar bar = new JToolBar();
        bar.setFloatable(false);

        JButton runBtn = new JButton("▶  Run Auth Tests");
        runBtn.setBackground(new Color(40, 140, 40));
        runBtn.setForeground(Color.WHITE);
        runBtn.setFont(runBtn.getFont().deriveFont(Font.BOLD, 13f));
        runBtn.setOpaque(true);
        runBtn.addActionListener(e -> runTests());

        JButton clearBtn = new JButton("Clear All");
        clearBtn.addActionListener(e -> clearAll());

        // ── Save/Load menu button ─────────────────────────────────────────────
        JButton saveLoadBtn = new JButton("💾  Save / Load");
        JPopupMenu saveLoadMenu = new JPopupMenu();

        JMenuItem saveItem = new JMenuItem("Save session (.json)");
        saveItem.addActionListener(e -> saveSession());

        JMenuItem loadItem = new JMenuItem("Load session (.json)");
        loadItem.addActionListener(e -> loadSession());

        saveLoadMenu.add(saveItem);
        saveLoadMenu.add(loadItem);

        saveLoadBtn.addActionListener(e ->
            saveLoadMenu.show(saveLoadBtn, 0, saveLoadBtn.getHeight()));

        // ── Export CSV button ─────────────────────────────────────────────────
        JButton exportBtn = new JButton("📄  Export CSV");
        exportBtn.addActionListener(e -> exportCsv());

        JButton helpBtn = new JButton("Help");
        helpBtn.addActionListener(e -> showHelp());

        bar.add(runBtn);
        bar.addSeparator();
        bar.add(clearBtn);
        bar.addSeparator();
        bar.add(saveLoadBtn);
        bar.add(exportBtn);
        bar.add(Box.createHorizontalGlue());
        bar.add(helpBtn);

        // ── Layout ────────────────────────────────────────────────────────────
        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                buildUserPanel(), buildRequestPanel());
        topSplit.setResizeWeight(0.38);

        JSplitPane tablesSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                topSplit, buildResultPanel());
        tablesSplit.setResizeWeight(0.40);

        detailPanel = buildDetailPanel();
        detailPanel.setVisible(false);

        mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablesSplit, detailPanel);
        mainSplit.setResizeWeight(1.0);

        root.add(bar,       BorderLayout.NORTH);
        root.add(mainSplit, BorderLayout.CENTER);

        api.userInterface().registerSuiteTab("AuthMatrix", root);
    }

    // ── Users panel ───────────────────────────────────────────────────────────
    private JPanel buildUserPanel() {
        JPanel p = new JPanel(new BorderLayout(2, 2));
        p.setBorder(BorderFactory.createTitledBorder("Users / Roles"));

        userModel = new DefaultTableModel(
                new String[]{"Name", "Header", "Token Value", "Role"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return true; }
        };
        JTable tbl = new JTable(userModel);
        tbl.setRowHeight(22);
        tbl.getColumnModel().getColumn(0).setPreferredWidth(80);
        tbl.getColumnModel().getColumn(1).setPreferredWidth(110);
        tbl.getColumnModel().getColumn(2).setPreferredWidth(160);
        tbl.getColumnModel().getColumn(3).setPreferredWidth(70);

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton add = new JButton("+ Add User");
        add.addActionListener(e -> addUser());
        JButton del = new JButton("- Remove");
        del.addActionListener(e -> {
            int row = tbl.getSelectedRow();
            if (row >= 0) { users.remove(row); userModel.removeRow(row); rebuildResultColumns(); }
        });
        btns.add(add); btns.add(del);

        p.add(new JScrollPane(tbl), BorderLayout.CENTER);
        p.add(btns, BorderLayout.SOUTH);
        return p;
    }

    // ── Requests panel ────────────────────────────────────────────────────────
    private JPanel buildRequestPanel() {
        JPanel p = new JPanel(new BorderLayout(2, 2));
        p.setBorder(BorderFactory.createTitledBorder("Requests"));

        requestModel = new DefaultTableModel(
                new String[]{"#", "Path", "Expected Users", "Expected Roles", "Description"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return c >= 2; }
        };
        JTable tbl = new JTable(requestModel);
        tbl.setRowHeight(22);
        tbl.getColumnModel().getColumn(0).setMaxWidth(35);
        tbl.getColumnModel().getColumn(1).setPreferredWidth(220);
        tbl.getColumnModel().getColumn(2).setPreferredWidth(120);
        tbl.getColumnModel().getColumn(3).setPreferredWidth(120);
        tbl.getColumnModel().getColumn(4).setPreferredWidth(200);
        tbl.getTableHeader().setToolTipText(
                "Expected Users OR Expected Roles — only one can be set per request.");

        tbl.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable t, Object v, boolean sel, boolean foc, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, v, sel, foc, row, col);
                String eu = str(requestModel.getValueAt(row, 2));
                String er = str(requestModel.getValueAt(row, 3));
                if (!eu.isEmpty() && !er.isEmpty()) {
                    c.setBackground(new Color(255, 200, 200));
                    c.setForeground(Color.BLACK);
                } else if (!sel) {
                    c.setBackground(Color.WHITE);
                    c.setForeground(Color.BLACK);
                }
                return c;
            }
        });

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton del = new JButton("- Remove");
        del.addActionListener(e -> {
            int row = tbl.getSelectedRow();
            if (row >= 0) {
                requests.remove(row);
                requestModel.removeRow(row);
                rebuildResultStore();
                if (row < resultModel.getRowCount()) resultModel.removeRow(row);
            }
        });
        JLabel hint = new JLabel("  ← Right-click any Burp request → 'Send to AuthMatrix'");
        hint.setForeground(Color.GRAY);
        btns.add(del); btns.add(hint);

        p.add(new JScrollPane(tbl), BorderLayout.CENTER);
        p.add(btns, BorderLayout.SOUTH);
        return p;
    }

    // ── Results panel ─────────────────────────────────────────────────────────
    private JPanel buildResultPanel() {
        JPanel p = new JPanel(new BorderLayout(2, 2));
        p.setBorder(BorderFactory.createTitledBorder(
                "Results   ✅ Expected   🔴 Unexpected Access   🟡 Unexpected Block   – Not tested"));

        resultModel = new DefaultTableModel(new String[]{"#", "Path", "Description"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        resultTable = new JTable(resultModel);
        resultTable.setRowHeight(22);
        resultTable.setDefaultRenderer(Object.class, new ResultRenderer());
        resultTable.getColumnModel().getColumn(0).setMaxWidth(35);
        resultTable.getColumnModel().getColumn(1).setPreferredWidth(200);
        resultTable.getColumnModel().getColumn(2).setPreferredWidth(200);

        resultTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = resultTable.rowAtPoint(e.getPoint());
                int col = resultTable.columnAtPoint(e.getPoint());
                if (row >= 0 && col >= 3) {
                    int userIdx = col - 3;
                    if (userIdx < users.size()) showDetail(row, userIdx);
                }
            }
        });

        p.add(new JScrollPane(resultTable), BorderLayout.CENTER);
        return p;
    }

    // ── Detail panel ──────────────────────────────────────────────────────────
    private JPanel buildDetailPanel() {
        JPanel p = new JPanel(new BorderLayout(0, 0));
        p.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));

        detailRequestPane  = makeDarkPane();
        detailResponsePane = makeDarkPane();

        JScrollPane reqScroll  = darkScroll(detailRequestPane,  "Request");
        JScrollPane respScroll = darkScroll(detailResponsePane, "Response");

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqScroll, respScroll);
        split.setResizeWeight(0.5);
        split.setBorder(null);
        split.setBackground(BG);

        p.add(split, BorderLayout.CENTER);
        p.setBackground(BG);
        return p;
    }

    private JTextPane makeDarkPane() {
        JTextPane tp = new JTextPane();
        tp.setEditable(false);
        tp.setBackground(BG);
        tp.setForeground(FG);
        tp.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        tp.setCaretColor(FG);
        return tp;
    }

    private JScrollPane darkScroll(JTextPane pane, String title) {
        JScrollPane sp = new JScrollPane(pane);
        sp.setBackground(BG);
        sp.getViewport().setBackground(BG);
        sp.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(0x55, 0x55, 0x55)),
                title, 0, 0,
                UIManager.getFont("TitledBorder.font"),
                new Color(0xAA, 0xAA, 0xAA)));
        return sp;
    }

    // =========================================================================
    // Data helpers
    // =========================================================================
    private void addUser() {
        UserEntry u = new UserEntry(
                "User" + (users.size() + 1),
                "Authorization", "Bearer <token>", "user");
        users.add(u);
        userModel.addRow(new Object[]{u.name, u.tokenHeader, u.tokenValue, u.role});
        rebuildResultColumns();
    }

    private void addRequest(HttpRequest req, HttpService svc) {
        String host = (svc != null) ? svc.host() : req.headerValue("Host");
        String path = req.method() + "  " + req.path();
        requests.add(new RequestEntry(req, svc, req.method(), host, req.path()));
        int idx = requests.size();

        requestModel.addRow(new Object[]{idx, path, "", "", ""});

        Object[] row = new Object[3 + users.size()];
        row[0] = idx; row[1] = path; row[2] = "";
        Arrays.fill(row, 3, row.length, "–");
        resultModel.addRow(row);
        rebuildResultStore();
    }

    private void rebuildResultColumns() {
        resultModel.setColumnCount(0);
        resultModel.addColumn("#");
        resultModel.addColumn("Path");
        resultModel.addColumn("Description");
        for (UserEntry u : users) resultModel.addColumn(u.name);

        resultModel.setRowCount(0);
        for (int i = 0; i < requests.size(); i++) {
            RequestEntry r = requests.get(i);
            Object[] row = new Object[3 + users.size()];
            row[0] = i + 1;
            row[1] = r.method + "  " + r.path;
            row[2] = (i < requestModel.getRowCount()) ? str(requestModel.getValueAt(i, 4)) : "";
            Arrays.fill(row, 3, row.length, "–");
            resultModel.addRow(row);
        }
        rebuildResultStore();

        if (resultTable != null) {
            resultTable.getColumnModel().getColumn(0).setMaxWidth(35);
            resultTable.getColumnModel().getColumn(1).setPreferredWidth(200);
            resultTable.getColumnModel().getColumn(2).setPreferredWidth(200);
        }
    }

    private void rebuildResultStore() {
        resultStore = new TestResult[requests.size()][Math.max(1, users.size())];
    }

    private void clearAll() {
        requests.clear();
        users.clear();
        userModel.setRowCount(0);
        requestModel.setRowCount(0);
        resultModel.setRowCount(0);
        resultModel.setColumnCount(0);
        resultModel.addColumn("#");
        resultModel.addColumn("Path");
        resultModel.addColumn("Description");
        resultStore = new TestResult[0][0];
        hideDetail();
    }

    // =========================================================================
    // Run Tests
    // =========================================================================
    private void runTests() {
        if (users.isEmpty() || requests.isEmpty()) {
            JOptionPane.showMessageDialog(null,
                    "Add at least one user and one request before running.",
                    "AuthMatrix", JOptionPane.WARNING_MESSAGE);
            return;
        }
        for (int i = 0; i < requestModel.getRowCount(); i++) {
            String eu = str(requestModel.getValueAt(i, 2));
            String er = str(requestModel.getValueAt(i, 3));
            if (!eu.isEmpty() && !er.isEmpty()) {
                JOptionPane.showMessageDialog(null,
                        "Request #" + (i + 1) + " has both 'Expected Users' and 'Expected Roles' set.\n" +
                        "Only one can be used at a time – please clear one of them.",
                        "AuthMatrix – Conflict", JOptionPane.ERROR_MESSAGE);
                return;
            }
        }

        syncUsersFromTable();
        rebuildResultColumns();
        hideDetail();

        new Thread(() -> {
            for (int ri = 0; ri < requests.size(); ri++) {
                RequestEntry re     = requests.get(ri);
                String expUsers     = str(requestModel.getValueAt(ri, 2));
                String expRoles     = str(requestModel.getValueAt(ri, 3));
                String desc         = str(requestModel.getValueAt(ri, 4));
                final int riF = ri;
                SwingUtilities.invokeLater(() -> {
                    if (riF < resultModel.getRowCount())
                        resultModel.setValueAt(desc, riF, 2);
                });

                for (int ui = 0; ui < users.size(); ui++) {
                    UserEntry user = users.get(ui);

                    HttpRequest modReq = re.request.hasHeader(user.tokenHeader)
                            ? re.request.withUpdatedHeader(user.tokenHeader, user.tokenValue)
                            : re.request.withAddedHeader(
                                    HttpHeader.httpHeader(user.tokenHeader, user.tokenValue));

                    String statusStr;
                    String rawRequest  = new String(modReq.toByteArray().getBytes());
                    String rawResponse = "";

                    try {
                        HttpRequest toSend = (re.service != null)
                                ? HttpRequest.httpRequest(re.service, modReq.toByteArray())
                                : modReq;
                        var result   = api.http().sendRequest(toSend);
                        HttpResponse resp = result.response();
                        statusStr    = String.valueOf(resp.statusCode());
                        rawRequest   = new String(toSend.toByteArray().getBytes());
                        rawResponse  = new String(resp.toByteArray().getBytes());
                    } catch (Exception ex) {
                        statusStr   = "ERR";
                        rawResponse = "Error: " + ex.getMessage();
                        api.logging().logToError("AuthMatrix: " + ex.getMessage());
                    }

                    boolean shouldAccess = shouldAccess(expUsers, expRoles, user);
                    boolean gotAccess    = statusStr.startsWith("2") || statusStr.startsWith("3");

                    String cell;
                    if (shouldAccess == gotAccess)       cell = "✅ " + statusStr;
                    else if (!shouldAccess && gotAccess) cell = "🔴 " + statusStr;
                    else                                 cell = "🟡 " + statusStr;

                    if (ri < resultStore.length && ui < resultStore[ri].length)
                        resultStore[ri][ui] = new TestResult(rawRequest, rawResponse, statusStr, cell);

                    final int row = ri, col = ui + 3;
                    final String val = cell;
                    SwingUtilities.invokeLater(() -> {
                        if (row < resultModel.getRowCount() && col < resultModel.getColumnCount())
                            resultModel.setValueAt(val, row, col);
                    });
                }
            }
            SwingUtilities.invokeLater(() ->
                    JOptionPane.showMessageDialog(null, "All tests completed.",
                            "AuthMatrix", JOptionPane.INFORMATION_MESSAGE));
        }, "AuthMatrix-Runner").start();
    }

    private boolean shouldAccess(String expUsers, String expRoles, UserEntry user) {
        if (expUsers.isEmpty() && expRoles.isEmpty()) return true;
        if (!expUsers.isEmpty()) {
            for (String name : expUsers.split(","))
                if (name.strip().equalsIgnoreCase(user.name)) return true;
            return false;
        }
        for (String role : expRoles.split(","))
            if (role.strip().equalsIgnoreCase(user.role)) return true;
        return false;
    }

    // =========================================================================
    // Export CSV
    // =========================================================================
    private void exportCsv() {
        if (resultModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(null, "No results to export yet.",
                    "AuthMatrix", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Export Results as CSV");
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        fc.setSelectedFile(new File("authmatrix_results_" + ts + ".csv"));
        fc.setFileFilter(new FileNameExtensionFilter("CSV files (*.csv)", "csv"));

        if (fc.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return;

        File out = fc.getSelectedFile();
        if (!out.getName().toLowerCase().endsWith(".csv"))
            out = new File(out.getAbsolutePath() + ".csv");

        try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(out), StandardCharsets.UTF_8))) {

            // Header row
            StringBuilder hdr = new StringBuilder();
            for (int c = 0; c < resultModel.getColumnCount(); c++) {
                if (c > 0) hdr.append(",");
                hdr.append(csvEscape(resultModel.getColumnName(c)));
            }
            pw.println(hdr);

            // Data rows
            for (int r = 0; r < resultModel.getRowCount(); r++) {
                StringBuilder row = new StringBuilder();
                for (int c = 0; c < resultModel.getColumnCount(); c++) {
                    if (c > 0) row.append(",");
                    row.append(csvEscape(str(resultModel.getValueAt(r, c))));
                }
                pw.println(row);
            }

            JOptionPane.showMessageDialog(null,
                    "CSV exported to:\n" + out.getAbsolutePath(),
                    "AuthMatrix – Export", JOptionPane.INFORMATION_MESSAGE);

        } catch (IOException ex) {
            JOptionPane.showMessageDialog(null,
                    "Export failed: " + ex.getMessage(),
                    "AuthMatrix – Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** RFC-4180 CSV escaping: wrap in quotes if field contains comma, quote or newline. */
    private static String csvEscape(String s) {
        if (s == null) s = "";
        // Strip emoji for cleaner CSV (optional – comment out to keep them)
        s = s.replace("✅ ", "OK_").replace("🔴 ", "BYPASS_").replace("🟡 ", "BLOCK_");
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            s = "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    // =========================================================================
    // Save / Load session  (hand-rolled JSON – no external dependencies)
    // =========================================================================

    /**
     * Session file format (JSON):
     * {
     *   "version": 1,
     *   "users": [
     *     {"name":"Alice","header":"Authorization","token":"Bearer eyJ...","role":"admin"},
     *     ...
     *   ],
     *   "requests": [
     *     {
     *       "method":"GET","host":"example.com","path":"/api/users",
     *       "expectedUsers":"Alice","expectedRoles":"","description":"List users",
     *       "rawRequest":"R0VUIC9hcGkvdXNlcnMgSFRUUC8xLjE...",   // base64
     *       "results": [
     *         {"userIndex":0,"status":"200","cell":"OK_200","rawRequest":"...","rawResponse":"..."},
     *         ...
     *       ]
     *     },
     *     ...
     *   ]
     * }
     */
    private void saveSession() {
        if (users.isEmpty() && requests.isEmpty()) {
            JOptionPane.showMessageDialog(null, "Nothing to save.",
                    "AuthMatrix", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Save AuthMatrix Session");
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        fc.setSelectedFile(new File("authmatrix_session_" + ts + ".json"));
        fc.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));

        if (fc.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return;

        File out = fc.getSelectedFile();
        if (!out.getName().toLowerCase().endsWith(".json"))
            out = new File(out.getAbsolutePath() + ".json");

        // Sync editable table data before saving
        syncUsersFromTable();

        StringBuilder sb = new StringBuilder();
        sb.append("{\n  \"version\": 1,\n");

        // ── Users ─────────────────────────────────────────────────────────────
        sb.append("  \"users\": [\n");
        for (int i = 0; i < users.size(); i++) {
            UserEntry u = users.get(i);
            sb.append("    {")
              .append("\"name\":").append(jStr(u.name)).append(",")
              .append("\"header\":").append(jStr(u.tokenHeader)).append(",")
              .append("\"token\":").append(jStr(u.tokenValue)).append(",")
              .append("\"role\":").append(jStr(u.role))
              .append("}");
            if (i < users.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");

        // ── Requests ──────────────────────────────────────────────────────────
        sb.append("  \"requests\": [\n");
        for (int ri = 0; ri < requests.size(); ri++) {
            RequestEntry re = requests.get(ri);
            String expUsers = str(requestModel.getValueAt(ri, 2));
            String expRoles = str(requestModel.getValueAt(ri, 3));
            String desc     = str(requestModel.getValueAt(ri, 4));

            // Encode raw HTTP bytes as base64 so JSON stays clean
            String rawReqB64 = Base64.getEncoder().encodeToString(re.request.toByteArray().getBytes());
            String host      = (re.service != null) ? re.service.host() : "";
            int    port      = (re.service != null) ? re.service.port() : 443;
            boolean secure   = (re.service != null) && re.service.secure();

            sb.append("    {\n")
              .append("      \"method\":").append(jStr(re.method)).append(",\n")
              .append("      \"host\":").append(jStr(host)).append(",\n")
              .append("      \"port\":").append(port).append(",\n")
              .append("      \"secure\":").append(secure).append(",\n")
              .append("      \"path\":").append(jStr(re.path)).append(",\n")
              .append("      \"expectedUsers\":").append(jStr(expUsers)).append(",\n")
              .append("      \"expectedRoles\":").append(jStr(expRoles)).append(",\n")
              .append("      \"description\":").append(jStr(desc)).append(",\n")
              .append("      \"rawRequest\":").append(jStr(rawReqB64)).append(",\n");

            // Stored test results for this request
            sb.append("      \"results\": [\n");
            if (ri < resultStore.length) {
                List<String> resParts = new ArrayList<>();
                for (int ui = 0; ui < resultStore[ri].length; ui++) {
                    TestResult tr = resultStore[ri][ui];
                    if (tr != null) {
                        String rawReqRes  = Base64.getEncoder().encodeToString(
                                tr.rawRequest.getBytes(StandardCharsets.UTF_8));
                        String rawRespRes = Base64.getEncoder().encodeToString(
                                tr.rawResponse.getBytes(StandardCharsets.UTF_8));
                        resParts.add("        {\"userIndex\":" + ui
                                + ",\"status\":" + jStr(tr.status)
                                + ",\"cell\":" + jStr(tr.cell)
                                + ",\"rawRequest\":" + jStr(rawReqRes)
                                + ",\"rawResponse\":" + jStr(rawRespRes)
                                + "}");
                    }
                }
                sb.append(String.join(",\n", resParts));
                if (!resParts.isEmpty()) sb.append("\n");
            }
            sb.append("      ]\n");
            sb.append("    }");
            if (ri < requests.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ]\n}\n");

        try {
            Files.writeString(out.toPath(), sb.toString(), StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(null,
                    "Session saved to:\n" + out.getAbsolutePath(),
                    "AuthMatrix – Saved", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(null,
                    "Save failed: " + ex.getMessage(),
                    "AuthMatrix – Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void loadSession() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Load AuthMatrix Session");
        fc.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));

        if (fc.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) return;

        try {
            String json = Files.readString(fc.getSelectedFile().toPath(), StandardCharsets.UTF_8);
            parseAndLoadSession(json);
            JOptionPane.showMessageDialog(null, "Session loaded successfully.",
                    "AuthMatrix – Loaded", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null,
                    "Load failed: " + ex.getMessage(),
                    "AuthMatrix – Error", JOptionPane.ERROR_MESSAGE);
            api.logging().logToError("AuthMatrix load error: " + ex.getMessage());
        }
    }

    /**
     * Minimal hand-rolled JSON parser — no external libraries required.
     * Handles the exact structure we write in saveSession().
     */
    private void parseAndLoadSession(String json) throws Exception {
        clearAll();

        // ── Parse users ───────────────────────────────────────────────────────
        String usersBlock = jsonArrayBlock(json, "users");
        for (String obj : jsonObjects(usersBlock)) {
            String name   = jsonStr(obj, "name");
            String header = jsonStr(obj, "header");
            String token  = jsonStr(obj, "token");
            String role   = jsonStr(obj, "role");
            UserEntry u = new UserEntry(name, header, token, role);
            users.add(u);
            userModel.addRow(new Object[]{u.name, u.tokenHeader, u.tokenValue, u.role});
        }

        // ── Parse requests ────────────────────────────────────────────────────
        String requestsBlock = jsonArrayBlock(json, "requests");
        for (String obj : jsonObjects(requestsBlock)) {
            String method     = jsonStr(obj, "method");
            String host       = jsonStr(obj, "host");
            int    port       = jsonInt(obj, "port", 443);
            boolean secure    = jsonBool(obj, "secure", true);
            String path       = jsonStr(obj, "path");
            String expUsers   = jsonStr(obj, "expectedUsers");
            String expRoles   = jsonStr(obj, "expectedRoles");
            String desc       = jsonStr(obj, "description");
            String rawReqB64  = jsonStr(obj, "rawRequest");

            byte[] rawBytes = Base64.getDecoder().decode(rawReqB64);
            HttpRequest req = HttpRequest.httpRequest(ByteArray.byteArray(rawBytes));
            HttpService svc = HttpService.httpService(host, port, secure);

            requests.add(new RequestEntry(req, svc, method, host, path));
            int idx = requests.size();
            String displayPath = method + "  " + path;
            requestModel.addRow(new Object[]{idx, displayPath, expUsers, expRoles, desc});

            Object[] row = new Object[3 + users.size()];
            row[0] = idx; row[1] = displayPath; row[2] = desc;
            Arrays.fill(row, 3, row.length, "–");
            resultModel.addRow(row);
        }

        // Rebuild result store with right dimensions
        rebuildResultStore();
        rebuildResultColumns();

        // ── Re-populate stored results ────────────────────────────────────────
        List<String> reqObjs = jsonObjects(requestsBlock);
        for (int ri = 0; ri < reqObjs.size() && ri < resultStore.length; ri++) {
            String resultsBlock = jsonArrayBlock(reqObjs.get(ri), "results");
            for (String resObj : jsonObjects(resultsBlock)) {
                int    ui      = jsonInt(resObj, "userIndex", -1);
                String status  = jsonStr(resObj, "status");
                String cell    = jsonStr(resObj, "cell");
                String rawReq  = new String(Base64.getDecoder().decode(jsonStr(resObj, "rawRequest")),  StandardCharsets.UTF_8);
                String rawResp = new String(Base64.getDecoder().decode(jsonStr(resObj, "rawResponse")), StandardCharsets.UTF_8);

                if (ui >= 0 && ui < resultStore[ri].length) {
                    resultStore[ri][ui] = new TestResult(rawReq, rawResp, status, cell);
                    final int r = ri, c = ui + 3, col = c;
                    final String v = cell;
                    SwingUtilities.invokeLater(() -> {
                        if (r < resultModel.getRowCount() && col < resultModel.getColumnCount())
                            resultModel.setValueAt(v, r, col);
                    });
                }
            }
        }
    }

    // ── Minimal JSON helpers ──────────────────────────────────────────────────

    /** Returns the raw content of a top-level JSON array by key. */
    private static String jsonArrayBlock(String json, String key) {
        String search = "\"" + key + "\"";
        int ki = json.indexOf(search);
        if (ki < 0) return "[]";
        int start = json.indexOf('[', ki + search.length());
        if (start < 0) return "[]";
        int depth = 0, i = start;
        while (i < json.length()) {
            char ch = json.charAt(i);
            if (ch == '[') depth++;
            else if (ch == ']') { depth--; if (depth == 0) return json.substring(start, i + 1); }
            else if (ch == '"') { i++; while (i < json.length() && json.charAt(i) != '"') { if (json.charAt(i) == '\\') i++; i++; } }
            i++;
        }
        return "[]";
    }

    /** Splits a JSON array string "[{...},{...}]" into a list of object strings "{...}". */
    private static List<String> jsonObjects(String arr) {
        List<String> result = new ArrayList<>();
        int i = 0;
        while (i < arr.length()) {
            if (arr.charAt(i) == '{') {
                int depth = 0, start = i;
                while (i < arr.length()) {
                    char ch = arr.charAt(i);
                    if (ch == '{') depth++;
                    else if (ch == '}') { depth--; if (depth == 0) { result.add(arr.substring(start, i + 1)); break; } }
                    else if (ch == '"') { i++; while (i < arr.length() && arr.charAt(i) != '"') { if (arr.charAt(i) == '\\') i++; i++; } }
                    i++;
                }
            }
            i++;
        }
        return result;
    }

    /** Reads a string value for a key from a flat JSON object string. */
    private static String jsonStr(String obj, String key) {
        String search = "\"" + key + "\"";
        int ki = obj.indexOf(search);
        if (ki < 0) return "";
        int colon = obj.indexOf(':', ki + search.length());
        if (colon < 0) return "";
        int q1 = obj.indexOf('"', colon + 1);
        if (q1 < 0) return "";
        StringBuilder sb = new StringBuilder();
        int i = q1 + 1;
        while (i < obj.length()) {
            char ch = obj.charAt(i);
            if (ch == '"') break;
            if (ch == '\\' && i + 1 < obj.length()) {
                char esc = obj.charAt(i + 1);
                switch (esc) {
                    case '"':  sb.append('"');  i += 2; continue;
                    case '\\': sb.append('\\'); i += 2; continue;
                    case 'n':  sb.append('\n'); i += 2; continue;
                    case 'r':  sb.append('\r'); i += 2; continue;
                    case 't':  sb.append('\t'); i += 2; continue;
                    default:   sb.append(esc);  i += 2; continue;
                }
            }
            sb.append(ch); i++;
        }
        return sb.toString();
    }

    private static int jsonInt(String obj, String key, int def) {
        String search = "\"" + key + "\"";
        int ki = obj.indexOf(search);
        if (ki < 0) return def;
        int colon = obj.indexOf(':', ki + search.length());
        if (colon < 0) return def;
        StringBuilder sb = new StringBuilder();
        int i = colon + 1;
        while (i < obj.length() && (Character.isDigit(obj.charAt(i)) || obj.charAt(i) == '-' || obj.charAt(i) == ' ')) {
            char c = obj.charAt(i++);
            if (c != ' ') sb.append(c);
        }
        try { return Integer.parseInt(sb.toString()); } catch (NumberFormatException e) { return def; }
    }

    private static boolean jsonBool(String obj, String key, boolean def) {
        String search = "\"" + key + "\"";
        int ki = obj.indexOf(search);
        if (ki < 0) return def;
        int colon = obj.indexOf(':', ki + search.length());
        if (colon < 0) return def;
        String rest = obj.substring(colon + 1).stripLeading();
        if (rest.startsWith("true"))  return true;
        if (rest.startsWith("false")) return false;
        return def;
    }

    /** Encodes a Java string as a JSON string literal (with escaping). */
    private static String jStr(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
        return sb.toString();
    }

    // =========================================================================
    // Detail view
    // =========================================================================
    private void showDetail(int ri, int ui) {
        if (ri >= resultStore.length || ui >= resultStore[ri].length) return;
        TestResult tr = resultStore[ri][ui];
        if (tr == null) return;

        renderHttp(detailRequestPane,  tr.rawRequest,  true);
        renderHttp(detailResponsePane, tr.rawResponse, false);

        if (!detailVisible) {
            detailPanel.setVisible(true);
            detailVisible = true;
            SwingUtilities.invokeLater(() -> {
                int total = mainSplit.getHeight();
                mainSplit.setDividerLocation((int)(total * 0.55));
            });
        }
    }

    private void hideDetail() {
        detailPanel.setVisible(false);
        detailVisible = false;
        detailRequestPane.setText("");
        detailResponsePane.setText("");
    }

    private void renderHttp(JTextPane pane, String raw, boolean isRequest) {
        StyledDocument doc = new DefaultStyledDocument();
        pane.setDocument(doc);

        Style base       = pane.addStyle("base",    null); StyleConstants.setFontFamily(base, Font.MONOSPACED); StyleConstants.setFontSize(base, 12); StyleConstants.setBackground(base, BG);
        Style styleFirst = pane.addStyle("first",   base); StyleConstants.setForeground(styleFirst, METHOD_COL);
        Style styleHdrK  = pane.addStyle("hdrKey",  base); StyleConstants.setForeground(styleHdrK,  HEADER_KEY);
        Style styleHdrV  = pane.addStyle("hdrVal",  base); StyleConstants.setForeground(styleHdrV,  HEADER_VAL);
        Style styleBody  = pane.addStyle("body",    base); StyleConstants.setForeground(styleBody,  BODY_COL);
        Style styleSep   = pane.addStyle("sep",     base); StyleConstants.setForeground(styleSep,   SEP_COL);

        if (raw == null || raw.isEmpty()) { appendStr(doc, "(no data)", styleBody); return; }

        boolean inBody = false, firstLine = true;
        for (String line : raw.split("\n", -1)) {
            String t = line.stripTrailing();
            if (firstLine) { appendStr(doc, t + "\n", styleFirst); firstLine = false; continue; }
            if (!inBody && t.isEmpty()) { appendStr(doc, "\n", styleSep); inBody = true; continue; }
            if (inBody) {
                appendStr(doc, t + "\n", styleBody);
            } else {
                int colon = t.indexOf(':');
                if (colon > 0) { appendStr(doc, t.substring(0, colon + 1), styleHdrK); appendStr(doc, t.substring(colon + 1) + "\n", styleHdrV); }
                else appendStr(doc, t + "\n", styleHdrK);
            }
        }
        pane.setCaretPosition(0);
    }

    private static void appendStr(StyledDocument doc, String text, Style style) {
        try { doc.insertString(doc.getLength(), text, style); } catch (BadLocationException ignored) {}
    }

    // =========================================================================
    // Helpers
    // =========================================================================
    private void syncUsersFromTable() {
        users.clear();
        for (int i = 0; i < userModel.getRowCount(); i++)
            users.add(new UserEntry(
                    str(userModel.getValueAt(i, 0)), str(userModel.getValueAt(i, 1)),
                    str(userModel.getValueAt(i, 2)), str(userModel.getValueAt(i, 3))));
    }

    private static String str(Object o) { return o == null ? "" : o.toString().trim(); }

    private void showHelp() {
        JOptionPane.showMessageDialog(null,
                "AuthMatrix – Montoya API Edition\n\n" +
                "── Setup ──────────────────────────────────────────\n" +
                "1. Right-click any request in Burp → 'Send to AuthMatrix'\n" +
                "2. Add users (Users panel):\n" +
                "   • Name / Header / Token Value / Role\n\n" +
                "── Expected access (Requests panel) ───────────────\n" +
                "   • Expected Users : comma-separated names  (e.g. Alice, Bob)\n" +
                "   • Expected Roles : comma-separated roles  (e.g. admin, editor)\n" +
                "   ⚠ Only ONE of the two columns per request.\n" +
                "   • Leave both empty → everyone should have access\n" +
                "   • Description : freetext note about the endpoint\n\n" +
                "── Results ────────────────────────────────────────\n" +
                "   ✅  Expected   🔴  Auth bypass!   🟡  Unexpected block\n" +
                "   Click any coloured cell → Request + Response detail\n\n" +
                "── Save / Load ─────────────────────────────────────\n" +
                "   💾 Save session → exports users, requests & results to .json\n" +
                "   💾 Load session → restores a previously saved .json\n\n" +
                "── Export CSV ──────────────────────────────────────\n" +
                "   📄 Exports the Results table to a .csv file\n",
                "AuthMatrix Help", JOptionPane.INFORMATION_MESSAGE);
    }

    // =========================================================================
    // Inner classes
    // =========================================================================
    static class UserEntry {
        String name, tokenHeader, tokenValue, role;
        UserEntry(String n, String h, String v, String r) { name=n; tokenHeader=h; tokenValue=v; role=r; }
    }

    static class RequestEntry {
        HttpRequest request; HttpService service; String method, host, path;
        RequestEntry(HttpRequest rq, HttpService svc, String m, String ho, String pa) { request=rq; service=svc; method=m; host=ho; path=pa; }
    }

    static class TestResult {
        String rawRequest, rawResponse, status, cell;
        TestResult(String req, String resp, String st, String c) { rawRequest=req; rawResponse=resp; status=st; cell=c; }
    }

    static class ResultRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean foc, int row, int col) {
            Component c = super.getTableCellRendererComponent(t, v, sel, foc, row, col);
            String s = v == null ? "" : v.toString();
            if (col >= 3) {
                if      (s.startsWith("✅")) { c.setBackground(new Color(180,240,180)); c.setForeground(Color.BLACK); }
                else if (s.startsWith("🔴")) { c.setBackground(new Color(255,160,160)); c.setForeground(Color.BLACK); }
                else if (s.startsWith("🟡")) { c.setBackground(new Color(255,240,140)); c.setForeground(Color.BLACK); }
                else                          { c.setBackground(Color.WHITE);             c.setForeground(Color.GRAY);  }
                if (sel) c.setBackground(c.getBackground().darker());
            } else {
                c.setBackground(sel ? t.getSelectionBackground() : Color.WHITE);
                c.setForeground(sel ? t.getSelectionForeground() : Color.BLACK);
            }
            return c;
        }
    }
}
