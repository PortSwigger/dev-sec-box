package DevSecBox;

import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import java.awt.*;
import java.awt.geom.Path2D;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;

interface DetailChangeListener {
    void onDetailChanged(String newDetail);
}

class Issue {
    public static boolean liveIssue;
    public static AuditIssueSeverity DEFAULT_SEVERITY = AuditIssueSeverity.INFORMATION;
    public static AuditIssueSeverity DEFAULT_TYPICAL_SEVERITY = AuditIssueSeverity.MEDIUM;
    public static AuditIssueConfidence DEFAULT_CONFIDENCE = AuditIssueConfidence.CERTAIN;

    public static void liveIssueON() {
        if (!liveIssue) {
            Issue.liveIssue = true;
            new Issue.Audit();
            Init.logging.logToOutput(Init.PREF + Init.DSB + "Live Audit has been loaded.");
        }

    }

    public static void liveIssueOFF() {
        if (liveIssue) {
            liveIssue = false;
            Audit.deregister();
            Audit.requestContextMap.forEach((id, future) -> future.complete(null));
            Audit.requestContextMap.clear();
            Audit.requestIdCounter.set(1);

            JInternalFrame solverFrame = Linker.СhainTaskList.stream()
                    .filter(frame -> Linker.TITLEsolver.equals(frame.getTitle()))
                    .findFirst()
                    .orElse(null);

            if (solverFrame != null) {
                Linker.removeConnections(solverFrame);
                solverFrame.dispose();
            }

            Init.Core.WorkflowPanel.revalidate();
            Init.Core.WorkflowPanel.repaint();
            Init.logging.logToOutput(Init.PREF + Init.DSB + "Live Audit has been unloaded.");
        }

    }

    public static class Audit implements ScanCheck {
        private static Registration registration;
        private static final ConcurrentMap<Integer, CompletableFuture<SolverData>> requestContextMap = new ConcurrentHashMap<>();
        private static final AtomicInteger requestIdCounter = new AtomicInteger(1);
        private static final int MAX_REQUEST_ID = Integer.MAX_VALUE - 1;

        public Audit() {
            registration = Init.api.scanner().registerScanCheck(this);
        }

        public static void deregister() {
            if (registration != null) {
                registration.deregister();
                registration = null;
            }
        }

        @Override
        public AuditResult passiveAudit(HttpRequestResponse httpRequestResponse) {
            if (!Hook.isActive || !Issue.liveIssue) {
                return AuditResult.auditResult();
            }
            int requestId = requestIdCounter.getAndUpdate(id -> (id >= MAX_REQUEST_ID) ? 1 : id + 1);
            CompletableFuture<SolverData> futureSolverData = new CompletableFuture<>();
            requestContextMap.put(requestId, futureSolverData);
            Linker.Pipe(sequencer(httpRequestResponse, requestId));
            return futureSolverData.thenCompose(solverData -> createStaticAuditIssue(httpRequestResponse, solverData))
                    .thenApply(auditIssue -> {
                        if (auditIssue != null) {
                            return AuditResult.auditResult(List.of(auditIssue));
                        }
                        return AuditResult.auditResult();
                    }).join();
        }

        @Override
        public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
            return AuditResult.auditResult();
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
            return ConsolidationAction.KEEP_BOTH;
        }

        public static CompletableFuture<AuditIssue> createStaticAuditIssue(HttpRequestResponse httpRequestResponse,
                SolverData solverData) {
            if (solverData == null) {
                return CompletableFuture.completedFuture(null);
            }

            String pref = determinePrefix();

            return CompletableFuture.completedFuture(AuditIssue.auditIssue(
                    pref + solverData.getTitle(),
                    solverData.getDetail(),
                    solverData.getRemediation(),
                    httpRequestResponse.request().url(),
                    solverData.getSeverity(),
                    solverData.getConfidence(),
                    solverData.getBackground(),
                    solverData.getRemediationBackground(),
                    solverData.getTypicalSeverity(),
                    List.of(httpRequestResponse)));
        }

        private static String determinePrefix() {
            StringBuilder activePlaceholders = new StringBuilder();
            for (Map.Entry<String, Boolean> buttonState : Init.Core.globalButtonState.getButtonStateMap().entrySet()) {
                if (buttonState.getValue()) {
                    activePlaceholders.append(buttonState.getKey()).append(" ");
                }
            }
            switch (Init.CURRENTOS) {
                case MAC:
                    return activePlaceholders + "DevSecBox: ";
                default:
                    return activePlaceholders + "□─■ DevSecBox: ";
            }
        }

        public static void jsonListener(JInternalFrame currentFrame) {
            Linker.frameListenerMap.put(currentFrame, data -> {
                for (Map<Object, Object> entry : data) {
                    Object DataObj = entry.keySet().iterator().next();
                    SolverData solverData = null;
                    ;
                    if (entry.containsKey(0)) {
                        DataObj = entry.get(DataObj);
                    } else {
                        String result = entry.get(DataObj).toString();

                        if (Addons.isJsonValid(result)) {
                            solverData = new SolverData();
                            String[] keys = { "title", "detail", "remediation", "background",
                                    "remediationBackground",
                                    "severity", "typicalSeverity", "confidence" };

                            for (String key : keys) {
                                String value = extractValueForKey(result, key);
                                if (value != null) {
                                    switch (key) {
                                        case "title":
                                            solverData.setTitle(value);
                                            break;
                                        case "detail":
                                            solverData.setDetail(value);
                                            break;
                                        case "remediation":
                                            solverData.setRemediation(value);
                                            break;
                                        case "background":
                                            solverData.setBackground(value);
                                            break;
                                        case "remediationBackground":
                                            solverData.setRemediationBackground(value);
                                            break;
                                        case "severity":
                                            solverData.setSeverity(parseSeverity(value));
                                            break;
                                        case "typicalSeverity":
                                            solverData.setTypicalSeverity(parseTypicalSeverity(value));
                                            break;
                                        case "confidence":
                                            solverData.setConfidence(parseConfidence(value));
                                            break;
                                    }
                                }
                            }
                        }
                    }

                    CompletableFuture<SolverData> future = requestContextMap.get(DataObj);
                    if (future != null) {
                        future.complete(solverData);
                    } else {
                        Init.logging
                                .logToError(Init.PREF + Init.DSB + "no matching solverIssue: " + DataObj);
                    }
                }
            });
        }

        private static AuditIssueSeverity parseSeverity(String value) {
            try {
                return AuditIssueSeverity.valueOf(value.toUpperCase());
            } catch (IllegalArgumentException e) {
                return Issue.DEFAULT_SEVERITY;
            }
        }

        private static AuditIssueSeverity parseTypicalSeverity(String value) {
            try {
                return AuditIssueSeverity.valueOf(value.toUpperCase());
            } catch (IllegalArgumentException e) {
                return Issue.DEFAULT_TYPICAL_SEVERITY;
            }
        }

        private static AuditIssueConfidence parseConfidence(String value) {
            try {
                return AuditIssueConfidence.valueOf(value.toUpperCase());
            } catch (IllegalArgumentException e) {
                return Issue.DEFAULT_CONFIDENCE;
            }
        }

        private static String extractValueForKey(String jsonString, String key) {
            String searchKey = "\"" + key + "\"";
            int keyIndex = jsonString.indexOf(searchKey);
            if (keyIndex == -1) {
                return null;
            }

            int colonIndex = jsonString.indexOf(":", keyIndex);
            if (colonIndex == -1) {
                return null;
            }

            int startQuoteIndex = jsonString.indexOf("\"", colonIndex);
            if (startQuoteIndex == -1) {
                return null;
            }

            int endQuoteIndex = jsonString.indexOf("\"", startQuoteIndex + 1);
            while (endQuoteIndex != -1 && jsonString.charAt(endQuoteIndex - 1) == '\\') {
                endQuoteIndex = jsonString.indexOf("\"", endQuoteIndex + 1);
            }

            if (endQuoteIndex == -1) {
                return null;
            }

            return jsonString.substring(startQuoteIndex + 1, endQuoteIndex);
        }

    }

    private static List<Object[]> sequencer(HttpRequestResponse httpRequestResponse, int ID) {
        Object[] data = new Object[] {
                httpRequestResponse.request().httpService().host(),
                httpRequestResponse.request().method(),
                httpRequestResponse.request().url(),
                httpRequestResponse.request().headers(),
                httpRequestResponse.request().body(),
                httpRequestResponse.response().headers(),
                httpRequestResponse.response().body(),
                ID
        };
        List<Object[]> dataList = new ArrayList<>();
        dataList.add(data);
        return dataList;
    }
}

class SolverData {
    private String title;
    private String detail;
    private String remediation;
    private String background;
    private String remediationBackground;
    private AuditIssueSeverity severity;
    private AuditIssueSeverity typicalSeverity;
    private AuditIssueConfidence confidence;

    public SolverData() {
        this.title = "";
        this.detail = "";
        this.remediation = "";
        this.background = "";
        this.remediationBackground = "";
        this.severity = Issue.DEFAULT_SEVERITY;
        this.typicalSeverity = Issue.DEFAULT_TYPICAL_SEVERITY;
        this.confidence = Issue.DEFAULT_CONFIDENCE;
    }

    public SolverData(String title, String detail, String remediation, String background,
            String remediationBackground, AuditIssueSeverity severity,
            AuditIssueSeverity typicalSeverity, AuditIssueConfidence confidence) {
        this.title = title;
        this.detail = detail;
        this.remediation = remediation;
        this.background = background;
        this.remediationBackground = remediationBackground;
        this.severity = severity;
        this.typicalSeverity = typicalSeverity;
        this.confidence = confidence;
    }

    public String getTitle() {
        return title;
    }

    public String getDetail() {
        return detail;
    }

    public String getRemediation() {
        return remediation;
    }

    public String getBackground() {
        return background;
    }

    public String getRemediationBackground() {
        return remediationBackground;
    }

    public AuditIssueSeverity getSeverity() {
        return severity;
    }

    public AuditIssueConfidence getConfidence() {
        return confidence;
    }

    public AuditIssueSeverity getTypicalSeverity() {
        return typicalSeverity;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    public void setRemediation(String remediation) {
        this.remediation = remediation;
    }

    public void setBackground(String background) {
        this.background = background;
    }

    public void setRemediationBackground(String remediationBackground) {
        this.remediationBackground = remediationBackground;
    }

    public void setSeverity(AuditIssueSeverity severity) {
        this.severity = severity;
    }

    public void setTypicalSeverity(AuditIssueSeverity typicalSeverity) {
        this.typicalSeverity = typicalSeverity;
    }

    public void setConfidence(AuditIssueConfidence confidence) {
        this.confidence = confidence;
    }

}

class ButtonState {
    private final Map<String, Boolean> buttonStateMap = new LinkedHashMap<>();
    private final Map<String, Color> buttonColorMap = new HashMap<>();
    private final Map<JButton, String> buttonIdentifierMap = new HashMap<>();
    private JTextArea inArea;
    public static int OneDimension = 30;

    public static final String[] PLACE_HOLDERS = { "🟩", "🟨", "🟪", "🟧", "🟦", "🟥", "🟫" };
    public static final String[] BUTTON_NAMES = { "Host", "HTTP Method", "URL", "Req. Header", "Req. Body",
            "Resp. Header",
            "Resp. Body", "ID" };

    public static final Color[] buttonColors = {
            new Color(200, 230, 201), // Light Green
            new Color(255, 241, 118), // Light Yellow
            new Color(224, 176, 255), // Light Purple
            new Color(255, 183, 77), // Light Orange
            new Color(130, 177, 255), // Light Blue
            new Color(255, 138, 128), // Light Red
            new Color(205, 133, 63) // Pastel Brown
    };

    public void deactivateAllButtons() {
        for (String identifier : buttonStateMap.keySet()) {
            buttonStateMap.put(identifier, false);
        }
        buttonColorMap.clear();
        updateStates();
    }

    public void setinArea(JTextArea inArea) {
        this.inArea = inArea;
        inArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                updateStates();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                updateStates();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                updateStates();
            }
        });
    }

    public void addButton(JButton button, String identifier, Color color) {
        buttonStateMap.put(identifier, false);
        buttonColorMap.put(identifier, color);
        buttonIdentifierMap.put(button, identifier);
        button.addActionListener(e -> toggleButtonState(identifier));
    }

    private void toggleButtonState(String identifier) {
        boolean currentState = buttonStateMap.get(identifier);
        buttonStateMap.put(identifier, !currentState);
        updateStates();
        updateinArea(identifier, !currentState);
    }

    private void updateinArea(String identifier, boolean isActive) {
        try {
            Document doc = inArea.getDocument();
            int caretPosition = inArea.getCaretPosition();
            if (isActive) {
                if (!inArea.getText().contains(identifier)) {
                    doc.insertString(caretPosition, identifier, null);
                }
            } else {
                String currentText = inArea.getText();
                String updatedText = currentText.replace(identifier, "").trim();
                inArea.setText(updatedText);
            }
        } catch (BadLocationException e) {
            e.printStackTrace();
        }
    }

    public void updateStates() {
        if (buttonIdentifierMap == null || buttonIdentifierMap.isEmpty() ||
                buttonStateMap == null || inArea == null) {
            return;
        }

        for (Map.Entry<JButton, String> entry : buttonIdentifierMap.entrySet()) {
            JButton button = entry.getKey();
            String identifier = entry.getValue();
            boolean isActive = inArea.getText().contains(identifier);
            buttonStateMap.put(identifier, isActive);
            updateButtonColor(button, identifier, isActive);
        }
    }

    private void updateButtonColor(JButton button, String identifier, boolean isActive) {
        if (isActive) {
            button.setBackground(buttonColorMap.get(identifier));
        } else {
            button.setBackground(null);
        }
    }

    public void clearPlaceholders() {
        inArea.setText("");
    }

    public Map<String, Boolean> getButtonStateMap() {
        return Collections.unmodifiableMap(buttonStateMap);
    }
}

class Addons {

    public static String convertColumnDataToString(Object columnData) {
        if (columnData instanceof String) {
            return (String) columnData;
        } else if (columnData instanceof byte[]) {
            return new String((byte[]) columnData, StandardCharsets.UTF_8);
        } else if (columnData instanceof List) {
            StringBuilder sb = new StringBuilder();
            List<?> list = (List<?>) columnData;
            for (int i = 0; i < list.size(); i++) {
                sb.append(list.get(i).toString());
                if (i < list.size() - 1) {
                    sb.append(System.lineSeparator());
                }
            }
            return sb.toString();
        } else {
            try {
                Method getBytesMethod = columnData.getClass().getMethod("getBytes");
                byte[] dataBytes = (byte[]) getBytesMethod.invoke(columnData);
                return new String(dataBytes, StandardCharsets.UTF_8);
            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                return columnData.toString();
            }
        }
    }

    public static String formatSize(long size) {
        if (size < 1_000) {
            return String.valueOf(size);
        } else if (size < 1_000_000) {
            return String.format("%.1fK", size / 1_000.0);
        } else if (size < 1_000_000_000) {
            return String.format("%.1fM", size / 1_000_000.0);
        } else if (size < 1_000_000_000_000L) {
            return String.format("%.1fB", size / 1_000_000_000.0);
        } else if (size < 1_000_000_000_000_000L) {
            return String.format("%.1fT", size / 1_000_000_000_000.0);
        } else {
            return "many...";
        }
    }

    public static void processJson(JTextArea jsonArea) {
        String jsonText = jsonArea.getText().trim();
        if (!jsonText.isEmpty()) {
            try {
                ObjectMapper objectMapper = new ObjectMapper();
                Object json = objectMapper.readValue(jsonText, Object.class);
                ObjectWriter writer = objectMapper.writerWithDefaultPrettyPrinter();
                String formattedJson = writer.writeValueAsString(json);
                jsonArea.setText(formattedJson);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(null,
                        "The JSON format is incorrect. Please review your input.",
                        "Invalid JSON Format",
                        JOptionPane.WARNING_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(null, "The JSON input is empty. Please provide valid JSON data.",
                    "Empty JSON", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    public static void importJson(JInternalFrame frame, JTextArea jsonArea) {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                String content = new String(Files.readAllBytes(Paths.get(file.getAbsolutePath())),
                        StandardCharsets.UTF_8);
                jsonArea.setText(content);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(frame, "Error loading file: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public static void exportJson(JInternalFrame frame, JTextArea jsonArea) {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showSaveDialog(frame) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                Files.write(Paths.get(file.getAbsolutePath()), jsonArea.getText().getBytes(StandardCharsets.UTF_8));
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(frame, "Error saving file: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public static void searchJson(JInternalFrame frame, JTextArea jsonArea) {
        String searchTerm = JOptionPane.showInputDialog(frame, "Enter text to search:");
        if (searchTerm != null && !searchTerm.isEmpty()) {
            String content = jsonArea.getText();
            int index = content.indexOf(searchTerm);
            if (index >= 0) {
                jsonArea.setCaretPosition(index);
                jsonArea.requestFocusInWindow();
                jsonArea.select(index, index + searchTerm.length());
            } else {
                JOptionPane.showMessageDialog(frame, "Text not found", "Search", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    public static void replaceJson(JInternalFrame frame, JTextArea jsonArea) {
        JPanel panel = new JPanel(new GridLayout(2, 2));
        JTextField searchField = new JTextField();
        JTextField replaceField = new JTextField();
        panel.add(new JLabel("Search:"));
        panel.add(searchField);
        panel.add(new JLabel("Replace with:"));
        panel.add(replaceField);

        int result = JOptionPane.showConfirmDialog(frame, panel, "Find and Replace", JOptionPane.OK_CANCEL_OPTION);
        if (result == JOptionPane.OK_OPTION) {
            String searchTerm = searchField.getText();
            String replaceTerm = replaceField.getText();
            if (searchTerm != null && !searchTerm.isEmpty()) {
                String content = jsonArea.getText();
                if (content.contains(searchTerm)) {
                    jsonArea.setText(content.replace(searchTerm, replaceTerm));
                } else {
                    JOptionPane.showMessageDialog(frame, "Text not found", "Replace",
                            JOptionPane.INFORMATION_MESSAGE);
                }
            }
        }
    }

    public static void validateJson(JTextArea jsonArea) {
        String jsonText = jsonArea.getText().trim();
        if (!jsonText.isEmpty()) {
            if (isJsonValid(jsonText)) {
                JOptionPane.showMessageDialog(null, "The JSON is valid.", "Validation Success",
                        JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(null, "The JSON format is incorrect. Please review your input.",
                        "Validation Error", JOptionPane.WARNING_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(null, "The JSON input is empty. Please provide valid JSON data.",
                    "Empty JSON", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static boolean isJsonValid(String json) {
        if (json == null || json.trim().isEmpty()) {
            return false;
        }
        try {
            objectMapper.readTree(json);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static final Map<String, String> EMOJI_UNICODE_MAP = Map.of(
            "🟩", "\\uD83D\\uDFE9",
            "🟨", "\\uD83D\\uDFE8",
            "🟪", "\\uD83D\\uDFEA",
            "🟧", "\\uD83D\\uDFE7",
            "🟦", "\\uD83D\\uDFE6",
            "🟥", "\\uD83D\\uDFE5",
            "🟫", "\\uD83D\\uDFEB");

    public static String escapeJsonString(String value) {
        String escapedValue = value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
        return replaceEmojis(escapedValue);
    }

    public static String unescapeJsonString(String value) {
        if (value == null) {
            return null;
        }
        return value.replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .replace("\\b", "\b")
                .replace("\\f", "\f")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t");
    }

    public static String escapeShellString(String value) {
        String escapedValue = value.replace("'", "\"");
        return replaceEmojis(escapedValue);
    }

    private static String replaceEmojis(String value) {
        for (Map.Entry<String, String> entry : EMOJI_UNICODE_MAP.entrySet()) {
            value = value.replace(entry.getKey(), entry.getValue());
        }
        return value;
    }

}

class Linker {
    private final String identifier;
    private final String replacement;
    private static final int LINE_SHORTENING_PIXELS = 10;
    public static int acquireTime = 10;
    public static int maxConcurrentProcesses = 1;
    public static int schedulerThreadCount = 1;
    public static int schedulerTimeout = 30;
    public static List<Connection> connections = new ArrayList<>();
    public static List<JInternalFrame> IsolatedTaskList = new ArrayList<>();
    public static List<JInternalFrame> СhainTaskList = new ArrayList<>();
    public static Map<JInternalFrame, Consumer<List<Map<Object, Object>>>> frameListenerMap = new HashMap<>();
    public static Map<JInternalFrame, List<Process>> frameProcessMap = new HashMap<>();
    public static Map<String, String> spoofMap = new HashMap<>();
    public static ScheduledExecutorService Scheduler = Executors.newScheduledThreadPool(1);
    public static Semaphore processSemaphore = new Semaphore(maxConcurrentProcesses);;
    public static String TITLEcatcher = "Catcher";
    public static String TITLEsender = "Sender";
    public static String TITLEsolver = "Solver [Burp Suite Professional]";
    public static String TITLEspoofer = "Spoofer";
    public static String TITLEtrigger = "Trigger";
    public static String[] WORKFLOWS = { "Live Workflow", "Manual Workflow" };

    public Linker(String identifier, String replacement) {
        this.identifier = identifier;
        this.replacement = replacement;
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getReplacement() {
        return replacement;
    }

    private static List<Map<Object, Object>> createOrUpdateMap(Object key, Object value) {
        Map<Object, Object> map = new HashMap<>();
        map.put(key, value);
        return Collections.singletonList(map);
    }

    public static void Pipe(List<Object[]> newRequestResponseData) {
        if (Linker.СhainTaskList.size() > 1) {
            List<Map<Object, Object>> keyValueList = newRequestResponseData.stream()
                    .map(entry -> {
                        Map<Object, Object> keyValueEntry = new HashMap<>();
                        for (int i = 0; i < entry.length; i++) {
                            Object DataObj = entry[i];
                            keyValueEntry.put(ButtonState.BUTTON_NAMES[i], DataObj);
                        }
                        return keyValueEntry;
                    })
                    .collect(Collectors.toList());

            Linker.frameListenerMap.getOrDefault(Linker.СhainTaskList.get(1), data -> {
            }).accept(keyValueList);
        }
    }

    public static void updateMaxConcurrentProcesses(int newMax) {
        maxConcurrentProcesses = newMax;
        if (Hook.isActive) {
            Linker.processSemaphore = new Semaphore(maxConcurrentProcesses);
        }
    }

    public static void updateSchedulerTimeout(int newTimeout) {
        schedulerTimeout = newTimeout;
        reinitializeScheduler();
    }

    public static void reinitializeScheduler() {
        Scheduler.shutdown();
        try {
            if (!Scheduler.awaitTermination(schedulerTimeout, TimeUnit.SECONDS)) {
                Scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            Scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
        Scheduler = Executors.newScheduledThreadPool(schedulerThreadCount);
    }

    public static JInternalFrame addConnection(JInternalFrame from, JInternalFrame to) {
        JInternalFrame newFrom = from;

        if (Linker.isSolverTask(to)) {
            if (Issue.liveIssue) {
                Issue.liveIssueOFF();
            } else {
                Issue.liveIssueON();
                if (Linker.СhainTaskList.get(0).getTitle().equals(Linker.WORKFLOWS[0])) {
                    Linker.addConnection(to,
                            Linker.СhainTaskList.get(0));
                }
            }

        }

        if (Linker.isSpooferTask(to)) {
            newFrom = СhainTaskList.get(0);
            Linker.connections.add(new Linker.Connection(newFrom, to));
            return newFrom;
        }

        if (Linker.isSolverTask(from)) {
            boolean connectionExists = Linker.connections.stream()
                    .anyMatch(connection -> connection.getFrom().equals(from)
                            && connection.getTo().equals(СhainTaskList.get(0)));

            if (connectionExists) {
                from.dispose();
                int index = Linker.СhainTaskList.indexOf(from);
                Linker.СhainTaskList.remove(from);
                if (index > 0) {
                    Issue.liveIssueOFF();
                    newFrom = Linker.СhainTaskList.get(index - 1);
                }
            }
        }

        Linker.connections.add(new Linker.Connection(newFrom, to));
        Init.Core.WorkflowPanel.revalidate();
        Init.Core.WorkflowPanel.repaint();
        return newFrom;
    }

    public static boolean isSolverTask(JInternalFrame frame) {
        return Linker.TITLEsolver.equals(frame.getTitle());
    }

    public static boolean isSpooferTask(JInternalFrame frame) {
        return Linker.TITLEspoofer.equals(frame.getTitle());
    }

    public static boolean issenderTask(JInternalFrame frame) {
        return Linker.TITLEsender.equals(frame.getTitle());
    }

    public static class Connection {
        private JInternalFrame from;
        private JInternalFrame to;
        private boolean visible;

        public Connection(JInternalFrame from, JInternalFrame to) {
            this.from = from;
            this.to = to;
            this.visible = true;
        }

        public JInternalFrame getFrom() {
            return from;
        }

        public JInternalFrame getTo() {
            return to;
        }

        public boolean involves(JInternalFrame frame) {
            return from.equals(frame) || to.equals(frame);
        }

        public void setVisible(boolean visible) {
            this.visible = visible;

        }

        public boolean isVisible() {
            return visible;
        }
    }

    public static void removeConnections(JInternalFrame frame) {
        Linker.frameListenerMap.remove(frame);
        Init.Core.WorkflowPanel.g2dLayer.remove(frame);
        if (Linker.isSpooferTask(frame)) {
            Linker.IsolatedTaskList.remove(frame);
            Linker.connections.removeIf(connection -> connection.getFrom().equals(frame)
                    || connection.getTo().equals(frame));
            Linker.spoofMap.clear();

        } else {
            frame.removeAll();
            List<Process> processes = Linker.frameProcessMap.get(frame);
            if (processes != null) {
                for (Process process : processes) {
                    try {
                        process.destroyForcibly();
                    } catch (Exception xe) {
                        xe.getMessage();
                    }
                }
            }
            Linker.frameProcessMap.remove(frame);
            int currentIndex = Linker.СhainTaskList.indexOf(frame);
            if (currentIndex == 1) {
                Init.Core.globalButtonState.deactivateAllButtons();
            }
            if (currentIndex == 0) {
                Init.Core.WorkflowPanel.clearAllComponents();
                Init.Core.WorkflowPanel.initUI(Init.api.userInterface());
            }
            Linker.СhainTaskList.remove(frame);
            Issue.liveIssueOFF();
        }

        connections.removeIf(connection -> connection.getTo().equals(frame));
        Init.Core.WorkflowPanel.revalidate();
        Init.Core.WorkflowPanel.repaint();
        frame.dispose();
    }

    public static void draw(Graphics2D g2d, Linker.Connection connection) {
        JInternalFrame from = connection.getFrom();
        JInternalFrame to = connection.getTo();
        if (!connection.isVisible()) {
            return;
        }
        boolean isFirstFrameIconified = Linker.СhainTaskList.get(0).isIcon();
        if (from.isVisible() && to.isVisible()) {
            Point fromCenter = new Point(from.getX() + from.getWidth() / 2, from.getY() + from.getHeight() / 2);
            Point toCenter = new Point(to.getX() + to.getWidth() / 2, to.getY() + to.getHeight() / 2);
            Point fromEdge = getEdgePoint(from, fromCenter, toCenter);
            Point toEdge = getEdgePoint(to, toCenter, fromCenter);
            double totalDistance = fromEdge.distance(toEdge);
            double shorteningFactor = LINE_SHORTENING_PIXELS / totalDistance;
            int dx = toEdge.x - fromEdge.x;
            int dy = toEdge.y - fromEdge.y;
            Point shortenedToEdge = new Point(
                    toEdge.x - (int) (dx * shorteningFactor),
                    toEdge.y - (int) (dy * shorteningFactor));

            if (isSpooferTask(from) || isSpooferTask(to)) {
                g2d.setColor(Color.DARK_GRAY);
                g2d.setStroke(
                        new BasicStroke(3, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 0,
                                new float[] { 0, 10 },
                                5));
                g2d.drawLine(fromEdge.x, fromEdge.y, shortenedToEdge.x, shortenedToEdge.y);
                drawArrow(g2d, toEdge, fromEdge);
                drawArrow(g2d, fromEdge, toEdge);
            } else {
                g2d.setColor(Color.GRAY);
                g2d.setStroke(
                        new BasicStroke(3, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 0,
                                new float[] { 0, 10 },
                                0));
                g2d.drawLine(fromEdge.x, fromEdge.y, shortenedToEdge.x, shortenedToEdge.y);
                if (isFirstFrameIconified) {
                    int squareSize = 13;
                    g2d.fillRect(fromEdge.x - squareSize / 2, fromEdge.y - squareSize / 2, squareSize, squareSize);
                }
                drawArrow(g2d, toEdge, fromEdge);
            }
        }
    }

    private static Point getEdgePoint(JInternalFrame frame, Point from, Point to) {
        Rectangle bounds = frame.getBounds();
        double dx = to.x - from.x;
        double dy = to.y - from.y;
        double slope = (dx != 0) ? dy / dx : 0;
        Point edgePoint = new Point();
        if (dx == 0) {
            edgePoint.x = from.x;
            edgePoint.y = (dy > 0) ? bounds.y + bounds.height : bounds.y;
        } else {
            double intercept = from.y - slope * from.x;
            if (to.x > from.x) {
                edgePoint.x = bounds.x + bounds.width;
            } else {
                edgePoint.x = bounds.x;
            }
            edgePoint.y = (int) (slope * edgePoint.x + intercept);
            if (edgePoint.y < bounds.y || edgePoint.y > bounds.y + bounds.height) {
                edgePoint.y = (to.y > from.y) ? bounds.y + bounds.height : bounds.y;
                edgePoint.x = (int) ((edgePoint.y - intercept) / slope);
            }
        }
        return edgePoint;
    }

    private static void drawArrow(Graphics2D g2d, Point to, Point control) {
        double arrowAngle = Math.toRadians(30);
        int arrowLength = 15;
        double dx = to.x - control.x;
        double dy = to.y - control.y;
        double angle = Math.atan2(dy, dx);
        Path2D arrowHead = new Path2D.Double();
        arrowHead.moveTo(to.x, to.y);
        arrowHead.lineTo(to.x - arrowLength * Math.cos(angle - arrowAngle),
                to.y - arrowLength * Math.sin(angle - arrowAngle));
        arrowHead.lineTo(to.x - arrowLength * 0.6 * Math.cos(angle),
                to.y - arrowLength * 0.6 * Math.sin(angle));
        arrowHead.lineTo(to.x - arrowLength * Math.cos(angle + arrowAngle),
                to.y - arrowLength * Math.sin(angle + arrowAngle));
        arrowHead.closePath();
        g2d.fill(arrowHead);
    }

    public static void catcherListener(JInternalFrame currentFrame,
            JTextArea inArea, JTextArea outArea, JTextArea defenderArea,
            ButtonState actualStateManager) {
        frameListenerMap.put(currentFrame, data -> {
            Object DataObj = null;
            for (Map<Object, Object> entry : data) {
                JInternalFrame nextFrame = getNextTask(currentFrame);
                if (entry.size() == 1) {
                    DataObj = entry.keySet().iterator().next();
                    if (entry.containsKey(0)) {
                        outArea.setText(null);
                        ClearNext(entry, nextFrame, entry.get(0));
                        continue;

                    }
                }

                String fullCommandHolder = inArea.getText();
                boolean inJSON = Addons.isJsonValid(fullCommandHolder);
                if (fullCommandHolder.isEmpty()) {
                    ClearNext(entry, nextFrame, DataObj);
                    continue;
                }

                boolean startsWithPlaceholder = Arrays.stream(ButtonState.PLACE_HOLDERS)
                        .anyMatch(fullCommandHolder::startsWith);

                if (startsWithPlaceholder) {
                    ClearNext(entry, nextFrame, DataObj);
                    continue;
                }

                fullCommandHolder = applyReplacements(DataObj, fullCommandHolder, inJSON, entry, actualStateManager);
                if (fullCommandHolder.isEmpty()) {
                    ClearNext(entry, nextFrame, DataObj);
                    continue;
                }

                if (DataObj == null) {
                    DataObj = entry.get(ButtonState.BUTTON_NAMES[ButtonState.BUTTON_NAMES.length - 1]);
                }

                boolean outJSON = Addons.isJsonValid(fullCommandHolder);
                if (outJSON) {
                    if (nextFrame != null) {
                        frameListenerMap.get(nextFrame).accept(createOrUpdateMap(DataObj, fullCommandHolder));
                    }

                    outArea.setText(fullCommandHolder);
                } else {
                    createWorker(fullCommandHolder, DataObj, nextFrame, outArea).execute();
                }
            }
        });

    }

    private static void ClearNext(Map<Object, Object> entry, JInternalFrame nextFrame, Object DataObj) {
        if (DataObj == null && entry != null) {
            DataObj = entry.get(ButtonState.BUTTON_NAMES[ButtonState.BUTTON_NAMES.length - 1]);
        }
        if (nextFrame != null) {
            frameListenerMap.get(nextFrame).accept(createOrUpdateMap(0, DataObj));
        }
    }

    private static JInternalFrame getNextTask(JInternalFrame currentFrame) {
        int currentIndex = Linker.СhainTaskList.indexOf(currentFrame);
        if (currentIndex + 1 >= Linker.СhainTaskList.size()) {
            return null;
        }
        return Linker.СhainTaskList.get(currentIndex + 1);
    }

    private static SwingWorker<Void, String> createWorker(String command,
            Object DataObj,
            JInternalFrame nextFrame,
            JTextArea outArea) {
        return new SwingWorker<>() {

            @Override
            protected Void doInBackground() throws Exception {
                boolean acquired = false;
                try {
                    acquired = processSemaphore.tryAcquire(Linker.acquireTime, TimeUnit.SECONDS);
                    if (!acquired) {
                        Init.logging.logToOutput(
                                Init.PREF + Init.DSB + "timeout acquire semaphore. infectionping execution.");
                        return null;
                    }

                    if (Hook.isActive) {
                        ProcessBuilder processBuilder = new ProcessBuilder();
                        switch (Init.CURRENTOS) {
                            case WINDOWS:
                                processBuilder.command("powershell.exe", "-ExecutionPolicy", "Bypass",
                                        "-Command", command);
                                break;
                            default:
                                processBuilder.command("sh", "-c", command);
                                break;
                        }
                        processBuilder.redirectErrorStream(true);
                        Process process = processBuilder.start();
                        frameProcessMap.computeIfAbsent(nextFrame, k -> new ArrayList<>()).add(process);

                        if (!process.waitFor(Linker.schedulerTimeout, TimeUnit.SECONDS)) {
                            process.destroy();
                            ClearNext(null, nextFrame, DataObj);
                            String truncatedCommand = command.length() > 100 ? command.substring(0, 100) + " ..."
                                    : command;
                            Init.logging.logToOutput(
                                    Init.PREF + Init.DSB + "process \"" + truncatedCommand
                                            + "\" terminated due to timeout.");
                            return null;
                        }

                        try (BufferedReader reader = new BufferedReader(
                                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                            StringBuilder outputBuilder = new StringBuilder();
                            String line;
                            boolean firstLine = true;
                            while ((line = reader.readLine()) != null) {
                                if (!firstLine) {
                                    outputBuilder.append(System.lineSeparator());
                                }
                                outputBuilder.append(line);
                                firstLine = false;
                            }

                            publish(outputBuilder.toString());
                        }

                    } else {
                        return null;
                    }
                } catch (IOException ex) {
                    ClearNext(null, nextFrame, DataObj);
                    Init.logging.logToError(
                            Init.PREF + Init.DSB + "error executing command: " + ex.getMessage());
                } finally {
                    if (acquired) {
                        processSemaphore.release();
                    }
                }
                return null;
            }

            @Override
            protected void process(java.util.List<String> chunks) {
                String commandResult = chunks.isEmpty() ? "" : chunks.get(0);

                if (commandResult.isEmpty()) {
                    ClearNext(null, nextFrame, DataObj);
                    return;
                }

                if (nextFrame != null) {
                    frameListenerMap.get(nextFrame).accept(createOrUpdateMap(DataObj, commandResult));
                }

                outArea.setText(commandResult);
            }

            @Override
            protected void done() {
                try {
                    get();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        };
    }

    private static boolean containsUnreadableCharacters(String input) {
        for (char c : input.toCharArray()) {
            if (c < 0x20 || c == 0x7F) {
                if (c != '\n' && c != '\r' && c != '\t' && c != ' ') {
                    return true;
                }
            }
        }
        return false;
    }

    private static String applyReplacements(Object DataObj, String fullCommandHolder, boolean inJSON,
            Map<Object, Object> entry, ButtonState actualStateManager) {
        List<Linker> replacements = new ArrayList<>();
        if (DataObj != null) {

            String DataString = entry.get(DataObj).toString();

            if (containsUnreadableCharacters(DataString)) {
                DataString = null;
            }

            if (DataString != null) {
                String replacement = inJSON ? Addons.escapeJsonString(DataString)
                        : Addons.escapeShellString(DataString);
                replacements.add(new Linker(ButtonState.PLACE_HOLDERS[0], replacement));
            }

        } else {
            for (Map.Entry<String, Boolean> buttonState : actualStateManager.getButtonStateMap().entrySet()) {

                String identifier = buttonState.getKey();
                if (buttonState.getValue()) {
                    int index = Arrays.asList(ButtonState.PLACE_HOLDERS).indexOf(identifier);
                    DataObj = entry.get(ButtonState.BUTTON_NAMES[index]);
                    String DataString = "";
                    if (DataObj != null) {
                        try {
                            if (DataObj instanceof String || DataObj instanceof List) {
                                DataString = Addons.convertColumnDataToString(DataObj);
                            } else {
                                byte[] dataBytes;
                                if (DataObj instanceof byte[]) {
                                    dataBytes = (byte[]) DataObj;
                                } else {
                                    Method getBytesMethod = DataObj.getClass().getMethod("getBytes");
                                    dataBytes = (byte[]) getBytesMethod.invoke(DataObj);
                                }
                                DataString = new String(dataBytes, StandardCharsets.UTF_8);
                            }
                        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                            DataString = null;
                        }
                        if (containsUnreadableCharacters(DataString)) {
                            DataString = null;
                        }

                    }
                    if (DataString != null) {
                        String replacement = inJSON ? Addons.escapeJsonString(DataString)
                                : Addons.escapeShellString(DataString);
                        replacements.add(new Linker(identifier, replacement));
                    }

                }
            }
        }

        boolean allReplacementsEmpty = replacements.stream()
                .allMatch(r -> r.getReplacement().isEmpty());
        if (allReplacementsEmpty) {
            return "";
        }

        if (!inJSON) {
            replacements.sort((r1, r2) -> Integer.compare(
                    fullCommandHolder.indexOf(r1.getIdentifier()),
                    fullCommandHolder.indexOf(r2.getIdentifier())));

            StringBuilder commandBuilder = new StringBuilder(fullCommandHolder);

            for (Linker replacement : replacements) {
                String replacementValue = "'" + replacement.getReplacement() + "'";
                int placeholderIndex = commandBuilder.indexOf(replacement.getIdentifier());

                while (placeholderIndex != -1) {
                    commandBuilder.replace(placeholderIndex, placeholderIndex + replacement.getIdentifier().length(),
                            replacementValue);
                    placeholderIndex = commandBuilder.indexOf(replacement.getIdentifier(),
                            placeholderIndex + replacementValue.length());
                }
            }

            return commandBuilder.toString();
        } else {
            StringBuilder commandBuilder = new StringBuilder(fullCommandHolder);
            for (Linker replacement : replacements) {
                int start = commandBuilder.indexOf(replacement.getIdentifier());
                while (start != -1) {
                    commandBuilder.replace(start, start + replacement.getIdentifier().length(),
                            replacement.getReplacement());
                    start = commandBuilder.indexOf(replacement.getIdentifier(),
                            start + replacement.getReplacement().length());
                }
            }
            return commandBuilder.toString();
        }
    }
}