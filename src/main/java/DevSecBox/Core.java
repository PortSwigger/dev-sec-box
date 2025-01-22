package DevSecBox;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.MouseMotionListener;
import java.awt.image.BufferedImage;
import java.io.InputStream;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.event.InternalFrameAdapter;
import javax.swing.event.InternalFrameEvent;
import javax.swing.event.InternalFrameListener;
import javax.swing.plaf.basic.BasicInternalFrameTitlePane;
import javax.swing.plaf.basic.BasicInternalFrameUI;
import javax.swing.table.DefaultTableModel;
import javax.swing.undo.UndoManager;

interface DataReceiver {
    void onlineReceiver(List<Object[]> requestResponseData);
}

public class Core implements DataReceiver {
    public final WorkflowPanel WorkflowPanel = new WorkflowPanel();
    public final ButtonState globalButtonState = new ButtonState();

    public Core() {
        SwingUtilities.invokeLater(() -> {
            Init.api.userInterface().registerSuiteTab("DevSecBox", WorkflowPanel);
            Init.api.userInterface().registerContextMenuItemsProvider(new MenuProvider());
            Init.api.logging().logToOutput(Init.PREF + Init.DSB + "orchestrator loaded - " + Linker.WORKFLOWS[1]);
        });
    }

    interface ColumnStateListener {
        void onColumnStateChanged(boolean[] columnStates);
    }

    @Override
    public void onlineReceiver(List<Object[]> requestResponseData) {
        if (WorkflowPanel.liveSwitch.isSelected()) {
            Linker.Pipe(requestResponseData);
        }
    }

    public void offlineReceiver(List<Object[]> requestResponseData) {
        Linker.Pipe(requestResponseData);
    }

    public class WorkflowPanel extends JPanel {
        private boolean editMode = false;
        private BufferedImage backgroundImage;
        private double SCALE = 1.0;
        private double CROP = 2.8;
        private static final int WIDTH = 250;
        private static final int HEIGHT = 200;
        private final int MINSIZE = 80;
        private JButton zoomIn;
        private JButton zoomOut;
        public JLayeredPane g2dLayer;
        private JPanel uiPanel;
        private JToggleButton liveSwitch;
        private Point initialClick;
        private boolean dragging = false;

        public void setLiveSwitchState(boolean state) {
            liveSwitch.setSelected(state);
        }

        public Map<String, String> getReplacements() {
            return Linker.spoofMap;
        }

        public WorkflowPanel() {
            initUI();
        }

        public void initUI() {
            this.setLayout(new BorderLayout());
            this.g2dLayer = new JLayeredPane() {
                @Override
                protected void paintComponent(Graphics g) {
                    super.paintComponent(g);
                    Graphics2D g2d = (Graphics2D) g;
                    for (Linker.Connection connection : Linker.connections) {
                        Linker.draw(g2d, connection);
                    }
                }
            };

            g2dLayer.addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    if (SwingUtilities.isLeftMouseButton(e)) {
                        initialClick = e.getPoint();
                        dragging = true;
                    } else if (SwingUtilities.isRightMouseButton(e)) {
                        showContextMenu(e);
                    }
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    dragging = false;
                }
            });

            g2dLayer.addMouseMotionListener(new MouseAdapter() {
                @Override
                public void mouseDragged(MouseEvent e) {
                    if (dragging) {
                        Point currentPoint = e.getPoint();
                        int deltaX = currentPoint.x - initialClick.x;
                        int deltaY = currentPoint.y - initialClick.y;
                        for (Component component : g2dLayer.getComponents()) {
                            if (component instanceof JInternalFrame) {
                                JInternalFrame frame = (JInternalFrame) component;
                                frame.setLocation(frame.getX() + deltaX, frame.getY() + deltaY);
                            }
                        }
                        initialClick = currentPoint;
                        g2dLayer.repaint();
                    }
                }
            });

            uiPanel = new JPanel();
            zoomIn = new JButton("+");
            zoomOut = new JButton("-");
            zoomIn.addActionListener(e -> {
                setScale(getScale() * CROP);
                updateButtonStates(zoomOut);
            });
            zoomOut.addActionListener(e -> {
                double newScale = getScale() / CROP;
                if (canScaleDown(newScale)) {
                    setScale(newScale);
                    updateButtonStates(zoomOut);
                }
            });

            zoomIn.setVisible(false);
            zoomOut.setVisible(false);

            backgroundImage = loadAndRender();
            liveSwitch = new JToggleButton("Live Workflow");
            liveSwitch.addItemListener(e -> {
                if (!zoomIn.isVisible()) {
                    zoomIn.setVisible(true);
                    zoomOut.setVisible(true);
                }
                if (liveSwitch.isSelected()) {
                    if (Linker.СhainTaskList.isEmpty()) {
                        triggerTask(100, 100);
                    }
                    Linker.СhainTaskList.get(0).setTitle(Linker.WORKFLOWS[0]);
                } else {
                    if (Linker.СhainTaskList.isEmpty()) {
                        triggerTask(100, 100);
                    }
                    Issue.liveIssueOFF();
                    Linker.СhainTaskList.get(0).setTitle(Linker.WORKFLOWS[1]);
                }
            });

            uiPanel.add(zoomIn);
            uiPanel.add(liveSwitch);
            uiPanel.add(zoomOut);
            this.add(uiPanel, BorderLayout.SOUTH);
            this.add(g2dLayer, BorderLayout.CENTER);
            revalidate();
            repaint();
        }

        private BufferedImage loadAndRender() {
            try (InputStream pngStream = getClass().getClassLoader().getResourceAsStream("DSB.PNG")) {
                if (pngStream != null) {
                    return ImageIO.read(pngStream);
                }
            } catch (IOException e) {
            }
            return null;
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            if (backgroundImage != null) {
                int panelWidth = getWidth();
                int panelHeight = getHeight();
                double scale = Math.min(panelWidth, panelHeight) * 0.4
                        / Math.min(backgroundImage.getWidth(), backgroundImage.getHeight());

                int newWidth = (int) (backgroundImage.getWidth() * scale);
                int newHeight = (int) (backgroundImage.getHeight() * scale);

                int x = (panelWidth - newWidth) / 2;
                int y = (panelHeight - newHeight) / 2;

                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
                g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2d.drawImage(backgroundImage, x, y, newWidth, newHeight, this);

                for (Linker.Connection connection : Linker.connections) {
                    Linker.draw(g2d, connection);
                }
            }
        }

        public void clearAllComponents() {
            Hook.Shutdown();
            globalButtonState.deactivateAllButtons();
            SCALE = 1.0;
            g2dLayer.removeAll();
            Linker.connections.clear();
            Linker.frameListenerMap.clear();
            Linker.frameProcessMap.clear();
            Linker.IsolatedTaskList.clear();
            Linker.СhainTaskList.clear();
            liveSwitch.setEnabled(true);
            for (MouseListener listener : getMouseListeners()) {
                removeMouseListener(listener);
            }
            for (MouseMotionListener listener : getMouseMotionListeners()) {
                removeMouseMotionListener(listener);
            }
            uiPanel.removeAll();
            zoomOut.setEnabled(true);
            removeAll();
        }

        private boolean canScaleDown(double newScale) {
            List<JInternalFrame> combinedTaskList = new ArrayList<>();
            combinedTaskList.addAll(Linker.СhainTaskList);
            combinedTaskList.addAll(Linker.IsolatedTaskList);

            for (JInternalFrame component : combinedTaskList) {
                int newWidth = (int) (component.getWidth() * newScale / getScale());
                if (newWidth < MINSIZE) {
                    return false;
                }
            }
            return true;
        }

        private void updateButtonStates(JButton zoomOut) {
            boolean canScaleDown = canScaleDown(getScale() / CROP);
            zoomOut.setEnabled(canScaleDown);
        }

        public double getScale() {
            return SCALE;
        }

        public void setScale(double newScale) {
            double factor = newScale / SCALE;
            SCALE = newScale;
            List<JInternalFrame> combinedTaskList = new ArrayList<>();
            combinedTaskList.addAll(Linker.СhainTaskList);
            combinedTaskList.addAll(Linker.IsolatedTaskList);

            for (JInternalFrame component : combinedTaskList) {
                component.setBounds(
                        (int) (component.getX() * factor),
                        (int) (component.getY() * factor),
                        (int) (component.getWidth() * factor),
                        (int) (component.getHeight() * factor));
            }
            g2dLayer.revalidate();
            g2dLayer.repaint();
        }

        public class SwingUtils {
            public static JInternalFrame suiteFrame(String name, int x, int y, int width, int height) {
                JInternalFrame frame = new JInternalFrame(name, false, true, true, false) {
                    @Override
                    public void setFrameIcon(Icon icon) {
                    }
                };
                frame.setBounds(x, y, width, height);
                frame.setVisible(true);
                frame.setFocusable(true);
                frame.setDefaultCloseOperation(JInternalFrame.DO_NOTHING_ON_CLOSE);

                Color titleBackgroundColor = new Color(94, 130, 174);
                Color titleForegroundColor = Color.WHITE;
                UIManager.put("InternalFrame.activeTitleBackground", titleBackgroundColor);
                UIManager.put("InternalFrame.inactiveTitleBackground", titleBackgroundColor);
                UIManager.put("InternalFrame.activeTitleForeground", titleForegroundColor);
                UIManager.put("InternalFrame.inactiveTitleForeground", titleForegroundColor);

                BasicInternalFrameUI ui = (BasicInternalFrameUI) frame.getUI();
                JComponent northPane = ui.getNorthPane();
                if (northPane instanceof BasicInternalFrameTitlePane) {
                    BasicInternalFrameTitlePane titlePane = (BasicInternalFrameTitlePane) northPane;
                    titlePane.addMouseListener(new MouseAdapter() {
                        @Override
                        public void mousePressed(MouseEvent e) {
                            frame.moveToFront();
                        }
                    });
                }
                Init.Core.WorkflowPanel.frameAction(frame);

                return frame;
            }
        }

        public void triggerTask(int x, int y) {
            SwingUtilities.invokeLater(() -> {
                backgroundImage = null;
                JInternalFrame frame = SwingUtils.suiteFrame("", x, y, (int) (WIDTH * SCALE), (int) (HEIGHT * SCALE));
                if (liveSwitch.isSelected()) {
                    frame.setTitle(Linker.WORKFLOWS[0]);
                } else {
                    Issue.liveIssueOFF();
                    frame.setTitle(Linker.WORKFLOWS[1]);
                }

                frame.setMaximizable(false);
                Linker.СhainTaskList.add(frame);
                JTabbedPane tabbedPanel = new JTabbedPane();
                JPanel buttonPanel = new JPanel(new GridBagLayout());
                GridBagConstraints gbc = new GridBagConstraints();

                JPanel layoutPanel = new JPanel();
                layoutPanel.setBorder(null);

                JPanel notesPanel = new JPanel(new BorderLayout());
                JTextArea notesArea = new JTextArea();
                notesArea.setLineWrap(true);
                notesArea.setWrapStyleWord(true);
                JScrollPane notesScrollPane = new JScrollPane(notesArea);
                notesScrollPane.setBorder(null);
                notesPanel.add(notesScrollPane, BorderLayout.CENTER);

                JSpinner semaphoreSpinner = new JSpinner(
                        new SpinnerNumberModel(Linker.maxConcurrentProcesses, 1, 5, 1));
                semaphoreSpinner.addChangeListener(e -> {
                    int newMax = (int) semaphoreSpinner.getValue();
                    Linker.updateMaxConcurrentProcesses(newMax);
                });

                JSpinner schedulerSpinner = new JSpinner(new SpinnerNumberModel(Linker.schedulerThreadCount, 1, 5, 1));
                schedulerSpinner.addChangeListener(e -> {
                    int newThreadCount = (int) schedulerSpinner.getValue();
                    Linker.schedulerThreadCount = newThreadCount;
                    Linker.reinitializeScheduler();
                });

                JSpinner timeoutSpinner = new JSpinner(
                        new SpinnerNumberModel(Linker.schedulerTimeout, 1, Integer.MAX_VALUE, 5));
                timeoutSpinner.addChangeListener(e -> {
                    int selectedTimeout = (int) timeoutSpinner.getValue();
                    Linker.updateSchedulerTimeout(selectedTimeout);
                });

                JSpinner acquireTimeSpinner = new JSpinner(
                        new SpinnerNumberModel(Linker.acquireTime, 1, Integer.MAX_VALUE, 5));
                acquireTimeSpinner.addChangeListener(e -> {
                    int newAcquireTime = (int) acquireTimeSpinner.getValue();
                    Linker.acquireTime = newAcquireTime;
                });

                JComponent editor = semaphoreSpinner.getEditor();
                JFormattedTextField textField = ((JSpinner.DefaultEditor) editor).getTextField();
                textField.setPreferredSize(new Dimension(30, textField.getPreferredSize().height));

                editor = schedulerSpinner.getEditor();
                textField = ((JSpinner.DefaultEditor) editor).getTextField();
                textField.setPreferredSize(new Dimension(30, textField.getPreferredSize().height));

                editor = timeoutSpinner.getEditor();
                textField = ((JSpinner.DefaultEditor) editor).getTextField();
                textField.setPreferredSize(new Dimension(30, textField.getPreferredSize().height));

                editor = acquireTimeSpinner.getEditor();
                textField = ((JSpinner.DefaultEditor) editor).getTextField();
                textField.setPreferredSize(new Dimension(30, textField.getPreferredSize().height));

                JPanel settingsPanel = new JPanel(new GridBagLayout());
                GridBagConstraints settingsGbc = new GridBagConstraints();
                settingsGbc.insets = new Insets(5, 5, 5, 5);
                settingsGbc.fill = GridBagConstraints.HORIZONTAL;
                settingsGbc.weightx = 1.0;

                settingsGbc.gridx = 0;
                settingsGbc.gridy = 0;
                settingsGbc.anchor = GridBagConstraints.WEST;
                settingsPanel.add(new JLabel("acquire"), settingsGbc);

                settingsGbc.gridx = 1;
                settingsGbc.anchor = GridBagConstraints.EAST;
                settingsPanel.add(acquireTimeSpinner, settingsGbc);

                settingsGbc.gridx = 0;
                settingsGbc.gridy = 1;
                settingsGbc.anchor = GridBagConstraints.WEST;
                settingsPanel.add(new JLabel("timeout"), settingsGbc);

                settingsGbc.gridx = 1;
                settingsGbc.anchor = GridBagConstraints.EAST;
                settingsPanel.add(timeoutSpinner, settingsGbc);

                settingsGbc.gridx = 0;
                settingsGbc.gridy = 2;
                settingsGbc.anchor = GridBagConstraints.WEST;
                settingsPanel.add(new JLabel("thds."), settingsGbc);

                settingsGbc.gridx = 1;
                settingsGbc.anchor = GridBagConstraints.EAST;
                settingsPanel.add(schedulerSpinner, settingsGbc);

                settingsGbc.gridx = 0;
                settingsGbc.gridy = 3;
                settingsGbc.anchor = GridBagConstraints.WEST;
                settingsPanel.add(new JLabel("conc."), settingsGbc);

                settingsGbc.gridx = 1;
                settingsGbc.anchor = GridBagConstraints.EAST;
                settingsPanel.add(semaphoreSpinner, settingsGbc);

                int fixedButtonCount = 7;
                gbc.insets = new Insets(5, 5, 5, 5);
                JButton[] buttons = new JButton[fixedButtonCount];
                for (int i = 0; i < fixedButtonCount; i++) {
                    JButton button = new JButton(ButtonState.BUTTON_NAMES[i]);
                    buttons[i] = button;
                    globalButtonState.addButton(buttons[i], ButtonState.PLACE_HOLDERS[i],
                            ButtonState.buttonColors[i]);
                    switch (i) {
                        case 0:
                            gbc.gridx = 0;
                            gbc.gridy = 0;
                            gbc.gridwidth = 2;
                            gbc.fill = GridBagConstraints.HORIZONTAL;
                            break;
                        case 1:
                            gbc.gridx = 0;
                            gbc.gridy = 1;
                            gbc.gridwidth = 1;
                            break;
                        case 2:
                            gbc.gridx = 1;
                            gbc.gridy = 1;
                            break;
                        case 3:
                            gbc.gridx = 0;
                            gbc.gridy = 2;
                            break;
                        case 4:
                            gbc.gridx = 1;
                            gbc.gridy = 2;
                            break;
                        case 5:
                            gbc.gridx = 0;
                            gbc.gridy = 3;
                            break;
                        case 6:
                            gbc.gridx = 1;
                            gbc.gridy = 3;
                            break;
                    }
                    buttonPanel.add(button, gbc);
                }

                tabbedPanel.addTab("trigger", buttonPanel);
                tabbedPanel.addTab("booster", settingsPanel);
                tabbedPanel.addTab("notes", notesPanel);
                frame.getContentPane().add(tabbedPanel);
                g2dLayer.add(frame, JLayeredPane.DEFAULT_LAYER);
                globalButtonState.updateStates();
                Hook.Start();
            });
        }

        public void catcherTask(String name, int x, int y, JInternalFrame fromFrame) {
            JInternalFrame frame = SwingUtils.suiteFrame(name, x, y, (int) (WIDTH * SCALE), (int) (HEIGHT * SCALE));
            Linker.СhainTaskList.add(frame);
            JTabbedPane tabbedPanel = new JTabbedPane();

            JPanel inPanel = new JPanel(new BorderLayout());
            JPanel outPanel = new JPanel(new BorderLayout());
            JPanel notesPanel = new JPanel(new BorderLayout());

            JTextArea inArea = new JTextArea();
            JTextArea outArea = new JTextArea();
            JTextArea notesArea = new JTextArea();
            JTextArea defenderArea = new JTextArea();

            outArea.setEditable(false);
            outArea.setLineWrap(true);
            outArea.setWrapStyleWord(true);

            notesArea.setLineWrap(true);
            notesArea.setWrapStyleWord(true);

            defenderArea.setEditable(false);
            defenderArea.setLineWrap(true);
            defenderArea.setWrapStyleWord(true);

            inArea.setLineWrap(true);
            inArea.setWrapStyleWord(true);

            JScrollPane inScrollPane = new JScrollPane(inArea);
            JScrollPane outScrollPane = new JScrollPane(outArea);
            JScrollPane notesScrollPane = new JScrollPane(notesArea);

            inScrollPane.setBorder(null);
            outScrollPane.setBorder(null);
            notesScrollPane.setBorder(null);

            inPanel.add(inScrollPane, BorderLayout.CENTER);
            outPanel.add(outScrollPane, BorderLayout.CENTER);
            notesPanel.add(notesScrollPane, BorderLayout.CENTER);

            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));
            inArea.setBackground(buttonPanel.getBackground());
            ButtonState actualStateManager;

            if (Linker.СhainTaskList.stream().count() < 3) {
                actualStateManager = globalButtonState;
                actualStateManager.setinArea(inArea);
                JButton[] buttons = new JButton[ButtonState.PLACE_HOLDERS.length];

                for (int i = 0; i < buttons.length; i++) {
                    buttons[i] = new JButton("");
                    buttons[i].setPreferredSize(
                            new Dimension(ButtonState.OneDimension, buttons[i].getPreferredSize().height));
                    actualStateManager.addButton(buttons[i], ButtonState.PLACE_HOLDERS[i],
                            ButtonState.buttonColors[i]);
                    buttonPanel.add(buttons[i]);
                }
            } else {
                actualStateManager = new ButtonState();

                actualStateManager.setinArea(inArea);
                JButton resultButton = new JButton();
                resultButton.setPreferredSize(
                        new Dimension(ButtonState.OneDimension, resultButton.getPreferredSize().height));
                actualStateManager.addButton(resultButton, ButtonState.PLACE_HOLDERS[0],
                        ButtonState.buttonColors[0]);
                buttonPanel.add(resultButton);
            }

            inPanel.add(buttonPanel, BorderLayout.SOUTH);

            JPopupMenu contextMenu = new JPopupMenu();
            JPopupMenu outMenu = new JPopupMenu();

            JMenuItem validateOutJsonMenu = new JMenuItem("JSON Validate");
            validateOutJsonMenu.addActionListener(e -> Addons.validateJson(outArea));
            outMenu.add(validateOutJsonMenu);

            JMenuItem importMenu = new JMenuItem("Import");
            importMenu.addActionListener(e -> Addons.importJson(frame, inArea));
            contextMenu.add(importMenu);

            JMenuItem exportMenu = new JMenuItem("Export");
            exportMenu.addActionListener(e -> Addons.exportJson(frame, inArea));
            contextMenu.add(exportMenu);

            JMenuItem processJsonMenu = new JMenuItem("JSON Beautiful");
            processJsonMenu.addActionListener(e -> Addons.processJson(inArea));
            contextMenu.add(processJsonMenu);

            JMenuItem validateJsonMenu = new JMenuItem("JSON Validate");
            validateJsonMenu.addActionListener(e -> Addons.validateJson(inArea));
            contextMenu.add(validateJsonMenu);

            JMenuItem searchMenu = new JMenuItem("Search");
            searchMenu.addActionListener(e -> Addons.searchJson(frame, inArea));
            contextMenu.add(searchMenu);

            JMenuItem replaceMenu = new JMenuItem("Replace");
            replaceMenu.addActionListener(e -> Addons.replaceJson(frame, inArea));
            contextMenu.add(replaceMenu);

            inArea.setComponentPopupMenu(contextMenu);
            outArea.setComponentPopupMenu(outMenu);
            UndoManager undoManager = new UndoManager();
            inArea.getDocument().addUndoableEditListener(e -> undoManager.addEdit(e.getEdit()));
            KeyStroke undoKeyStroke;
            KeyStroke redoKeyStroke;

            switch (Init.CURRENTOS) {
                case MAC:
                    undoKeyStroke = KeyStroke.getKeyStroke("meta Z");
                    redoKeyStroke = KeyStroke.getKeyStroke("meta Y");
                    break;
                default:
                    undoKeyStroke = KeyStroke.getKeyStroke("control Z");
                    redoKeyStroke = KeyStroke.getKeyStroke("control Y");
                    break;
            }

            inArea.getInputMap().put(undoKeyStroke, "Undo");
            inArea.getActionMap().put("Undo", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    if (undoManager.canUndo()) {
                        undoManager.undo();
                    }
                }
            });

            inArea.getInputMap().put(redoKeyStroke, "Redo");
            inArea.getActionMap().put("Redo", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    if (undoManager.canRedo()) {
                        undoManager.redo();
                    }
                }
            });

            tabbedPanel.addTab("in", inPanel);
            tabbedPanel.addTab("out", outPanel);
            tabbedPanel.addTab("notes", notesPanel);
            frame.getContentPane().add(tabbedPanel);
            g2dLayer.add(frame, JLayeredPane.DEFAULT_LAYER);
            Linker.addConnection(fromFrame, frame);
            Linker.catcherListener(frame, inArea, outArea, defenderArea, actualStateManager);
            actualStateManager.updateStates();
        }

        public void SenderTask(String name, int x, int y, JInternalFrame previousFrame) {
            JInternalFrame frame = SwingUtils.suiteFrame(name, x, y, (int) (WIDTH * SCALE), (int) (HEIGHT * SCALE));
            JTabbedPane tabbedPanel = new JTabbedPane();

            JPanel mainPanel = new JPanel(new BorderLayout());
            JPanel lastPanel = new JPanel(new BorderLayout());

            JPanel settingsPanel = new JPanel();
            GroupLayout layout = new GroupLayout(settingsPanel);
            settingsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            JTextArea responseArea = new JTextArea();
            responseArea.setLineWrap(true);
            responseArea.setWrapStyleWord(true);

            JScrollPane lastScrollPane = new JScrollPane(responseArea);
            lastScrollPane.setBorder(null);

            mainPanel.add(settingsPanel, BorderLayout.CENTER);

            lastPanel.add(lastScrollPane, BorderLayout.CENTER);
            tabbedPanel.addTab("request", mainPanel);
            tabbedPanel.addTab("last result", lastPanel);

            JLabel methodLabel = new JLabel("Method:");
            String[] methods = { "GET", "POST", "PUT", "DELETE" };
            JComboBox<String> methodComboBox = new JComboBox<>(methods);

            JLabel urlLabel = new JLabel("URL:");
            JTextField urlField = new JTextField();

            JLabel headersLabel = new JLabel("Headers:");
            JTextArea headersArea = new JTextArea();
            headersArea.setLineWrap(true);
            headersArea.setWrapStyleWord(true);
            JScrollPane headersScrollPane = new JScrollPane(headersArea);

            JLabel bodyLabel = new JLabel("Body:");
            JTextArea bodyArea = new JTextArea();
            bodyArea.setLineWrap(true);
            bodyArea.setWrapStyleWord(true);
            JScrollPane bodyScrollPane = new JScrollPane(bodyArea);

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addComponent(methodLabel)
                                    .addComponent(urlLabel)
                                    .addComponent(headersLabel)
                                    .addComponent(bodyLabel))
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addComponent(methodComboBox)
                                    .addComponent(urlField)
                                    .addComponent(headersScrollPane)
                                    .addComponent(bodyScrollPane)));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(methodLabel)
                                    .addComponent(methodComboBox))
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(urlLabel)
                                    .addComponent(urlField))
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addComponent(headersLabel)
                                    .addComponent(headersScrollPane))
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addComponent(bodyLabel)
                                    .addComponent(bodyScrollPane)));

            JPopupMenu popupMenu = new JPopupMenu();
            JMenuItem sendRequestMenuItem = new JMenuItem("Test Request");
            popupMenu.add(sendRequestMenuItem);
            mainPanel.setComponentPopupMenu(popupMenu);
            sendRequestMenuItem.addActionListener(e -> {
                responseArea.setText("");
                String method = (String) methodComboBox.getSelectedItem();
                String url = urlField.getText();
                String headers = headersArea.getText();
                String body = bodyArea.getText();

                try {
                    URI uri = new URI(url);
                    String host = uri.getHost();
                    int port = uri.getPort() != -1 ? uri.getPort() : (uri.getScheme().equals("https") ? 443 : 80);

                    StringBuilder requestBuilder = new StringBuilder();
                    requestBuilder.append(method).append(" ").append(uri.getPath()).append(" HTTP/1.1\n");
                    requestBuilder.append("Host: ").append(host).append(":").append(port).append("\n");
                    if (!headers.isEmpty()) {
                        requestBuilder.append(headers).append("\n");
                    }
                    requestBuilder.append("Content-Length: ").append(body.length()).append("\n");
                    requestBuilder.append("\n");
                    if (!body.isEmpty()) {
                        requestBuilder.append(body);
                    }

                    String requestText = requestBuilder.toString();
                    Init.api.logging().logToOutput(Init.PREF + Init.DSB + "Request Text: " + requestText);

                    new SwingWorker<HttpRequestResponse, Void>() {
                        @Override
                        protected HttpRequestResponse doInBackground() throws Exception {
                            boolean isSecure = uri.getScheme().equals("https");
                            HttpService httpService = HttpService.httpService(host, port, isSecure);
                            HttpRequest httpRequest = HttpRequest.httpRequest(httpService, requestText);
                            return Init.api.http().sendRequest(httpRequest);
                        }

                        @Override
                        protected void done() {
                            try {
                                HttpRequestResponse httpResponse = get();
                                StringBuilder responseDetails = new StringBuilder();
                                responseDetails.append("Response Body: ")
                                        .append(httpResponse.response().body().toString()).append("\n");

                                SwingUtilities.invokeLater(() -> {
                                    responseArea.setText(responseDetails.toString());
                                });
                            } catch (Exception ex) {
                                throw new RuntimeException("Error processing HTTP response", ex);
                            }
                        }
                    }.execute();
                } catch (Exception ex) {
                    Init.api.logging().logToOutput(Init.PREF + Init.DSB + "Exception: " + ex.getMessage());
                }
            });

            frame.getContentPane().add(tabbedPanel);
            g2dLayer.add(frame, JLayeredPane.DEFAULT_LAYER);
            Linker.addConnection(previousFrame, frame);
        }

        public void SolverTask(String name, int x, int y, JInternalFrame previousFrame) {
            JInternalFrame frame = SwingUtils.suiteFrame(name, x, y, (int) (WIDTH * SCALE), (int) (HEIGHT * SCALE));
            frame.setMaximizable(false);
            Linker.СhainTaskList.add(frame);
            JTabbedPane tabbedPanel = new JTabbedPane();

            JPanel issuePanel = new JPanel(new GridBagLayout());
            JPanel jsonPanel = new JPanel(new BorderLayout());
            GridBagConstraints gbc = new GridBagConstraints();

            JTextArea issueArea = new JTextArea(5, 10);
            issueArea.setLineWrap(true);
            issueArea.setWrapStyleWord(true);

            JTextArea jsonArea = new JTextArea();
            jsonArea.setEditable(false);
            jsonArea.setLineWrap(true);
            jsonArea.setWrapStyleWord(true);
            jsonArea.setCaretPosition(0);
            jsonArea.setText("{\n" + //
                    "  \"title\":\"\",\n" + //
                    "  \"detail\":\"🟩\",\n" + //
                    "  \"remediation\":\"\",\n" + //
                    "  \"background\":\"\",\n" + //
                    "  \"remediationBackground\":\"\",\n" + //
                    "  \"severity\":\"\",\n" + //
                    "  \"confidence\":\"\",\n" + //
                    "  \"typicalSeverity\":\"\"\n" + //
                    "}");
            JScrollPane jsonScrollPane = new JScrollPane(jsonArea);
            jsonScrollPane.setBorder(null);
            jsonPanel.add(jsonScrollPane, BorderLayout.CENTER);

            JLabel severityLabel = new JLabel("Severity:");
            JLabel typicalSeverityLabel = new JLabel("Typical Severity:");
            JLabel confidenceLabel = new JLabel("Confidence:");

            JComboBox<AuditIssueSeverity> severityComboBox = new JComboBox<>(AuditIssueSeverity.values());
            JComboBox<AuditIssueSeverity> typicalSeverityComboBox = new JComboBox<>(AuditIssueSeverity.values());
            JComboBox<AuditIssueConfidence> confidenceComboBox = new JComboBox<>(AuditIssueConfidence.values());

            severityComboBox.setSelectedItem(Issue.DEFAULT_SEVERITY);
            severityComboBox.addActionListener(e -> {
                AuditIssueSeverity selectedSeverity = (AuditIssueSeverity) severityComboBox.getSelectedItem();
                if (selectedSeverity != null) {
                    Issue.DEFAULT_SEVERITY = selectedSeverity;
                }
            });

            typicalSeverityComboBox.setSelectedItem(Issue.DEFAULT_TYPICAL_SEVERITY);
            typicalSeverityComboBox.addActionListener(e -> {
                AuditIssueSeverity selectedtypicalSeverity = (AuditIssueSeverity) typicalSeverityComboBox
                        .getSelectedItem();
                if (selectedtypicalSeverity != null) {
                    Issue.DEFAULT_TYPICAL_SEVERITY = selectedtypicalSeverity;
                }
            });

            confidenceComboBox.setSelectedItem(Issue.DEFAULT_CONFIDENCE);
            confidenceComboBox.addActionListener(e -> {
                AuditIssueConfidence setConfidence = (AuditIssueConfidence) confidenceComboBox.getSelectedItem();
                if (setConfidence != null) {
                    Issue.DEFAULT_CONFIDENCE = setConfidence;
                }
            });

            gbc.insets = new Insets(5, 5, 5, 5);
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.weightx = 0.5;

            addComponentToPanel(issuePanel, gbc, severityLabel, 0, 5, 1);
            addComponentToPanel(issuePanel, gbc, severityComboBox, 1, 5, 1);
            addComponentToPanel(issuePanel, gbc, typicalSeverityLabel, 0, 6, 1);
            addComponentToPanel(issuePanel, gbc, typicalSeverityComboBox, 1, 6, 1);
            addComponentToPanel(issuePanel, gbc, confidenceLabel, 0, 7, 1);
            addComponentToPanel(issuePanel, gbc, confidenceComboBox, 1, 7, 1);

            tabbedPanel.addTab("issue", issuePanel);
            tabbedPanel.addTab("example", jsonPanel);

            frame.getContentPane().add(tabbedPanel);
            g2dLayer.add(frame, JLayeredPane.DEFAULT_LAYER);
            Linker.addConnection(previousFrame, frame);
            Issue.Audit.jsonListener(frame);
            revalidate();
            repaint();
        }

        private void addComponentToPanel(JPanel panel, GridBagConstraints gbc, Component component, int gridx,
                int gridy, int gridwidth) {
            gbc.gridx = gridx;
            gbc.gridy = gridy;
            gbc.gridwidth = gridwidth;
            panel.add(component, gbc);
        }

        public void SpooferTask(String name, int x, int y) {
            if (!Linker.IsolatedTaskList.isEmpty()) {
                return;
            }
            JInternalFrame frame = SwingUtils.suiteFrame(name, x, y, (int) (WIDTH * SCALE), (int) (HEIGHT * SCALE));
            Linker.IsolatedTaskList.add(frame);
            JTabbedPane tabbedPanel = new JTabbedPane();

            JPanel notesPanel = new JPanel(new BorderLayout());
            JTextArea notesArea = new JTextArea();
            notesArea.setLineWrap(true);
            notesArea.setWrapStyleWord(true);
            JScrollPane notesScrollPane = new JScrollPane(notesArea);
            notesScrollPane.setBorder(null);
            notesPanel.add(notesScrollPane, BorderLayout.CENTER);

            String[] columnNames = { "original", "spoofed" };
            DefaultTableModel tableModel = new DefaultTableModel(columnNames, 0);
            JTable table = new JTable(tableModel);
            table.setFillsViewportHeight(true);

            for (Map.Entry<String, String> entry : Linker.spoofMap.entrySet()) {
                tableModel.addRow(new Object[] { entry.getKey(), entry.getValue() });
            }

            JScrollPane tableScrollPane = new JScrollPane(table);

            JPopupMenu contextMenu = new JPopupMenu();

            JMenuItem addItem = new JMenuItem("Add Replacement");
            addItem.addActionListener(e -> {
                JPanel panel = new JPanel(new GridLayout(2, 2));
                JTextField findField = new JTextField();
                JTextField replaceField = new JTextField();
                panel.add(new JLabel("origin:"));
                panel.add(findField);
                panel.add(new JLabel("spoof:"));
                panel.add(replaceField);

                int result = JOptionPane.showConfirmDialog(frame, panel, addItem.getActionCommand(),
                        JOptionPane.OK_CANCEL_OPTION);
                if (result == JOptionPane.OK_OPTION) {
                    String findText = findField.getText();
                    String replaceText = replaceField.getText();
                    if (!findText.isEmpty() && !replaceText.isEmpty()) {
                        Linker.spoofMap.put(findText, replaceText);
                        tableModel.addRow(new Object[] { findText, replaceText });
                    }
                }
            });
            contextMenu.add(addItem);

            JMenuItem removeItem = new JMenuItem("Remove Replacement");
            removeItem.addActionListener(e -> {
                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) {
                    String findText = (String) tableModel.getValueAt(selectedRow, 0);
                    Linker.spoofMap.remove(findText);
                    tableModel.removeRow(selectedRow);
                }
            });
            contextMenu.add(removeItem);

            table.setComponentPopupMenu(contextMenu);
            table.getDefaultEditor(String.class).addCellEditorListener(new CellEditorListener() {
                @Override
                public void editingStopped(ChangeEvent e) {
                    int row = table.getSelectedRow();
                    if (row != -1) {
                        String findText = (String) tableModel.getValueAt(row, 0);
                        String replaceText = (String) tableModel.getValueAt(row, 1);
                        Linker.spoofMap.put(findText, replaceText);
                    }
                }

                @Override
                public void editingCanceled(ChangeEvent e) {
                }
            });

            JPanel tablePanel = new JPanel(new BorderLayout());
            tablePanel.add(tableScrollPane, BorderLayout.CENTER);

            tabbedPanel.addTab("response Body", tablePanel);
            tabbedPanel.addTab("notes", notesPanel);

            frame.getContentPane().add(tabbedPanel);
            g2dLayer.add(frame, JLayeredPane.DEFAULT_LAYER);
            Linker.addConnection(Linker.СhainTaskList.get(0), frame);
            frame.addInternalFrameListener(new InternalFrameAdapter() {
                @Override
                public void internalFrameClosing(InternalFrameEvent e) {
                    Linker.spoofMap.clear();
                    Linker.IsolatedTaskList.clear();
                }
            });
        }

        // frames and menu actions
        private void frameAction(JInternalFrame frame) {
            frame.addInternalFrameListener(new InternalFrameAdapter() {
                @Override
                public void internalFrameClosing(InternalFrameEvent e) {
                    if (!editMode) {
                        int result = JOptionPane.showConfirmDialog(
                                frame,
                                "Deleting it will also remove all its connections.",
                                "Confirm workflow deletion",
                                JOptionPane.YES_NO_OPTION,
                                JOptionPane.WARNING_MESSAGE);
                        if (result == JOptionPane.YES_OPTION) {
                            for (MouseListener listener : frame.getMouseListeners()) {
                                frame.removeMouseListener(listener);
                            }
                            for (MouseMotionListener listener : frame.getMouseMotionListeners()) {
                                frame.removeMouseMotionListener(listener);
                            }
                            for (ComponentListener listener : frame.getComponentListeners()) {
                                frame.removeComponentListener(listener);
                            }
                            for (InternalFrameListener listener : frame.getInternalFrameListeners()) {
                                frame.removeInternalFrameListener(listener);
                            }
                            if (Linker.issenderTask(frame)) {
                                Linker.removeConnections(frame);
                            }
                            if (Linker.isSpooferTask(frame)) {
                                Linker.removeConnections(frame);
                                Linker.spoofMap.clear();
                            } else {

                                int index = Linker.СhainTaskList.indexOf(frame);
                                List<JInternalFrame> framesToRemove = new ArrayList<>(
                                        Linker.СhainTaskList.subList(index,
                                                Linker.СhainTaskList.size()));
                                for (JInternalFrame component : framesToRemove) {
                                    Linker.removeConnections(component);

                                }
                            }
                        }
                    }
                }
            });
            frame.addComponentListener(new ComponentAdapter() {
                @Override
                public void componentResized(java.awt.event.ComponentEvent e) {
                    Rectangle visibleRect = g2dLayer.getVisibleRect();
                    editMode = frame.getBounds().equals(visibleRect);
                    zoomIn.setVisible(!editMode);
                    zoomOut.setVisible(!editMode);
                    liveSwitch.setVisible(!editMode);
                    List<JInternalFrame> combinedTaskList = new ArrayList<>();
                    combinedTaskList.addAll(Linker.СhainTaskList);
                    combinedTaskList.addAll(Linker.IsolatedTaskList);
                    if (editMode) {
                        for (JInternalFrame component : combinedTaskList) {
                            component.setVisible(component.equals(frame));
                        }
                        zoomIn.setVisible(false);
                        zoomOut.setVisible(false);
                        liveSwitch.setVisible(false);
                        frame.setBorder(BorderFactory.createEmptyBorder());
                        frame.setClosable(false);
                    } else {
                        for (JInternalFrame component : combinedTaskList) {
                            component.setVisible(true);
                        }
                        zoomIn.setVisible(true);
                        zoomOut.setVisible(true);
                        liveSwitch.setVisible(true);
                        frame.setClosable(true);
                        frame.setBorder(BorderFactory.createLineBorder(Color.GRAY));
                        g2dLayer.revalidate();
                        g2dLayer.repaint();
                    }
                }
            });
        }

        private void showContextMenu(MouseEvent e) {
            JPopupMenu popupMenu = new JPopupMenu();

            if (!Linker.СhainTaskList.isEmpty() && Linker.СhainTaskList.get(0) != null) {
                JMenuItem catcherMenu = new JMenuItem(Linker.TITLEcatcher);
                catcherMenu.addActionListener(actionEvent -> {
                    catcherTask(catcherMenu.getActionCommand(), e.getX(), e.getY(),
                            Linker.СhainTaskList.get(Linker.СhainTaskList.size() - 1));
                });

                JMenuItem SpooferMenu = new JMenuItem(Linker.TITLEspoofer);
                SpooferMenu.addActionListener(actionEvent -> {
                    SpooferTask(SpooferMenu.getActionCommand(), e.getX(), e.getY());
                });

                JMenuItem SolverMenu = new JMenuItem(Linker.TITLEsolver);
                SolverMenu.addActionListener(actionEvent -> {
                    SolverTask(SolverMenu.getActionCommand(), e.getX(), e.getY(),
                            Linker.СhainTaskList.get(Linker.СhainTaskList.size() - 1));
                });

                JMenuItem SenderMenu = new JMenuItem(Linker.TITLEsender);
                SenderMenu.addActionListener(actionEvent -> {
                    SenderTask(SenderMenu.getActionCommand(), e.getX(), e.getY(),
                            Linker.СhainTaskList.get(Linker.СhainTaskList.size() - 1));
                });
                popupMenu.add(catcherMenu);
                popupMenu.add(SpooferMenu);
                popupMenu.add(SenderMenu);
                if (WorkflowPanel.liveSwitch.isSelected()) {
                    popupMenu.add(SolverMenu);
                }
                if (Issue.liveIssue) {
                    popupMenu.remove(SolverMenu);
                    popupMenu.remove(SpooferMenu);

                }
                if (!Linker.IsolatedTaskList.isEmpty()) {
                    popupMenu.remove(SpooferMenu);
                    popupMenu.remove(SolverMenu);
                }
                popupMenu.addSeparator();
            }

            if (!Linker.connections.isEmpty()) {
                JMenuItem mockRun = new JMenuItem("Mock test-run");
                mockRun.addActionListener(actionEvent -> {
                    List<Object[]> requestData = new ArrayList<>();
                    requestData.add(new Object[] { "www.dev-sec-box.local", "GET",
                            "/path/DevSecBox.html",
                            "req_header: req_header_value_1_line", "req_body:req_body_value_1_line",
                            "resp_header: resp_header_value_1_line",
                            "resp_body_value_line_1_of_2\nresp_body_value_line_2_of_2" });
                    Linker.Pipe(requestData);
                });

                popupMenu.add(mockRun);
                popupMenu.addSeparator();
            }
            JMenuItem AboutMenu = new JMenuItem("About");

            AboutMenu.addActionListener(actionEvent -> {
                try {
                    if (Desktop.isDesktopSupported()) {
                        Desktop desktop = Desktop.getDesktop();
                        if (desktop.isSupported(Desktop.Action.BROWSE)) {
                            URI uri = new URI("https://github.com/taradaidv/dev-sec-box");
                            desktop.browse(uri);
                        }
                    }
                } catch (Exception err) {
                    err.printStackTrace();
                    JOptionPane.showMessageDialog(null, "Failed to open URL: " + err.getMessage(),
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            });

            JMenuItem triggerMenu = new JMenuItem(Linker.TITLEtrigger);
            triggerMenu.addActionListener(actionEvent -> {
                triggerTask(e.getX(), e.getY());
            });

            if (Linker.СhainTaskList.isEmpty()) {
                popupMenu.add(triggerMenu);
                popupMenu.addSeparator();
            }

            popupMenu.add(AboutMenu);

            popupMenu.show(g2dLayer, e.getX(), e.getY());
        }
    }

}