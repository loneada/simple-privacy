package com.benjamin.simpleprivacy;

import java.io.File;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.nio.channels.ClosedByInterruptException;
import java.awt.Font;
import java.awt.Cursor;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.Dimension;
import java.awt.Component;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentAdapter;
import javax.swing.JFrame;
import javax.swing.JMenuBar;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.ButtonGroup;
import javax.swing.JTextField;
import javax.swing.JPasswordField;
import javax.swing.JTextArea;
import javax.swing.JProgressBar;
import javax.swing.JTabbedPane;
import javax.swing.JList;
import javax.swing.JScrollPane;
import javax.swing.JOptionPane;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileSystemView;
import javax.swing.JComponent;
import javax.swing.BorderFactory;
import javax.swing.SwingUtilities;
import javax.swing.plaf.metal.MetalIconFactory;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import static com.benjamin.simpleprivacy.PrivacyUtil.*;

enum CipherOperation {ENCRYPT, DECRYPT}
enum DigestOperation {GENERATE, VERIFY}

public class PrivacyFrame extends JFrame {
    private CipherOperation cipherOp = CipherOperation.ENCRYPT;
    private DigestOperation digestOp = DigestOperation.GENERATE;
    private CryptMode cipherAlgo = CryptMode.AES128_CBC;
    private DigestMode digestAlgo = DigestMode.SHA1;
    private JProgressBar cipherProgress;
    private JProgressBar digestProgress;
    private Path cipherInput = null;
    private Path cipherOutput = null;
    private File[] digestInputFiles = null;
    private Thread cipherWorker = null;
    private Thread digestWorker = null;
    private volatile boolean isSucceeded = false;

    public PrivacyFrame() {
        super("SimplePrivacy");
        setJMenuBar(createMenuBar());
        add(createTabbedPane());
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        pack();
        setResizable(false);
        setVisible(true);
    }

    private JMenuBar createMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        JMenu fileMenu = new JMenu("File");
        fileMenu.setMnemonic('F');
        JMenuItem exitItem = new JMenuItem("Exit");
        exitItem.setMnemonic('x');
        exitItem.addActionListener(ae -> System.exit(0));
        fileMenu.add(exitItem);
        JMenu helpMenu = new JMenu("Help");
        helpMenu.setMnemonic('H');
        JMenuItem aboutItem = new JMenuItem("About...");
        StringBuilder builder = new StringBuilder();
        builder.append("SimplePrivacy is a simple software provides basic encryption/decryption\n");
        builder.append("and message digests functionality with common algorithms.\n\n");
        builder.append("License: GPLv3 <http://www.gnu.org/licenses/gpl-3.0.html>\n");
        builder.append("Author: Benjamin Zhang <loneada@sina.com>\n");
        builder.append("Version: 0.5.0");
        aboutItem.addActionListener(ae -> JOptionPane.showMessageDialog(this, builder.toString(), "Info", JOptionPane.INFORMATION_MESSAGE));
        aboutItem.setMnemonic('A');
        helpMenu.add(aboutItem);
        menuBar.add(fileMenu);
        menuBar.add(helpMenu);
        return menuBar;
    }

    private JTabbedPane createTabbedPane() {
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Cipher", createCipherPanel());
        tabbedPane.addTab("Digest", createDigestPanel());
        return tabbedPane;
    }

    private JPanel createCipherPanel() {
        JPanel operationPanel = new JPanel();
        JRadioButton encryptRadioButton = new JRadioButton("Encrypt", true);
        encryptRadioButton.addActionListener(ae -> cipherOp = CipherOperation.ENCRYPT);
        JRadioButton decryptRadionButton = new JRadioButton("Decrypt");
        decryptRadionButton.addActionListener(ae -> cipherOp = CipherOperation.DECRYPT);
        ButtonGroup operationGroup = new ButtonGroup();
        operationGroup.add(encryptRadioButton);
        operationGroup.add(decryptRadionButton);
        operationPanel.add(encryptRadioButton);
        operationPanel.add(decryptRadionButton);
        operationPanel.setBorder(BorderFactory.createTitledBorder("Operation"));

        JPanel algorithmPanel = new JPanel();
        JRadioButton ecbRadioButton = new JRadioButton("AES128/ECB");
        ecbRadioButton.addActionListener(ae -> cipherAlgo = CryptMode.AES128_ECB);
        JRadioButton cbcRadioButton = new JRadioButton("AES128/CBC", true);
        cbcRadioButton.addActionListener(ae -> cipherAlgo = CryptMode.AES128_CBC);
        ButtonGroup algorithmGroup = new ButtonGroup();
        algorithmGroup.add(ecbRadioButton);
        algorithmGroup.add(cbcRadioButton);
        algorithmPanel.add(cbcRadioButton);
        algorithmPanel.add(ecbRadioButton);
        algorithmPanel.setBorder(BorderFactory.createTitledBorder("Algorithm"));

        JPanel optionPanel = new JPanel();
        optionPanel.add(operationPanel);
        optionPanel.add(algorithmPanel);

        JPanel pathPanel = new JPanel(new GridLayout(2, 1));
        JPanel inputPanel = new JPanel();
        JLabel inputLabel = new JLabel("Input:");
        JTextField inputTextField = new JTextField(24);
        JButton inputButton = new JButton(new MetalIconFactory.FolderIcon16());
        inputButton.setToolTipText("Choose input file path.");
        inputPanel.add(inputLabel);
        inputPanel.add(inputTextField);
        inputPanel.add(inputButton);
        JPanel outputPanel = new JPanel();
        JLabel outputLabel = new JLabel("Output:");
        JTextField outputTextField = new JTextField(24);
        JButton outputButton = new JButton(new MetalIconFactory.FolderIcon16());
        outputButton.setToolTipText("Choose output file path.");
        outputPanel.add(outputLabel);
        outputPanel.add(outputTextField);
        outputPanel.add(outputButton);
        inputLabel.setPreferredSize(outputLabel.getPreferredSize());
        inputButton.addActionListener(ae -> {
            File file = chooseFile(JFileChooser.OPEN_DIALOG);
            if (file != null) {
                inputTextField.setText(file.getAbsolutePath());
                String filename = file.getName();
                int idx = filename.lastIndexOf('.');
                String outname = "";
                String ext = cipherOp == CipherOperation.ENCRYPT ? ".enc" : ".dec";
                if (idx == -1) {outname = filename + ext;}
                else {outname = filename.substring(0, idx) + ext;}
                outputTextField.setText(new File(file.getParentFile(), outname).getAbsolutePath());
                outputTextField.requestFocus();
                outputTextField.selectAll();
            }
        });
        outputButton.addActionListener(ae -> {
            File file = chooseFile(JFileChooser.SAVE_DIALOG);
            if (file != null) {outputTextField.setText(file.getAbsolutePath());}
        });
        pathPanel.add(inputPanel);
        pathPanel.add(outputPanel);
        pathPanel.setBorder(BorderFactory.createTitledBorder("File path"));

        JPanel passwordPanel = new JPanel(new GridLayout(2, 1));
        JPanel entryPanel = new JPanel();
        JLabel entryLabel = new JLabel("Password:");
        JPasswordField passwordField = new JPasswordField(23);
        entryPanel.add(entryLabel);
        entryPanel.add(passwordField);
        JPanel confirmPanel = new JPanel();
        JLabel confirmLabel = new JLabel("Confirm password:");
        JPasswordField confirmPasswordField = new JPasswordField(23);
        confirmPanel.add(confirmLabel);
        confirmPanel.add(confirmPasswordField);
        entryLabel.setPreferredSize(confirmLabel.getPreferredSize());
        passwordPanel.add(entryPanel);
        passwordPanel.add(confirmPanel);
        passwordPanel.setBorder(BorderFactory.createTitledBorder("Password (at least 6 characters)"));

        JPanel progressPanel = new JPanel();
        cipherProgress = new JProgressBar();
        progressPanel.add(cipherProgress);
        progressPanel.setBorder(BorderFactory.createTitledBorder("Progress"));
        progressPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent ce) {
                Component panel = ce.getComponent();
                Dimension panelDimension = panel.getSize();
                Dimension progressDimension = cipherProgress.getPreferredSize();
                progressDimension.width = panelDimension.width - 20;
                cipherProgress.setPreferredSize(progressDimension);
                panel.doLayout();
            }
        });

        JPanel buttonPanel = new JPanel();
        FlowLayout layout = (FlowLayout) buttonPanel.getLayout();
        layout.setHgap(10);
        JButton commitButton = new JButton("Commit");
        commitButton.setMnemonic('C');
        JButton resetButton = new JButton("Reset");
        resetButton.setMnemonic('R');
        JButton cancelButton = new JButton("Cancel");
        cancelButton.setMnemonic('n');
        cancelButton.setEnabled(false);
        Dimension dimension = commitButton.getPreferredSize();
        resetButton.setPreferredSize(dimension);
        cancelButton.setPreferredSize(dimension);
        buttonPanel.add(commitButton);
        buttonPanel.add(resetButton);
        buttonPanel.add(cancelButton);
        JComponent[] cipherComponents = {encryptRadioButton, decryptRadionButton, ecbRadioButton, cbcRadioButton,
                                         inputTextField, inputButton, outputTextField, outputButton,
                                         passwordField, confirmPasswordField, commitButton, resetButton};
        commitButton.addActionListener(ae -> {
            try {
                String path = inputTextField.getText().trim();
                if (path.length() == 0) {throw new RuntimeException("Empty path!");}
                cipherInput = Paths.get(path);
                if (!Files.isRegularFile(cipherInput)) {throw new RuntimeException("File does not exist!");}
            }
            catch(RuntimeException ex) {
                JOptionPane.showMessageDialog(this, "Invalid input file!", "Error", JOptionPane.ERROR_MESSAGE);
                inputTextField.requestFocus();
                inputTextField.selectAll();
                return;
            }
            try {
                String path = outputTextField.getText().trim();
                if (path.length() == 0) {throw new RuntimeException("Empty path!");}
                cipherOutput = Paths.get(path);
                if (Files.isRegularFile(cipherOutput)) {
                    String msg = path + " already exists!\nDo you want to overwrite it?";
                    if (JOptionPane.NO_OPTION == JOptionPane.showConfirmDialog(this, msg, "Confirmation", JOptionPane.YES_NO_OPTION)) {
                        outputTextField.requestFocus();
                        outputTextField.selectAll();
                        return;
                    }
                }
            }
            catch(RuntimeException ex) {
                JOptionPane.showMessageDialog(this, "Invalid output file!", "Error", JOptionPane.ERROR_MESSAGE);
                outputTextField.requestFocus();
                outputTextField.selectAll();
                return;
            }
            if (passwordField.getText().length() < 6) {
                JOptionPane.showMessageDialog(this, "Password must not be less than 6 characters!", "Error", JOptionPane.ERROR_MESSAGE);
                passwordField.requestFocus();
                passwordField.selectAll();
                return;
            }
            if (!passwordField.getText().equals(confirmPasswordField.getText())) {
                JOptionPane.showMessageDialog(this, "Passwords mismatch!", "Error", JOptionPane.ERROR_MESSAGE);
                confirmPasswordField.requestFocus();
                confirmPasswordField.selectAll();
                return;
            }
            char[] password = passwordField.getPassword();
            disableComponents(cipherComponents);
            cipherWorker = new Thread(() -> {
                switch(cipherOp) {
                case ENCRYPT:
                    try {
                        encrypt(cipherAlgo, password, cipherInput, cipherOutput);
                        isSucceeded = true;
                    }
                    catch(GeneralSecurityException ex) {
                        ex.printStackTrace();
                        SwingUtilities.invokeLater(() -> {
                            String msg = "Operation failed!\nCurrent platform does not support the specific cipher algorithm.\n";
                            msg += ex.getMessage();
                            JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
                        });
                    }
                    catch(IOException ex) {
                        ex.printStackTrace();
                        SwingUtilities.invokeLater(() -> {
                            String msg = "Operation failed!\n" + ex.getMessage();
                            JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
                        });
                    }
                    catch(InterruptedException ex) {
                        return;
                    }
                    break;
                case DECRYPT:
                    try {
                        decrypt(cipherAlgo, password, cipherInput, cipherOutput);
                        isSucceeded = true;
                    }
                    catch(GeneralSecurityException ex) {
                        ex.printStackTrace();
                        SwingUtilities.invokeLater(() -> {
                            String msg = "Operation failed!\nCurrent platform does not support the specific cipher algorithm.\nOr the input file has been corrupted.\n";
                            msg += ex.getMessage();
                            JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
                        });
                    }
                    catch(IOException ex) {
                        ex.printStackTrace();
                        SwingUtilities.invokeLater(() -> {
                            String msg = "Operation failed!\nMaybe the input file was not encrypted by this software or had been corrupted.\n";
                            msg += ex.getMessage();
                            JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
                        });
                    }
                    catch(InterruptedException ex) {
                        return;
                    }
                    break;
                default:
                    break;
                }
                SwingUtilities.invokeLater(() -> {
                    cipherProgress.setIndeterminate(false);
                    setCursor(Cursor.getDefaultCursor());
                    if (isSucceeded) {
                        JOptionPane.showMessageDialog(this, "Operation completed successfully.", "Info", JOptionPane.INFORMATION_MESSAGE);
                        isSucceeded = false;
                    }
                    cancelButton.setEnabled(false);
                    enableComponents(cipherComponents);
                    cipherWorker = null;
                });
            });
            cipherWorker.start();
            cipherProgress.setIndeterminate(true);
            setCursor(Cursor.getPredefinedCursor(WAIT_CURSOR));
            cancelButton.setEnabled(true);
        });
        resetButton.addActionListener(ae -> {
            encryptRadioButton.doClick();
            cbcRadioButton.doClick();
            inputTextField.setText("");
            outputTextField.setText("");
            passwordField.setText("");
            confirmPasswordField.setText("");
        });
        cancelButton.addActionListener(ae -> {
            if (cipherWorker != null) {
                cipherWorker.interrupt();
                cipherWorker = null;
            }
            cipherProgress.setIndeterminate(false);
            setCursor(Cursor.getDefaultCursor());
            isSucceeded = false;
            cancelButton.setEnabled(false);
            enableComponents(cipherComponents);
        });

        Box cipherBox = Box.createVerticalBox();
        cipherBox.add(optionPanel);
        cipherBox.add(Box.createVerticalStrut(10));
        cipherBox.add(pathPanel);
        cipherBox.add(Box.createVerticalStrut(10));
        cipherBox.add(passwordPanel);
        cipherBox.add(Box.createVerticalStrut(10));
        cipherBox.add(progressPanel);
        cipherBox.add(Box.createVerticalStrut(10));
        cipherBox.add(buttonPanel);

        JPanel cipherPanel = new JPanel();
        cipherPanel.add(cipherBox);
        return cipherPanel;
    }

    private JPanel createDigestPanel() {
        JPanel operationPanel = new JPanel();
        JRadioButton generateRadioButton = new JRadioButton("Generate", true);
        generateRadioButton.addActionListener(ae -> digestOp = DigestOperation.GENERATE);
        JRadioButton verifyRadioButton = new JRadioButton("Verify");
        ButtonGroup operationGroup = new ButtonGroup();
        operationGroup.add(generateRadioButton);
        operationGroup.add(verifyRadioButton);
        operationPanel.add(generateRadioButton);
        operationPanel.add(verifyRadioButton);
        operationPanel.setBorder(BorderFactory.createTitledBorder("Operation"));

        JPanel algorithmPanel = new JPanel();
        JRadioButton md5RadioButton = new JRadioButton("MD5");
        md5RadioButton.addActionListener(ae -> digestAlgo = DigestMode.MD5);
        JRadioButton sha1RadioButton = new JRadioButton("SHA-1", true);
        sha1RadioButton.addActionListener(ae -> digestAlgo = DigestMode.SHA1);
        JRadioButton sha256RadioButton = new JRadioButton("SHA-256");
        sha256RadioButton.addActionListener(ae -> digestAlgo = DigestMode.SHA256);
        ButtonGroup algorithmGroup = new ButtonGroup();
        algorithmGroup.add(md5RadioButton);
        algorithmGroup.add(sha1RadioButton);
        algorithmGroup.add(sha256RadioButton);
        algorithmPanel.add(md5RadioButton);
        algorithmPanel.add(sha1RadioButton);
        algorithmPanel.add(sha256RadioButton);
        algorithmPanel.setBorder(BorderFactory.createTitledBorder("Algorithm"));

        JPanel optionPanel = new JPanel();
        optionPanel.add(operationPanel);
        optionPanel.add(algorithmPanel);

        JPanel inputPanel = new JPanel(new GridBagLayout());
        JList<File> inputList = new JList<>();
        inputList.setVisibleRowCount(4);
        GridBagConstraints listConstraints = new GridBagConstraints();
        listConstraints.gridx = listConstraints.gridy = 0;
        listConstraints.fill = GridBagConstraints.BOTH;
        listConstraints.weightx = 1.0;
        listConstraints.weighty = 1.0;
        JButton inputButton = new JButton(new MetalIconFactory.FolderIcon16());
        inputButton.setToolTipText("Choose input file path(s).");
        GridBagConstraints buttonConstraints = new GridBagConstraints();
        buttonConstraints.gridx = 1;
        buttonConstraints.gridy = 0;
        buttonConstraints.fill = GridBagConstraints.VERTICAL;
        buttonConstraints.insets = new Insets(0, 2, 0, 0);
        inputPanel.add(new JScrollPane(inputList), listConstraints);
        inputPanel.add(inputButton, buttonConstraints);
        inputPanel.setBorder(BorderFactory.createTitledBorder("Input file(s)"));
        inputPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent ce) {
                inputPanel.setPreferredSize(ce.getComponent().getSize());
            }
        });
        inputButton.addActionListener(ae -> {
            switch(digestOp) {
            case GENERATE:
                File[] inputFiles = chooseMultiFiles();
                if (inputFiles != null) {digestInputFiles = inputFiles;}
                break;
            case VERIFY:
                File inputFile = chooseFile(JFileChooser.OPEN_DIALOG);
                if (inputFile != null) {digestInputFiles = new File[] {inputFile};}
                break;
            default:
                break;
            }
            if (digestInputFiles != null) {inputList.setListData(digestInputFiles);}
        });

        verifyRadioButton.addActionListener(ae -> {
            digestOp = DigestOperation.VERIFY;
            if (digestInputFiles != null && digestInputFiles.length > 1) {
                digestInputFiles = null;
                inputList.setListData(new File[] {});
            }
        });

        JPanel outputPanel = new JPanel(new GridLayout(1, 1));
        JTextArea outputTextArea = new JTextArea();
        outputTextArea.setRows(5);
        outputTextArea.setEditable(false);
        Font origin = outputTextArea.getFont();
        Font mono = new Font("Monospaced", origin.getStyle(), origin.getSize());
        outputTextArea.setFont(mono);
        outputPanel.add(new JScrollPane(outputTextArea));
        outputPanel.setBorder(BorderFactory.createTitledBorder("Output"));
        outputPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent ce) {
                outputPanel.setPreferredSize(ce.getComponent().getSize());
            }
        });

        JPanel progressPanel = new JPanel();
        digestProgress = new JProgressBar();
        progressPanel.add(digestProgress);
        progressPanel.setBorder(BorderFactory.createTitledBorder("Progress"));
        progressPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent ce) {
                Component panel = ce.getComponent();
                Dimension panelDimension = panel.getSize();
                Dimension progressDimension = digestProgress.getPreferredSize();
                progressDimension.width = panelDimension.width - 20;
                digestProgress.setPreferredSize(progressDimension);
                panel.doLayout();
            }
        });

        JPanel buttonPanel = new JPanel(new GridBagLayout());
        JButton commitButton = new JButton("Commit");
        commitButton.setMnemonic('C');
        JButton resetButton = new JButton("Reset");
        resetButton.setMnemonic('R');
        JButton cancelButton = new JButton("Cancel");
        cancelButton.setMnemonic('n');
        cancelButton.setEnabled(false);
        Dimension dimension = commitButton.getPreferredSize();
        resetButton.setPreferredSize(dimension);
        cancelButton.setPreferredSize(dimension);
        JButton saveButton = new JButton("Save output");
        saveButton.setEnabled(false);
        saveButton.setMnemonic('S');
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        leftPanel.add(commitButton);
        leftPanel.add(resetButton);
        leftPanel.add(cancelButton);
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        rightPanel.add(saveButton);
        GridBagConstraints leftConstraints = new GridBagConstraints();
        leftConstraints.gridx = leftConstraints.gridy = 0;
        leftConstraints.fill = GridBagConstraints.HORIZONTAL;
        leftConstraints.weightx = 1.0;
        GridBagConstraints rightConstraints = new GridBagConstraints();
        rightConstraints.gridx = 1;
        rightConstraints.gridy = 0;
        rightConstraints.anchor = GridBagConstraints.EAST;
        buttonPanel.add(leftPanel, leftConstraints);
        buttonPanel.add(rightPanel, rightConstraints);
        JComponent[] digestComponents = {generateRadioButton, verifyRadioButton, md5RadioButton, sha1RadioButton, sha256RadioButton,
                                         inputList, inputButton, commitButton, resetButton};
        commitButton.addActionListener(ae -> {
            disableComponents(digestComponents);
            if (digestInputFiles == null || digestInputFiles.length == 0) {
                enableComponents(digestComponents);
                JOptionPane.showMessageDialog(this, "Please choose input file(s).", "Warning", JOptionPane.WARNING_MESSAGE);
                return;
            }
            outputTextArea.setText("");
            saveButton.setEnabled(false);
            digestWorker = new Thread(() -> {
                switch(digestOp) {
                case GENERATE:
                    isSucceeded = true;
                    for (File file: digestInputFiles) {
                        try (InputStream in = Files.newInputStream(file.toPath());
                             BufferedInputStream bufferedIn = new BufferedInputStream(in)) {
                            String digest = toHexString(generateDigest(digestAlgo, bufferedIn));
                            SwingUtilities.invokeLater(() -> outputTextArea.append(digest + "  " + file.getName() + "\n"));
                        }
                        catch(NoSuchAlgorithmException ex) {
                            ex.printStackTrace();
                            String msg = "Operation failed!\nCurrent platform dose not support the specific hash algorithm.\n" + ex.getMessage();
                            SwingUtilities.invokeLater(
                                () -> JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE)
                            );
                            isSucceeded = false;
                            SwingUtilities.invokeLater(() -> outputTextArea.setText(""));
                            break;
                        }
                        catch(ClosedByInterruptException ex) {
                            return;
                        }
                        catch(IOException ex) {
                            ex.printStackTrace();
                            StringBuilder builder = new StringBuilder();
                            builder.append("Operation failed!\n").append(file.getAbsolutePath()).append("\n").append(ex.getMessage());
                            SwingUtilities.invokeLater(
                                () -> JOptionPane.showMessageDialog(this,  builder.toString(), "Error", JOptionPane.ERROR_MESSAGE)
                            );
                            isSucceeded = false;
                            SwingUtilities.invokeLater(() -> outputTextArea.setText(""));
                            break;
                        }
                        catch(InterruptedException ex) {
                            return;
                        }
                    }
                    break;
                case VERIFY:
                    isSucceeded = true;
                    Path path = digestInputFiles[0].toPath();
                    if (!checkFileType(path)) {
                        SwingUtilities.invokeLater(() -> {
                            String msg = "Invalid file format!\nMaybe this file was not produced by this software or had been corrupted.";
                            JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
                        });
                        isSucceeded = false;
                        break;
                    } else {
                        try (BufferedReader reader = Files.newBufferedReader(path)) {
                            int lineNum = 0, failures = 0;
                            String line = null;
                            while ((line = reader.readLine()) != null) {
                                ++lineNum;
                                String[] parts = line.split(" [ *]");
                                if (parts.length != 2) {
                                    String msg = "Invalid format at line " + lineNum + "!";
                                    SwingUtilities.invokeLater(
                                        () -> JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE)
                                    );
                                    isSucceeded = false;
                                    break;
                                }
                                StringBuilder result = new StringBuilder(parts[1] + ": ");
                                if (verifyDigest(digestAlgo, path.resolveSibling(parts[1]), parts[0])) {result.append("OK");}
                                else {
                                    result.append("FAILED");
                                    ++failures;
                                }
                                result.append("\n");
                                SwingUtilities.invokeLater(() -> outputTextArea.append(result.toString()));
                            }
                            if (failures != 0) {
                                String singular = String.format("Waring: %d computed checksum mismatches!", failures);
                                String plural = String.format("Warning: %d computed checksums mismatch!", failures);
                                String msg = failures == 1 ? singular : plural;
                                SwingUtilities.invokeLater(() -> outputTextArea.append(msg));
                            }
                        }
                        catch(NoSuchAlgorithmException ex) {
                            ex.printStackTrace();
                            SwingUtilities.invokeLater(() -> {
                                String msg = "Operation failed!\nCurrent platform does not support the specific hash algorithm.\n" + ex.getMessage();
                                JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
                            });
                            isSucceeded = false;
                            break;
                        }
                        catch(ClosedByInterruptException ex) {
                            return;
                        }
                        catch(IOException ex) {
                            ex.printStackTrace();
                            SwingUtilities.invokeLater(
                                () -> JOptionPane.showMessageDialog(this, "Operation failed!\n" + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE)
                            );
                            isSucceeded = false;
                            break;
                        }
                        catch(InterruptedException ex) {
                            return;
                        }
                    }
                    break;
                default:
                    break;
                }
                SwingUtilities.invokeLater(() -> {
                    cancelButton.setEnabled(false);
                    digestProgress.setIndeterminate(false);
                    setCursor(Cursor.getDefaultCursor());
                    if (isSucceeded) {
                        JOptionPane.showMessageDialog(this, "Operation completed successfully.", "Info", JOptionPane.INFORMATION_MESSAGE);
                        if (digestOp == DigestOperation.GENERATE) {saveButton.setEnabled(true);}
                        isSucceeded = false;
                    }
                    enableComponents(digestComponents);
                    digestWorker = null;
                });
            });
            digestWorker.start();
            cancelButton.setEnabled(true);
            digestProgress.setIndeterminate(true);
            setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        });
        resetButton.addActionListener(ae -> {
            generateRadioButton.doClick();
            sha1RadioButton.doClick();
            inputList.setListData(new File[] {});
            digestInputFiles = null;
            outputTextArea.setText("");
            saveButton.setEnabled(false);
        });
        cancelButton.addActionListener(ae -> {
            if (digestWorker != null) {
                digestWorker.interrupt();
                digestWorker = null;
            }
            digestProgress.setIndeterminate(false);
            setCursor(Cursor.getDefaultCursor());
            outputTextArea.setText("");
            cancelButton.setEnabled(false);
            isSucceeded = false;
            enableComponents(digestComponents);
        });
        saveButton.addActionListener(ae -> saveDigestOutput(outputTextArea.getText()));

        Box digestBox = Box.createVerticalBox();
        digestBox.add(optionPanel);
        digestBox.add(Box.createVerticalStrut(5));
        digestBox.add(inputPanel);
        digestBox.add(Box.createVerticalStrut(5));
        digestBox.add(outputPanel);
        digestBox.add(Box.createVerticalStrut(5));
        digestBox.add(progressPanel);
        digestBox.add(Box.createVerticalStrut(5));
        digestBox.add(buttonPanel);

        JPanel digestPanel = new JPanel();
        digestPanel.add(digestBox);
        return digestPanel;
    }
    
    private void enableComponents(JComponent... components) {
        for (JComponent component: components) {component.setEnabled(true);}
    }

    private void disableComponents(JComponent... components) {
        for (JComponent component: components) {component.setEnabled(false);}
    }

    private File chooseFile(int type) {
        File file = null;
        JFileChooser chooser = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
        chooser.setMultiSelectionEnabled(false);
        switch(type) {
        case JFileChooser.OPEN_DIALOG:
            if (JFileChooser.APPROVE_OPTION == chooser.showOpenDialog(this)) {
                file = chooser.getSelectedFile();
            }
            break;
        case JFileChooser.SAVE_DIALOG:
            if (JFileChooser.APPROVE_OPTION == chooser.showSaveDialog(this)) {
                file = chooser.getSelectedFile();
            }
            break;
        default:
            break;
        }
        return file;
    }

    private File[] chooseMultiFiles() {
        JFileChooser chooser = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
        chooser.setMultiSelectionEnabled(true);
        if (JFileChooser.APPROVE_OPTION == chooser.showOpenDialog(this)) {return chooser.getSelectedFiles();}
        else {return null;}
    }

    private void saveDigestOutput(String digests) {
        if (digests == null || digests.trim().length() == 0) return;
        if (digestInputFiles != null && digestInputFiles.length > 0) {
            JFileChooser chooser = new JFileChooser();
            chooser.setMultiSelectionEnabled(false);
            String ext = "";
            switch(digestAlgo) {
                case MD5: ext = ".md5"; break;
                case SHA1: ext = ".sha1"; break;
                case SHA256: ext = ".sha256"; break;
                default: break;
            }
            chooser.setSelectedFile(new File(digestInputFiles[0].getParentFile(), "checksum" + ext));
            if (JFileChooser.APPROVE_OPTION == chooser.showSaveDialog(this)) {
                Path path = chooser.getSelectedFile().toPath();
                if (Files.isRegularFile(path)) {
                    String msg = path + " already exists.\nDo you want to overwrite it?";
                    if (JOptionPane.NO_OPTION == JOptionPane.showConfirmDialog(this, msg, "Confirmation", JOptionPane.YES_NO_OPTION)) return;
                }
                try {Files.write(path, digests.getBytes(StandardCharsets.UTF_8));}
                catch(Exception ex) {
                    ex.printStackTrace();
                    String msg = "Operation failed! Can not save output to" + path + ".\n" + ex.getMessage();
                    JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                JOptionPane.showMessageDialog(this, path + " saved successfully.", "Info", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    private boolean checkFileType(Path path) {
        String hexadecimal = "0123456789abcdefABCDEF";
        try (BufferedReader reader = Files.newBufferedReader(path)) {
            for (int i = 0; i < 16; ++i) {
                int c = reader.read();
                if (c == -1 || hexadecimal.indexOf(c) == -1) return false;
            }
            return true;
        }
        catch(Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
}