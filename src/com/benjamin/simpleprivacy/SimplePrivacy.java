package com.benjamin.simpleprivacy;

import javax.swing.SwingUtilities;

public class SimplePrivacy {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new PrivacyFrame());
    }
}