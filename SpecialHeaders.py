# -*- coding: utf-8 -*-
import json, os
from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab, ITab
from javax.swing import JPanel, JEditorPane, JScrollPane, BoxLayout, JLabel, JButton, JTextArea, JSplitPane, JTabbedPane
from java.awt import BorderLayout, Color, Font, Dimension
from javax.swing.border import EmptyBorder, TitledBorder, LineBorder

SETTINGS_FILE = os.path.expanduser("~/.burp_headers_plugin.json")

class BurpExtender(IBurpExtender, IMessageEditorTabFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Headers Viewer Pro")

        # Load saved settings
        self._loadSettings()

        # Build settings UI
        self._buildSettingsUI()

        # Register plugin
        callbacks.addSuiteTab(self)
        callbacks.registerMessageEditorTabFactory(self)

    # ========================================
    # Settings load/save
    # ========================================

    def _loadSettings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r") as f:
                    data = json.load(f)

                self.filtered_headers = set(data.get("filtered_headers", []))
                self.highlight_headers = set(data.get("highlight_headers", []))
            except:
                self.filtered_headers = set()
                self.highlight_headers = set()
        else:
            self.filtered_headers = set()
            self.highlight_headers = set()

    def _saveSettings(self):
        data = {
            "filtered_headers": list(self.filtered_headers),
            "highlight_headers": list(self.highlight_headers)
        }
        with open(SETTINGS_FILE, "w") as f:
            json.dump(data, f, indent=2)

    # ========================================
    # Settings Panel UI
    # ========================================

    def _buildSettingsUI(self):
        # Main panel with border
        self.settings_panel = JPanel(BorderLayout())
        self.settings_panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Create tabbed pane for better organization
        tabbed_pane = JTabbedPane()
        
        # Tab 1: Headers Management
        headers_tab = self._createHeadersTab()
        tabbed_pane.addTab("Headers Management", headers_tab)
        
        # Tab 2: About
        about_tab = self._createAboutTab()
        tabbed_pane.addTab("About", about_tab)

        self.settings_panel.add(tabbed_pane, BorderLayout.CENTER)

    def _createHeadersTab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Create split pane for side-by-side layout
        split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        split_pane.setResizeWeight(0.5)
        split_pane.setDividerLocation(0.5)

        # Left side - Filtered Headers
        left_panel = JPanel(BorderLayout(5, 5))
        left_panel.setBorder(TitledBorder(LineBorder(Color.GRAY, 1), "Hidden Headers"))
        
        left_panel.add(JLabel("Headers to hide from view - One per line (case-insensitive)"), BorderLayout.NORTH)
        
        self.filter_text = JTextArea()
        self.filter_text.setText("\n".join(sorted(self.filtered_headers)))
        self.filter_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.filter_text.setLineWrap(True)
        self.filter_text.setWrapStyleWord(True)
        
        filter_scroll = JScrollPane(self.filter_text)
        filter_scroll.setPreferredSize(Dimension(300, 200))
        left_panel.add(filter_scroll, BorderLayout.CENTER)
        
        # Filter buttons
        filter_btn_panel = JPanel()
        save_filter_btn = JButton("Save Hidden List", actionPerformed=self._saveFilters)
        save_filter_btn.setToolTipText("Save the list of headers to hide")
        clear_filter_btn = JButton("Clear", actionPerformed=lambda e: self.filter_text.setText(""))
        clear_filter_btn.setToolTipText("Clear the hidden headers list")
        
        filter_btn_panel.add(save_filter_btn)
        filter_btn_panel.add(clear_filter_btn)
        left_panel.add(filter_btn_panel, BorderLayout.SOUTH)

        # Right side - Highlighted Headers
        right_panel = JPanel(BorderLayout(5, 5))
        right_panel.setBorder(TitledBorder(LineBorder(Color.GRAY, 1), "Highlighted Headers"))
        
        right_panel.add(JLabel("Headers to highlight in red - One per line (case-insensitive)"), BorderLayout.NORTH)
        
        self.highlight_text = JTextArea()
        self.highlight_text.setText("\n".join(sorted(self.highlight_headers)))
        self.highlight_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.highlight_text.setLineWrap(True)
        self.highlight_text.setWrapStyleWord(True)
        
        highlight_scroll = JScrollPane(self.highlight_text)
        highlight_scroll.setPreferredSize(Dimension(300, 200))
        right_panel.add(highlight_scroll, BorderLayout.CENTER)
        
        # Highlight buttons
        highlight_btn_panel = JPanel()
        save_highlight_btn = JButton("Save Highlight List", actionPerformed=self._saveHighlights)
        save_highlight_btn.setToolTipText("Save the list of headers to highlight")
        clear_highlight_btn = JButton("Clear", actionPerformed=lambda e: self.highlight_text.setText(""))
        clear_highlight_btn.setToolTipText("Clear the highlighted headers list")
        
        highlight_btn_panel.add(save_highlight_btn)
        highlight_btn_panel.add(clear_highlight_btn)
        right_panel.add(highlight_btn_panel, BorderLayout.SOUTH)

        split_pane.setLeftComponent(left_panel)
        split_pane.setRightComponent(right_panel)

        panel.add(split_pane, BorderLayout.CENTER)

        return panel

    def _createAboutTab(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(EmptyBorder(20, 20, 20, 20))

        # Simple text without HTML
        title_label = JLabel("Headers Viewer Pro", JLabel.CENTER)
        title_label.setFont(Font("SansSerif", Font.BOLD, 18))
        
        version_label = JLabel("Version 2.0", JLabel.CENTER)
        version_label.setFont(Font("SansSerif", Font.PLAIN, 14))
        
        desc_label = JLabel("Enhanced Header Management for Burp Suite", JLabel.CENTER)
        
        features_label = JLabel("Features:", JLabel.CENTER)
        features_label.setFont(Font("SansSerif", Font.BOLD, 12))
        
        # Create features list without HTML
        features_panel = JPanel()
        features_panel.setLayout(BoxLayout(features_panel, BoxLayout.Y_AXIS))
        
        feature1 = JLabel("- Clean header-only view in separate tab")
        feature2 = JLabel("- Hide unwanted headers from view")
        feature3 = JLabel("- Highlight important headers in red")
        feature4 = JLabel("- Automatic header counting")
        
        features_panel.add(feature1)
        features_panel.add(feature2)
        features_panel.add(feature3)
        features_panel.add(feature4)
        
        note_label = JLabel("Simply navigate to any request/response to see the Headers tab in action!", JLabel.CENTER)
        note_label.setFont(Font("SansSerif", Font.ITALIC, 12))

        about_panel = JPanel()
        about_panel.setLayout(BoxLayout(about_panel, BoxLayout.Y_AXIS))
        about_panel.add(title_label)
        about_panel.add(version_label)
        about_panel.add(desc_label)
        about_panel.add(JLabel(" "))  # spacer
        about_panel.add(features_label)
        about_panel.add(features_panel)
        about_panel.add(JLabel(" "))  # spacer
        about_panel.add(note_label)

        panel.add(about_panel, BorderLayout.CENTER)

        return panel

    # Save lists
    def _saveFilters(self, event):
        lines = self.filter_text.getText().split("\n")
        self.filtered_headers = set([l.strip().lower() for l in lines if l.strip()])
        self._saveSettings()
        self.callbacks.printOutput("Hidden headers list saved. (" + str(len(self.filtered_headers)) + " headers)")

    def _saveHighlights(self, event):
        lines = self.highlight_text.getText().split("\n")
        self.highlight_headers = set([l.strip().lower() for l in lines if l.strip()])
        self._saveSettings()
        self.callbacks.printOutput("Highlight headers list saved. (" + str(len(self.highlight_headers)) + " headers)")

    # ========================================
    # Burp Tab
    # ========================================
    def getTabCaption(self):
        return "Headers Settings"

    def getUiComponent(self):
        return self.settings_panel

    # ========================================
    # Editor Tab Factory
    # ========================================
    def createNewInstance(self, controller, editable):
        return HeadersTab(self, controller)


# ========================================
# Viewer TAB
# ========================================

class HeadersTab(IMessageEditorTab):

    def __init__(self, extender, controller):
        self.extender = extender
        self.controller = controller
        self.panel = JPanel(BorderLayout())
        self.html_viewer = JEditorPane("text/html", "")
        self.html_viewer.setEditable(False)
        self.panel.add(JScrollPane(self.html_viewer), BorderLayout.CENTER)
        self.headers_count = 0  # Current headers count

    def getTabCaption(self):
        return "Headers (%d)" % self.headers_count

    def getUiComponent(self):
        return self.panel

    def isEnabled(self, content, isRequest):
        return True

    def setMessage(self, content, isRequest):
        self.headers_count = 0  # reset
        if not content:
            self.html_viewer.setText("")
            return

        helpers = self.extender.helpers
        try:
            analyzed = helpers.analyzeRequest(content) if isRequest else helpers.analyzeResponse(content)
            headers = analyzed.getHeaders()

            html = "<html><body style='font-family: monospace; background-color: #2b2b2b; color: #ffffff; padding: 10px;'>"
            for h in headers[1:]:  # skip request line
                parts = h.split(":", 1)
                if len(parts) != 2: continue
                name = parts[0].strip().lower()
                value = parts[1].strip()

                if name in self.extender.filtered_headers:
                    continue

                self.headers_count += 1
                if name in self.extender.highlight_headers:
                    # Only header name in red and bold
                    html += "<div style='margin-bottom: 2px;'><span style='color: #ff6b6b; font-weight: bold;'>%s</span>: <span style='color: #a9b7c6;'>%s</span></div>" % (parts[0], value)
                else:
                    # Only header name in white and bold
                    html += "<div style='margin-bottom: 2px;'><span style='color: #ffffff; font-weight: bold;'>%s</span>: <span style='color: #a9b7c6;'>%s</span></div>" % (parts[0], value)

            html += "</body></html>"
            self.html_viewer.setText(html)
            # Force Burp to refresh tab caption
            self.panel.revalidate()

        except Exception as e:
            self.html_viewer.setText("<html><body style='color: red;'>Error: %s</body></html>" % e)

    def getMessage(self):
        return self.controller.getMessage()

    def isModified(self):
        return False
