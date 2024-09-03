# -*- coding: utf-8 -*-
# Author: ALPEREN ERGEL (@alpernae)
# v0.7 (UI Fix)

import os
import json
import urllib2
import subprocess
import threading # Import the threading module
import re # Import the re module for regular expressions

from java.lang import Integer
from java.util import ArrayList
from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import BorderFactory, JOptionPane, SwingUtilities, UIManager
from java.awt import FlowLayout, Dimension, Color, BorderLayout, Font
from javax.swing import (
    JPanel,
    JScrollPane,
    JButton,
    JMenuItem,
    BoxLayout,
    JTextField,
    JLabel,
    JTextPane,
    Box,
)


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def __init__(self):
        self.api_key_file = os.path.expanduser("~/.api_key")
        self.server_running = False
        self.server_process = None

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self._helpers = self.callbacks.getHelpers()
        self.callbacks.setExtensionName("BurpAI")

        # Add additional metadata
        extension_info = {
            "Author": "ALPEREN ERGEL (@alpernae)",
            "Version": "v0.8",
            "Description": "BurpAI is a powerful Burp Suite extension that leverages artificial intelligence to elevate your web security testing workflow.",
        }

        for key, value in extension_info.items():
            self.callbacks.printOutput("{}: {}".format(key, value))

        # UI Setup
        self.panel = JPanel(BorderLayout())
        self.panel.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20))

        # Top Panel (API Key)
        top_panel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 10))
        api_key_panel = JPanel()
        api_key_panel.setLayout(BoxLayout(api_key_panel, BoxLayout.X_AXIS))

        api_key_label = JLabel("API KEY")
        api_key_label.setPreferredSize(Dimension(70, 40))
        api_key_label.setFont(Font("Arial", Font.BOLD, 14))

        self.api_key_input = JTextField("", 27)
        self.api_key_input.setPreferredSize(Dimension(100, 25))

        api_key_panel.add(api_key_label)
        api_key_panel.add(self.api_key_input)

        add_key_button = JButton("Add API Key", actionPerformed=self.add_api_key)
        add_key_button.setPreferredSize(Dimension(130, 30))
        add_key_button.setBackground(Color.decode("#d86633"))
        add_key_button.setForeground(Color.WHITE)
        add_key_button.setOpaque(True)
        add_key_button.setBorderPainted(False)

        self.server_button = JButton("Activate", actionPerformed=self.toggle_server)
        self.server_button.setPreferredSize(Dimension(130, 30))
        self.server_button.setBackground(Color.decode("#d86633"))
        self.server_button.setForeground(Color.WHITE)
        self.server_button.setOpaque(True)
        self.server_button.setBorderPainted(False)

        top_panel.add(api_key_panel)
        top_panel.add(add_key_button)
        top_panel.add(self.server_button)

        # Center Panel (Messages)
        self.messages_panel = JPanel()
        self.messages_panel.setLayout(BoxLayout(self.messages_panel, BoxLayout.Y_AXIS))
        self.messages_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        self.scroll_pane = JScrollPane(self.messages_panel)
        self.scroll_pane.setVerticalScrollBarPolicy(
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS
        )
        self.scroll_pane.setHorizontalScrollBarPolicy(
            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
        )

        self.panel.add(self.scroll_pane, BorderLayout.CENTER)

        # Bottom Panel (Prompt Input)
        bottom_panel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 10))
        prompt_input_panel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 0))

        self.prompt_input = JTextField("", 35)
        self.prompt_input.setPreferredSize(Dimension(130, 30))

        prompt_input_panel.add(self.prompt_input)

        send_prompt_button = JButton("Send Prompt", actionPerformed=self.send_prompt)
        send_prompt_button.setPreferredSize(Dimension(130, 30))
        send_prompt_button.setBackground(Color.decode("#d86633"))
        send_prompt_button.setForeground(Color.WHITE)
        send_prompt_button.setOpaque(True)
        send_prompt_button.setBorderPainted(False)

        bottom_panel.add(prompt_input_panel)
        bottom_panel.add(send_prompt_button)

        self.panel.add(top_panel, BorderLayout.NORTH)
        self.panel.add(bottom_panel, BorderLayout.SOUTH)

        self.load_api_key()
        self.callbacks.addSuiteTab(self)
        self.callbacks.registerContextMenuFactory(self)

    def getTabCaption(self):
        return "BurpAI"

    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = ArrayList()
        menuList.add(JMenuItem("Ask The AI", actionPerformed=self.AskTheAi))
        return menuList

    def getUiComponent(self):
        return self.panel

    def toggle_server(self, event):
        if self.server_running:
            self.stop_server()
            self.server_button.setText("Activete")
            self.server_button.setBackground(Color.decode("#d86633"))
            self.server_button.setForeground(Color.WHITE)
        else:
            self.start_server()
            if self.server_running:
                self.server_button.setText("Deactivate")
                self.server_button.setBackground(Color.GREEN)
                self.server_button.setForeground(Color.BLACK)

    # START SERVER
    def start_server(self):
        if not self.server_running:
            try:
                self.server_process = subprocess.Popen(
                    ["python", "server/app.py"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.server_running = True
                print("Server Started!")
            except Exception as e:
                print("Failed to start server: {}".format(e))

    # STOP SERVER
    def stop_server(self):
        if self.server_running and self.server_process:
            try:
                self.server_process.kill()
                self.server_process.kill()
                self.server_running = False
                print("Server Stopped!")
            except Exception as e:
                print("Failed to stop server: {}".format(e))

        # LOAD SAVED API KEY

    def load_api_key(self):
        if os.path.exists(self.api_key_file):
            with open(self.api_key_file, "r") as f:
                api_key = f.read().strip()
                self.api_key_input.setText(api_key)
        # ADD API KEY

    def add_api_key(self, event):
        api_key = self.api_key_input.getText()
        if api_key:
            with open(self.api_key_file, "w") as f:
                f.write(api_key)
            JOptionPane.showMessageDialog(
                None,
                "API Key successfully saved!",
                "Success",
                JOptionPane.INFORMATION_MESSAGE,
            )
        else:
            JOptionPane.showMessageDialog(
                None, "API Key cannot be empty!", "Error", JOptionPane.ERROR_MESSAGE
            )

    # SEND PROMPT TO AI (in a separate thread)
    def send_prompt(self, event):
        prompt = self.prompt_input.getText()
        self.prompt_input.setText("")
        self.add_message_to_chat(prompt, is_user=True)

        # Create and start a new thread for the AI communication
        threading.Thread(target=self.ai_request, args=(prompt,)).start()

    # Function to handle the AI request
    def ai_request(self, prompt):
        try:
            url = "http://127.0.0.1:5000/generate"
            data = json.dumps({"prompt": prompt}, ensure_ascii=False).encode("utf-8")
            headers = {"Content-Type": "application/json"}

            request = urllib2.Request(url, data, headers)
            response = urllib2.urlopen(request)
            content = response.read().decode("utf-8")

            response_json = json.loads(content)
            response_text = response_json.get("response", "No response content")

            # Use SwingUtilities.invokeLater to update the UI from the thread
            SwingUtilities.invokeLater(lambda: self.process_ai_response(response_text))

        except Exception as e:
            error_message = "Error: {}".format(e)
            SwingUtilities.invokeLater(lambda: self.add_message_to_chat(error_message, is_user=False))

    # Function to extract command output from text
    def extract_command_output(self, text):
        # Example using regular expressions to find text within ``` blocks 
        match = re.search(r"```\n(.*?)\n```", text, re.DOTALL)
        if match:
            return match.group(1).strip()
        else:
            return None  # Or return an appropriate value if no command output is found

    # Process the AI response and add it to the chat
    def process_ai_response(self, response_text):
        command_output = self.extract_command_output(response_text)
        if command_output:
            self.add_message_to_chat("```\n" + command_output + "\n```", is_user=False)
        else:
            self.add_message_to_chat(response_text, is_user=False)

    def AskTheAi(self, event):
        # Get the selected message
        selectedMessages = self.context.getSelectedMessages()
        if len(selectedMessages) != 1:
            print("[-] Please select a single request or response.")
            return

        message = selectedMessages[0]
        msgInfo = self._helpers.analyzeRequest(message)

        # Extract request information
        request = message.getRequest()
        analyzedRequest = self._helpers.analyzeRequest(request)
        requestHeaders = analyzedRequest.getHeaders()
        requestBody = request[analyzedRequest.getBodyOffset() :].tostring()

        # Extract response information
        response = message.getResponse()
        if response:  # Check if response exists
            analyzedResponse = self._helpers.analyzeResponse(response)
            responseHeaders = analyzedResponse.getHeaders()
            responseBody = response[analyzedResponse.getBodyOffset() :].tostring()
        else:
            responseHeaders = ["No response found."]
            responseBody = ""

        # Decode request and response bodies to Unicode (assuming UTF-8 encoding)
        requestBody = requestBody.decode("utf-8", errors="replace")
        if response:
            responseBody = responseBody.decode("utf-8", errors="replace")

        # Decode headers (using UTF-8, replace invalid characters with '?')
        decodedRequestHeaders = [
            header.decode("utf-8", errors="replace") for header in requestHeaders
        ]
        decodedResponseHeaders = [
            header.decode("utf-8", errors="replace") for header in responseHeaders
        ]

        # Format the request and response as a prompt (using .format())
        request_prompt = """
    REQUEST:
    {}
    {}
    """.format(
            "-" * 50, "\n".join(decodedRequestHeaders) + "\n" + requestBody
        )

        response_prompt = """
    RESPONSE:
    {}
    {}
    """.format(
            "-" * 50, "\n".join(decodedResponseHeaders) + "\n" + responseBody
        )

        initial_prompt = """
Carefully examine the following HTTP request and response:
Analyze this request and response to determine if any security vulnerabilities are present. Follow the steps below:
1. **Identify Input Points:** Identify all input points within the request (parameters, headers, body data, etc.) that originate from the user.
2. **Examine Vulnerability Types:** Analyze each input point for the following types of vulnerabilities:
   - **XSS (Cross-Site Scripting):** Check if the input points are properly sanitized. Identify test payloads for potential XSS attacks.
   - **SQL Injection:** Inspect parameters that might be used in database queries for SQL injection risks. Identify test payloads for potential SQL Injection.
   - **CSRF (Cross-Site Request Forgery):** Determine if the requests are protected against CSRF attacks. Specify methods and payloads to test for CSRF.
   - **IDOR (Insecure Direct Object References):** Examine requests for object references that lack proper authorization checks. Identify payloads for IDOR testing.
   - **Command Injection:** Assess the risk of command injection in server-side commands or scripts. Specify test payloads for potential Command Injection.
   - **File Upload/Download Vulnerabilities:** If the request involves file upload or download, check for security measures and potential file handling vulnerabilities.
   - **Other Vulnerability Types:** Examine other potential vulnerability types (e.g., security misconfigurations, information disclosure, etc.) and specify appropriate testing methods.
3. **Technology Detection:** Identify the technologies used by the application based on request and response data:
   - **Web Server and Frameworks:** Analyze headers and other metadata to identify the web server (e.g., Apache, Nginx) and server-side frameworks (e.g., Django, Ruby on Rails).
   - **Programming Languages and Libraries:** Infer the programming languages (e.g., PHP, Python) or libraries based on the response structure or content.
   - **Content Management Systems (CMS) or Platforms:** Detect if a CMS or specific platform (e.g., WordPress, Joomla) is in use.
   - **Frontend Technologies:** Identify frontend technologies (e.g., Angular, React) based on response content or request patterns.
4. **Response Analysis:** Analyze the HTTP response:
   - **Potential Vulnerabilities in the Response:** Is there any sensitive data leakage, insecure error messages, or other signs of vulnerabilities in the response?
   - **Request-Response Relationship:** Examine the relationship between the request and response. Does the response expose any security weaknesses related to the request?
6. **Findings and Recommendations:**
   - Specify the input points associated with each identified vulnerability.
   - List the potential vulnerability type and appropriate test payloads.
   - Explain how the vulnerability could be exploited and the potential consequences.
   - Provide recommendations to mitigate or address the vulnerability.
7. **Technology-Specific Recommendations:** Based on the detected technologies, provide any additional recommendations or considerations specific to those technologies.
show the results only for possaible vulnerabilities. Do not show results for each vulnerability type.
        """

        # Create and start a new thread for the AI communication
        threading.Thread(target=self.ai_request, args=(initial_prompt + request_prompt + response_prompt,)).start()

    # Burp Suite'in tema ayarlarını al
    def currentTheme(self):
        # Attempt to get system theme as a workaround
        look_and_feel = UIManager.getLookAndFeel().getName()
        is_dark_theme = "dark" in look_and_feel.lower()  # Check for "dark" in the name
        #print("Current Theme (System): {}".format(look_and_feel))
        return is_dark_theme

    # ADD MESSAGE TO AI CHAT
    def add_message_to_chat(self, message, is_user):
        try:
            message_area = JTextPane()
            message_area.setContentType("text/html")

            # Get the current UI theme
            is_dark_theme = self.currentTheme()

            # Set colors based on the theme (consistent for user and AI)
            background_color = "#444343" if is_dark_theme else "#eeeeee" 
            text_color = "white" if is_dark_theme else "black"
            align = "left" if is_user else "left"  # Align user messages to the center 

            # Create the HTML message with the dynamic colors
            html_message = """
            <div style='background: {}; padding: 6px; margin: 5px; text-align: {}; max-width: 250px; word-wrap: break-word;'>
            <span style='color: {}; overflow-wrap: break-word; word-break: break-all;'>{}</span></div>
            """.format(
                background_color,
                align,
                text_color,
                message.replace("*", " ").replace("\n", "<br>"),
            )

            message_area.setText(html_message)
            message_area.setEditable(False)
            message_area.setOpaque(False)
            message_area.setMaximumSize(Dimension(300, Integer.MAX_VALUE))

            message_panel = JPanel()
            message_panel.setLayout(BoxLayout(message_panel, BoxLayout.X_AXIS))
            message_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
            message_panel.setOpaque(False)

            if is_user:
                message_panel.add(Box.createHorizontalGlue())  # Push user message to the right
                message_panel.add(message_area)
            else:
                message_panel.add(message_area)
                message_panel.add(Box.createHorizontalGlue())  # Push AI message to the left

            self.messages_panel.add(message_panel)
            self.messages_panel.revalidate()
            self.messages_panel.repaint()
            self.scroll_pane.revalidate()
            self.scroll_pane.repaint()

            SwingUtilities.invokeLater(
                lambda: self.scroll_pane.getVerticalScrollBar().setValue(
                    self.scroll_pane.getVerticalScrollBar().getMaximum()
                )
            )

        except Exception as e:
            print("Error: {}".format(e))