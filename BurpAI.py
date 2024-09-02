# -*- coding: utf-8 -*-
# Author: ALPEREN ERGEL (@alpernae)
# v0.7 (UI Fix)

import os
import json
import urllib2
import subprocess
from java.lang import Integer
from java.util import ArrayList
from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import BorderFactory, JOptionPane, SwingUtilities
from java.awt import FlowLayout, Dimension, Color, BorderLayout, Font
from javax.swing import (
    JPanel,
    JScrollPane,
    JButton,
    JMenu,
    JMenuBar,
    JMenuItem,
    BoxLayout,
    JTextField,
    JLabel,
    JTextPane,
    Box,
    SwingWorker,
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
            "Version": "v0.7",
            "Description": "An AI Assistant for Burp Suite",
            "Last Update": "08/30/2024",
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

        self.prompt_input = JTextField("", 20)
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
        return "BurpAI Assistant"

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

    def extract_command_output(self, response_text):
        # Basic placeholder implementation
        return response_text

        # SEND PROMPT TO AI ___________________________________________________________________________________________

    def send_prompt(self, event):
        prompt = self.prompt_input.getText()
        self.prompt_input.setText("")

        self.add_message_to_chat(prompt, is_user=True)

        try:
            url = "http://127.0.0.1:5000/generate"
            data = json.dumps({"prompt": prompt}, ensure_ascii=False).encode("utf-8")
            headers = {"Content-Type": "application/json"}

            request = urllib2.Request(url, data, headers)
            response = urllib2.urlopen(request)
            content = response.read().decode("utf-8")

            response_json = json.loads(content)
            response_text = response_json.get("response", "No response content")

            # Komut satırı çıktısını ayrıştır
            command_output = self.extract_command_output(response_text)
            if command_output:
                self.add_message_to_chat(
                    "```\n" + command_output + "\n```", is_user=False
                )
            else:
                self.add_message_to_chat(response_text, is_user=False)
        except urllib2.URLError as e:
            error_message = "Network Error: {}".format(e.reason)
            self.add_message_to_chat(error_message, is_user=False)
        except ValueError:
            error_message = "Error decoding JSON response from server."
            self.add_message_to_chat(error_message, is_user=False)
        except Exception as e:
            error_message = "Unexpected error: {}".format(e)
            self.add_message_to_chat(error_message, is_user=False)

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
        """

        # Send the prompt to the AI and display the response
        try:
            url = "http://127.0.0.1:5000/generate"
            data = json.dumps(
                {"prompt": initial_prompt + request_prompt + response_prompt},
                ensure_ascii=False,
            ).encode(
                "utf-8"
            )  # Combine prompts
            headers = {"Content-Type": "application/json"}

            request = urllib2.Request(url, data, headers)
            response = urllib2.urlopen(request)
            content = response.read().decode("utf-8")

            response_json = json.loads(content)
            ai_response = response_json.get("response", "No response from AI.")

            self.add_message_to_chat(ai_response, is_user=False)

        except urllib2.URLError as e:
            error_message = "Network Error: {}".format(e.reason)
            self.add_message_to_chat(error_message, is_user=False)
        except json.JSONDecodeError:
            error_message = "Error decoding JSON response from server."
            self.add_message_to_chat(error_message, is_user=False)
        except Exception as e:
            error_message = "Unexpected error: {}".format(e)
            self.add_message_to_chat(error_message, is_user=False)

        # ADD MESSAGE TO AI CHAT

    def add_message_to_chat(self, message, is_user):
        try:
            message_area = JTextPane()
            message_area.setContentType("text/html")

            panel_background = self.panel.getBackground()
            is_dark_theme = panel_background == Color.DARK_GRAY

            if is_dark_theme:
                background_color = "black"
                text_color = "white"
            else:
                background_color = "#eeeeee"
                text_color = "black"

            align = "center" if is_user else "left"

            html_message = """
            <div style="background: {}; padding: 5px; border-radius: 10px; text-align: {}; max-width: 300px; word-wrap: break-word;">
            <span style="color: {}; overflow-wrap: break-word; word-break: break-all;">{}</span>
            </div>
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
                message_panel.add(Box.createHorizontalGlue())
                message_panel.add(message_area)
            else:
                message_panel.add(message_area)
                message_panel.add(Box.createHorizontalGlue())

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
            print("Hata: {}".format(e))
