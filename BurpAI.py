# -*- coding: utf-8 -*-
# Author: ALPEREN ERGEL (@alpernae)
# v0.7 (UI Fix)

from javax.swing import JPanel, JScrollPane, JButton, JMenu, JMenuBar, JMenuItem, BoxLayout, JTextField, JLabel, JTextPane, JComboBox, Box
from java.awt import FlowLayout, Dimension, Color, BorderLayout, Font
from javax.swing import BorderFactory, JOptionPane, SwingUtilities
import os
import json
import urllib2
import subprocess
from burp import IBurpExtender, ITab, IContextMenuFactory
from java.lang import Integer

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    def __init__(self):
        # Init api key
        self.api_key_file = os.path.expanduser("~/.api_key")
        self.server_running = False
        self.server_process = None

        # Seçenekler için örnek veri
        self.options = ["Option 1", "Option 2", "Option 3"]

        print("Author: ALPEREN ERGEL (@alpernae)")

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpAI")

        # Add additional metadata
        extension_info = {
            "Author": "ALPEREN ERGEL (@alpernae)",
            "Version": "v0.7",
            "Description": "An AI Assistant for Burp Suite to help users create",
            "Last Update": "08/30/2024"
        }

        # Log the metadata information
        for key, value in extension_info.items():
            callbacks.printOutput("{}: {}".format(key, value))

        # Paneli oluştur
        self.panel = JPanel(BorderLayout())
        self.panel.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20))

        # Menü oluştur
        self.create_menu()

        # Üst kısım: API Key girişi
        top_panel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 10))

        # API Key Label ve Input Panel
        api_key_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        api_key_label = JLabel("Enter API Key")
        api_key_label.setPreferredSize(Dimension(150, 30))

        # API Key Input
        self.api_key_input = JTextField("", 20)
        self.api_key_input.setPreferredSize(Dimension(100, 30))

        # Panelde boşluk ayarla
        api_key_panel.add(api_key_label)
        api_key_panel.add(self.api_key_input)

        # Add Key Button
        add_key_button = JButton("Add API Key", actionPerformed=self.add_api_key)
        add_key_button.setPreferredSize(Dimension(130, 30))
        add_key_button.setBackground(Color.decode("#d86633"))
        add_key_button.setForeground(Color.WHITE)
        add_key_button.setOpaque(True)
        add_key_button.setBorderPainted(False)

        # Start/Stop Server Button
        self.server_button = JButton("Start Server", actionPerformed=self.toggle_server)
        self.server_button.setPreferredSize(Dimension(130, 30))
        self.server_button.setBackground(Color.decode("#d86633"))
        self.server_button.setForeground(Color.WHITE)
        self.server_button.setOpaque(True)
        self.server_button.setBorderPainted(False)

        # Bileşenleri top_panel'e ekle
        top_panel.add(api_key_panel)
        top_panel.add(add_key_button)
        top_panel.add(self.server_button)  # Add server button

        # Orta kısım: Mesajları gösterme
        self.messages_panel = JPanel()
        self.messages_panel.setLayout(BoxLayout(self.messages_panel, BoxLayout.Y_AXIS))
        self.messages_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Mesajları göstermek için bir kaydırma penceresi oluştur
        self.scroll_pane = JScrollPane(self.messages_panel)
        self.scroll_pane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self.scroll_pane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)

        # Kaydırma penceresini paneldeki merkezi bileşene ekle
        self.panel.add(self.scroll_pane, BorderLayout.CENTER)

        # Alt kısım: Prompt girişi ve gönderim
        bottom_panel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 10))
        
        # Prompt Input Panel
        prompt_input_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        
        # Create JComboBox with example options
        self.combo_box = JComboBox(["Option 1", "Option 2", "Option 3"])
        self.combo_box.setPreferredSize(Dimension(130, 30))
        
        # Plugin Label
        plugin_label = JLabel("Plugin")
        plugin_label.setPreferredSize(Dimension(60, 30))
        
        # Prompt Input
        self.prompt_input = JTextField("", 20)
        self.prompt_input.setPreferredSize(Dimension(130, 30))
        
        # Add components to the prompt input panel
        prompt_input_panel.add(plugin_label)  # Add JLabel first
        prompt_input_panel.add(self.combo_box)  # Add JComboBox next
        prompt_input_panel.add(self.prompt_input)  # Add JTextField last
        
        # Send Prompt Button
        send_prompt_button = JButton("Send Prompt", actionPerformed=self.send_prompt)
        send_prompt_button.setPreferredSize(Dimension(130, 30))
        send_prompt_button.setBackground(Color.decode("#d86633"))
        send_prompt_button.setForeground(Color.WHITE)
        send_prompt_button.setOpaque(True)
        send_prompt_button.setBorderPainted(False)
        
        # Add components to bottom panel
        bottom_panel.add(prompt_input_panel)
        bottom_panel.add(send_prompt_button)
        
        # Add panels to the main panel
        self.panel.add(top_panel, BorderLayout.NORTH)
        self.panel.add(bottom_panel, BorderLayout.SOUTH)


        # API Key'i dosyadan oku
        self.load_api_key()

        # Burp'a sekme olarak ekle
        callbacks.addSuiteTab(self)

        # Sağ tıklama menüsü için callback ayarla
        callbacks.registerContextMenuFactory(self)

    def create_menu(self):
        # Menü oluştur
        menu_bar = JMenuBar()

        # İstek ve Yanıtları Gönder menüsü
        Ask_to_AI = JMenu("Ask to AI")
        menu_bar.add(Ask_to_AI)

        # İstek ve Yanıtları Gönder menü öğesi
        send_ai_item = JMenuItem("Ask to AI")
        send_ai_item.addActionListener(self.send_request_and_response)
        Ask_to_AI.add(send_ai_item)

        # Menü çubuğunu paneldeki bir bileşene ekle (örneğin: üst panel)
        self.panel.add(menu_bar, BorderLayout.NORTH)

    def createMenuItems(self, invocation):
        # Sağ tıklama menüsü öğelerini oluşturur
        menu = []
        send_ai_item = JMenuItem("Ask to AI", actionPerformed=lambda event: self.send_request_and_response(invocation))
        menu.append(send_ai_item)
        return menu

    def getTabCaption(self):
        # Sekme ismi
        return "BurpAI Assistant"

    def getUiComponent(self):
        # Paneli döndür
        return self.panel

    def add_api_key(self, event):
        # API Key ekleme işlemi
        api_key = self.api_key_input.getText()
        if api_key:
            with open(self.api_key_file, 'w') as f:
                f.write(api_key)
            JOptionPane.showMessageDialog(None, "API Key successfully saved!", "Success", JOptionPane.INFORMATION_MESSAGE)
        else:
            JOptionPane.showMessageDialog(None, "API Key cannot be empty!", "Error", JOptionPane.ERROR_MESSAGE)

    def toggle_server(self, event):
        # Sunucuyu başlat/durdur
        if self.server_running:
            self.stop_server()
            self.server_button.setText("Start Server")
            self.server_button.setBackground(Color.decode("#d86633"))  # Background color to default
        else:
            self.start_server()  # Server_running'i değiştirmeden önce start_server'ı çağırın
            if self.server_running:  # Eğer sunucu başarıyla başlatıldıysa
                self.server_button.setText("Stop Server")
                self.server_button.setBackground(Color.GREEN)  # Background color to green

    def start_server(self):
        # Sunucu başlatma işlemi
        if not self.server_running:
            try:
                # Sunucu scriptini başlat
                self.server_process = subprocess.Popen(["python", "server/app.py"],
                                                      stdout=subprocess.PIPE,
                                                      stderr=subprocess.PIPE)
                self.server_running = True
                print("Server Started!")
            except Exception as e:
                print("Failed to start server: {}".format(e))

    def stop_server(self):
        # Sunucuyu durdurma işlemi
        if self.server_running and self.server_process:
            try:
                self.server_process.kill()  # terminate() yerine kill() kullanın
                self.server_process.kill()
                self.server_running = False
                print("Server Stopped!")
            except Exception as e:
                print("Failed to stop server: {}".format(e))
    
    def handle_combo_box_selection(self, event):
        selected_option = self.combo_box.getSelectedItem()
        print("Selected Option:", selected_option)
    
        # In the registerExtenderCallbacks method or where you define the combo box:
        self.combo_box.addActionListener(self.handle_combo_box_selection)

    def send_prompt(self, event):
        prompt = self.prompt_input.getText()
        self.prompt_input.setText("")  # Clear prompt input

        # Add user message
        self.add_message_to_chat(prompt, is_user=True)

        try:
            url = "http://127.0.0.1:5000/generate"
            data = json.dumps({"prompt": prompt}, ensure_ascii=False).encode('utf-8')
            headers = {"Content-Type": "application/json"}

            # Make POST request
            request = urllib2.Request(url, data, headers)
            response = urllib2.urlopen(request)
            content = response.read().decode('utf-8')

            # Parse JSON response
            response_json = json.loads(content)
            response_text = response_json.get("response", "No response content")

            # Add AI response
            self.add_message_to_chat(response_text, is_user=False)
        except urllib2.URLError as e:
            error_message = "Network Error: {}".format(e.reason)
            self.add_message_to_chat(error_message, is_user=False)
        except json.JSONDecodeError:
            error_message = "Error decoding JSON response from server."
            self.add_message_to_chat(error_message, is_user=False)
        except Exception as e:
            error_message = "Unexpected error: {}".format(e)
            self.add_message_to_chat(error_message, is_user=False)

    def add_message_to_chat(self, message, is_user):
        try:
            message_area = JTextPane()
            message_area.setContentType("text/html")

            # Theme-based colors
            panel_background = self.panel.getBackground()
            text_color = "white" if panel_background == Color.DARK_GRAY else "black"
            background_color = "#e6e6e6" if not is_user else "#d86633"
            align = "right" if is_user else "left"

            # Wrap the message in a simple HTML structure
            html_message = """
            <div style="background: {}; padding: 5px; border-radius: 10px; text-align: {}; max-width: 300px; word-wrap: break-word;">
            <span style="color: {}; overflow-wrap: break-word; word-break: break-all;">{}</span>
            </div>
            """.format(background_color, align, text_color, message.replace("\n", "<br>"))

            message_area.setText(html_message)
            message_area.setEditable(False)
            message_area.setOpaque(False)
            message_area.setMaximumSize(Dimension(300, Integer.MAX_VALUE))  # Set max width for wrapping

            # Message panel for alignment
            message_panel = JPanel()
            message_panel.setLayout(BoxLayout(message_panel, BoxLayout.X_AXIS))
            message_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
            message_panel.setOpaque(False)

            if is_user:
                message_panel.add(Box.createHorizontalGlue())  # Push to the right
                message_panel.add(message_area)
            else:
                message_panel.add(message_area)
                message_panel.add(Box.createHorizontalGlue())  # Push to the left

            self.messages_panel.add(message_panel)
            self.messages_panel.revalidate()
            self.messages_panel.repaint()
            self.scroll_pane.revalidate()
            self.scroll_pane.repaint()

            # Scroll to the bottom
            SwingUtilities.invokeLater(lambda: self.scroll_pane.getVerticalScrollBar().setValue(self.scroll_pane.getVerticalScrollBar().getMaximum()))

        except Exception as e:
            print("Error adding message to chat: {}".format(e))

    def load_api_key(self):
        # API Key'i dosyadan oku
        if os.path.exists(self.api_key_file):
            with open(self.api_key_file, 'r') as f:
                api_key = f.read().strip()
                self.api_key_input.setText(api_key)

    def send_request_and_response(self, invocation=None):  # invocation parametresini ekleyin
        try:
            # Show message box with "Hello World"
            print("send_request_and_response called")  # Debugging line
            JOptionPane.showMessageDialog(None, "Hello World", "Message", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            print("Unexpected error in send_request_and_response: {}".format(e))
