# -*- coding: utf-8 -*-
# Author: ALPEREN ERGEL (@alpernae)
# v0.7 (UI Fix)

from javax.swing import JPanel, JScrollPane, JButton, JMenu, JMenuBar, JMenuItem, BoxLayout, JTextField, JLabel, JTextPane
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
        self.api_key_file = os.path.expanduser("~/.api_key")
        self.server_running = False
        self.server_process = None

        print("Author: ALPEREN ERGEL (@alpernae)")

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AI Assistant")

        # Paneli oluştur
        self.panel = JPanel(BorderLayout())
        self.panel.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20))

        # Menü oluştur
        self.create_menu()

        # Sunucu scriptini başlat
        self.start_server()

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

        # Bileşenleri top_panel'e ekle
        top_panel.add(api_key_panel)
        top_panel.add(add_key_button)

        # Orta kısım: Mesajları gösterme
        self.messages_panel = JPanel()
        self.messages_panel.setLayout(BoxLayout(self.messages_panel, BoxLayout.Y_AXIS))
        self.messages_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))

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

        # Prompt Input
        self.prompt_input = JTextField("", 20)
        self.prompt_input.setPreferredSize(Dimension(130, 30))
        prompt_input_panel.add(self.prompt_input)

        # Send Prompt Button
        send_prompt_button = JButton("Send Prompt", actionPerformed=self.send_prompt)
        send_prompt_button.setPreferredSize(Dimension(130, 30))
        send_prompt_button.setBackground(Color.decode("#d86633"))
        send_prompt_button.setForeground(Color.WHITE)
        send_prompt_button.setOpaque(True)
        send_prompt_button.setBorderPainted(False)

        # Bileşenleri bottom_panel'e ekle
        bottom_panel.add(prompt_input_panel)
        bottom_panel.add(send_prompt_button)

        # Panelleri ana panele ekle
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
        send_menu = JMenu("Send Requests")
        menu_bar.add(send_menu)

        # İstek ve Yanıtları Gönder menü öğesi
        send_request_item = JMenuItem("Send Request & Response to AI")
        send_request_item.addActionListener(self.send_request_and_response)
        send_menu.add(send_request_item)

        # Menü çubuğunu paneldeki bir bileşene ekle (örneğin: üst panel)
        self.panel.add(menu_bar, BorderLayout.NORTH)

    def createMenuItems(self, invocation):
        # Sağ tıklama menüsü öğelerini oluşturur
        menu = []
        send_request_item = JMenuItem("Send Request & Response to AI")
        send_request_item.addActionListener(
            lambda event: self.send_request_and_response(invocation))  # Pass invocation correctly
        menu.append(send_request_item)
        return menu


    def getTabCaption(self):
        # Sekme ismi
        return "AI Assistant"

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
            # Temaya göre renk ayarları
            panel_background = self.panel.getBackground()

            if panel_background == Color.DARK_GRAY:  # Koyu tema için renk ayarları
                user_background_color = "#3c3d3e"
                ai_background_color = "#3c3d3e"
                text_color = "white"
            else:  # Açık tema için renk ayarları
                user_background_color = "#e6e6e6"
                ai_background_color = "#e6e6e6"
                text_color = "#000000"  # Siyah renk

            # Her iki durumda da satır sonlarını ekle
            message = message.replace("\n", "<br>")

            # HTML formatında mesaj (border-radius eklendi)
            if is_user:  # Kullanıcı mesajı için stil
                html_message = """
                <div style='padding: 5px 5px; background: {}; border-radius: 35px;'>  
                <span style='color: {}; white-space: pre-wrap; overflow-wrap: break-word; display: inline-block;'>{}</span>
                </div>""".format(user_background_color, text_color, message)
                message_area.setFont(Font("Monospaced", Font.PLAIN, 12))  # Kullanıcı mesajı için font boyutu
            else:  # AI mesajı için stil
                html_message = """
                <div style='padding: 5px 5px; background: {}; border-radius: 10px;'>  
                <span style='color: {}; white-space: pre-wrap; overflow-wrap: break-word; display: inline-block;'>{}</span>
                </div>""".format(ai_background_color, text_color, message)
                message_area.setFont(Font("Monospaced", Font.PLAIN, 12))  # AI mesajı için font boyutu

            message_area.setText(html_message)
            message_area.setEditable(False)
            message_area.setOpaque(False)
            message_area.setMaximumSize(Dimension(self.scroll_pane.getWidth() - 0, Integer.MAX_VALUE)) 

            # Mesaj panelini oluştur ve ekle (FlowLayout kullanarak)
            message_panel = JPanel(FlowLayout(FlowLayout.RIGHT if is_user else FlowLayout.LEFT))
            message_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))  # Varsayılan border
            message_panel.setOpaque(False)
            message_panel.add(message_area)

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

    def start_server(self):
        # Sunucu başlatma işlemi
        if not self.server_running:
            try:
                # Sunucu scriptini başlat
                self.server_process = subprocess.Popen(["python", "server.py"],
                                                      stdout=subprocess.PIPE,
                                                      stderr=subprocess.PIPE)
                self.server_running = True
            except Exception as e:
                print("Failed to start server: {}".format(e))

    def send_request_and_response(self, invocation):
        try:
            # Show message box with "Hello World"
            print("send_request_and_response called")  # Debugging line
            JOptionPane.showMessageDialog(None, "Hello World", "Message", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            print("Unexpected error in send_request_and_response: {}".format(e))
