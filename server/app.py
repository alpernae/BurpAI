from flask import Flask, request, jsonify
import os
import google.generativeai as genai
import markdown2
import time
import requests

app = Flask(__name__)

# API anahtarını dosyadan oku
def read_api_key():
    api_key_path = os.path.expanduser("~/.api_key")
    with open(api_key_path, 'r', encoding='utf-8') as file:  # UTF-8 olarak oku
        return file.read().strip()

# Gemini API'yi yapılandır
api_key = read_api_key()
genai.configure(api_key=api_key)

# Model yapılandırması
generation_config = {
    "temperature": 0.2,
    "top_p": 0.1,
    "top_k": 5,
    "max_output_tokens": 10720,
}

safety_settings = [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUAL", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_DANGEROUS", "threshold": "BLOCK_NONE"}
]

model = genai.GenerativeModel(
    model_name="gemini-1.5-flash-8b-exp-0827", # possible vuln to prompt inj
    generation_config=generation_config,
    safety_settings=safety_settings
)

# Başlangıçta AI'a verilecek ilk talimatlar
initial_instructions = [
    """
    I am conducting a bug bounty hunt and pentesting on a Application. Your task is to assist me with everything related to this process, including but not limited to identifying vulnerabilities, 
    suggesting payloads, automating scans, and providing recommendations for exploiting potential weaknesses. 
    Start by identifying common vulnerabilities like XSS, SQL injection, Command Injection, RCE, CSRF, and IDOR. For each vulnerability, 
    generate potential payloads, identify attack vectors, and suggest tools or scripts that can be used to automate testing. Additionally, 
    if there are any novel techniques or recent security trends that could be relevant, integrate those into your analysis. Present your findings and recommendations in a concise, 
    actionable format without needing further input from me and present answers will be like this: 
    "🔓 BurpAI: 
    [RESPONSE]" 
    """
]

# Sohbet geçmişini saklamak için bir liste
chat_history = [{'role': 'user', 'parts': [instruction]} for instruction in initial_instructions]

@app.route('/')
def home():
    return "Gemini AI REST API"

@app.route('/ping')
def ping():
    return "Pong"

@app.route('/generate', methods=['POST'])
def generate():
    data = request.get_json()
    prompt = data.get('prompt')

    if not prompt:
        return jsonify({'error': 'No prompt provided'}), 400

    # Chat oturumu başlat
    chat_session = model.start_chat(history=chat_history)

    try:
        # Mesaj gönder
        response = chat_session.send_message(prompt)

        # Yanıtı geçmişe ekle
        chat_history.append({
            "role": "model",
            "parts": [response.text],
        })

        # \n karakterlerini <br> ile değiştirin, sonra Markdown'ı HTML'e dönüştürün
        html_response = markdown2.markdown(response.text.replace('\n', '<br>'))

        # Yanıtı JSON formatında UTF-8 olarak döndür
        return jsonify({
            'response': html_response
        }), 200, {'Content-Type': 'application/json; charset=utf-8'}

    except requests.exceptions.HTTPError as e:  # requests.exceptions.HTTPError kullan
        if e.response.status_code == 429:  # 429 hatasını kontrol et
            return jsonify({'error': 'Quota exceeded, please wait and try again later'}), 429
        else:
            return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        time.sleep(2)

if __name__ == '__main__':
    app.run()