# -*- coding: utf-8 -*-
import os
import time
import json
import logging

import jwt
import requests
from dotenv import load_dotenv
from urllib.parse import urljoin

# --- Configuração ---
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- DMO específico para o teste ---
DMO_TO_TEST = "ACESSO_ION__dlm"
OUTPUT_FILE = "api_test_result.txt"

# --- Configurações do Ambiente ---
SF_CLIENT_ID = os.getenv("SF_CLIENT_ID")
SF_USERNAME = os.getenv("SF_USERNAME")
SF_AUDIENCE = os.getenv("SF_AUDIENCE")
SF_LOGIN_URL = os.getenv("SF_LOGIN_URL")
USE_PROXY = os.getenv("USE_PROXY", "False").lower() == "true"
PROXY_URL = os.getenv("PROXY_URL")
VERIFY_SSL = os.getenv("VERIFY_SSL", "False").lower() == "true"
API_VERSION = "v60.0"

def get_access_token():
    """Função de autenticação copiada do script principal."""
    logging.info("🔑 Autenticando com o Salesforce via JWT...")
    if not all([SF_CLIENT_ID, SF_USERNAME, SF_AUDIENCE, SF_LOGIN_URL]):
        raise ValueError("Variáveis de ambiente de autenticação faltando no .env.")
    try:
        with open('private.pem', 'r') as f:
            private_key = f.read()
    except FileNotFoundError:
        logging.error("❌ Arquivo 'private.pem' não encontrado.")
        raise
        
    payload = {'iss': SF_CLIENT_ID, 'sub': SF_USERNAME, 'aud': SF_AUDIENCE, 'exp': int(time.time()) + 300}
    assertion = jwt.encode(payload, private_key, algorithm='RS256')
    params = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': assertion}
    token_url = urljoin(SF_LOGIN_URL, "/services/oauth2/token")
    
    proxies = {'http': PROXY_URL, 'https': PROXY_URL} if USE_PROXY and PROXY_URL else None
    
    try:
        res = requests.post(token_url, data=params, proxies=proxies, verify=VERIFY_SSL)
        res.raise_for_status()
        logging.info("✅ Autenticação bem-sucedida.")
        return res.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Erro na autenticação: {e.response.text if e.response else e}")
        raise

def main():
    """Função principal para executar o teste."""
    logging.info(f"🚀 Iniciando teste de API para o DMO: {DMO_TO_TEST}")
    
    try:
        auth_data = get_access_token()
        access_token = auth_data['access_token']
        instance_url = auth_data['instance_url']

        # Monta a URL do endpoint de mapeamentos
        endpoint_path = f"/services/data/{API_VERSION}/ssot/data-model-object-mappings"
        params = {"dataspace": "default", "dmoDeveloperName": DMO_TO_TEST}
        
        url = urljoin(instance_url, endpoint_path)

        # Prepara os headers (sem 'Content-Type' para requisições GET)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        proxies = {'http': PROXY_URL, 'https': PROXY_URL} if USE_PROXY and PROXY_URL else None
        
        logging.info(f"Realizando chamada GET para: {url}")
        logging.info(f"Parâmetros: {params}")
        logging.info(f"Usando proxy: {USE_PROXY}")
        
        # Realiza a chamada GET
        response = requests.get(url, headers=headers, params=params, proxies=proxies, verify=VERIFY_SSL)
        
        # Levanta um erro para status ruins (4xx ou 5xx)
        response.raise_for_status()
        
        payload = response.json()
        
        logging.info(f"✅ Sucesso! Resposta da API recebida com status {response.status_code}.")
        
        # Salva o payload formatado no arquivo de texto
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=4, ensure_ascii=False)
            
        logging.info(f"📄 Payload salvo com sucesso no arquivo: {OUTPUT_FILE}")

    except Exception as e:
        error_message = f"❌ Ocorreu um erro durante o teste: {e}"
        logging.error(error_message)
        # Tenta salvar o erro no arquivo de saída
        try:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(error_message)
                if hasattr(e, 'response') and e.response is not None:
                    f.write("\n\n--- Detalhes da Resposta ---\n")
                    f.write(f"Status Code: {e.response.status_code}\n")
                    f.write(f"Corpo: {e.response.text}\n")
        except Exception as write_e:
            logging.error(f"Não foi possível escrever o erro no arquivo de saída: {write_e}")

if __name__ == "__main__":
    main()