# -*- coding: utf-8 -*-
"""
Script de diagnóstico para isolar e paginar a busca de dados em DMOs de Activation Audience.

Versão: 1.1 - Adicionada Paginação Completa
"""
import os
import time
import asyncio
import csv
import json
import html
import logging
from urllib.parse import urljoin, urlencode

import jwt
import requests
import aiohttp
from dotenv import load_dotenv
from tqdm.asyncio import tqdm

# --- Configuração de Rede ---
USE_PROXY = True
PROXY_URL = "http://usuario:senha@proxy.suaempresa.com:porta" # Substitua pelo seu proxy
VERIFY_SSL = False

# --- Configuração do Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Funções de Autenticação e Busca (copiadas do script principal) ---

def get_access_token():
    logging.info("🔑 Autenticando com o Salesforce via JWT (certificado)...")
    load_dotenv()
    
    sf_client_id = os.getenv("SF_CLIENT_ID")
    sf_username = os.getenv("SF_USERNAME")
    sf_audience = os.getenv("SF_AUDIENCE")
    sf_login_url = os.getenv("SF_LOGIN_URL")

    if not all([sf_client_id, sf_username, sf_audience, sf_login_url]):
        raise ValueError("Uma ou mais variáveis de ambiente para o fluxo JWT estão faltando.")
    
    try:
        with open('private.pem', 'r') as f: 
            private_key = f.read()
    except FileNotFoundError:
        logging.error("❌ Erro: Arquivo 'private.pem' não encontrado."); raise
        
    payload = {'iss': sf_client_id, 'sub': sf_username, 'aud': sf_audience, 'exp': int(time.time()) + 300}
    assertion = jwt.encode(payload, private_key, algorithm='RS256')
    params = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': assertion}
    token_url = f"{sf_login_url}/services/oauth2/token"
    
    try:
        proxies = {'http': PROXY_URL, 'https': PROXY_URL} if USE_PROXY else None
        res = requests.post(token_url, data=params, proxies=proxies, verify=VERIFY_SSL)
        res.raise_for_status()
        logging.info("✅ Autenticação bem-sucedida.")
        return res.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Erro na autenticação com Salesforce: {e.response.text if e.response else e}"); raise


async def fetch_api_data(session, instance_url, relative_url, key_name=None):
    all_records = []
    current_url = urljoin(instance_url, relative_url)
    logging.info(f"  -> Iniciando busca em: {relative_url}")
    try:
        page_count = 1
        while current_url:
            kwargs = {'ssl': VERIFY_SSL}
            if USE_PROXY:
                kwargs['proxy'] = PROXY_URL

            async with session.get(current_url, **kwargs) as response:
                response.raise_for_status(); data = await response.json()
                
                records_on_page = data.get(key_name, [])
                all_records.extend(records_on_page)
                logging.info(f"  -> Página {page_count}: {len(records_on_page)} registros recebidos.")

                next_page_url = data.get('nextRecordsUrl')

                if next_page_url and not next_page_url.startswith('http'):
                    current_url = urljoin(instance_url, next_page_url)
                else:
                    current_url = next_page_url # Será None se for a última página
                
                page_count += 1
        return all_records
    except aiohttp.ClientError as e:
        logging.error(f"  -> ❌ Erro ao buscar dados: {e}")
        return []

# --- Lógica Principal de Diagnóstico ---

async def debug_audience_dmo_query():
    auth_data = get_access_token()
    if not auth_data:
        return

    access_token, instance_url = auth_data['access_token'], auth_data['instance_url']
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}

    target_dmos = [
        "AA_SFMC_85U5e000000fxbrEAA__dlm",
        "AA_SFMC_85U5e000000fxcLEAQ__dlm"
    ]
    logging.info(f"Iniciando script de diagnóstico para {len(target_dmos)} DMOs.")

    all_results_for_csv = []

    async with aiohttp.ClientSession(headers=headers) as session:
        for dmo_name in target_dmos:
            logging.info(f"--- Processando DMO: {dmo_name} ---")
            
            query = f"SELECT Activation_Id__c, Activation_Record__c FROM {dmo_name}"
            logging.info(f"  -> Montando query: {query}")
            
            url = f"/services/data/v64.0/query?{urlencode({'q': query})}"
            
            records = await fetch_api_data(session, instance_url, url, 'records')
            
            logging.info(f"  -> Query para {dmo_name} retornou um total de {len(records)} registro(s) após paginação.")

            if records:
                for rec in records:
                    all_results_for_csv.append({
                        'DMO_API_NAME': dmo_name,
                        'Activation_Id__c': rec.get('Activation_Id__c', 'N/A'),
                        'Activation_Record__c': rec.get('Activation_Record__c', 'N/A')
                    })
    
    logging.info("\n--- Finalizando Coleta ---")
    logging.info(f"Total de registros coletados para o CSV: {len(all_results_for_csv)}")

    if not all_results_for_csv:
        logging.warning("Nenhum registro foi retornado.")

    # Gerar CSV com os resultados
    csv_file_path = 'debug_audience_dmo_output.csv'
    header = ['DMO_API_NAME', 'Activation_Id__c', 'Activation_Record__c']
    try:
        with open(csv_file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()
            writer.writerows(all_results_for_csv)
        logging.info(f"✅ Arquivo de diagnóstico gerado com sucesso: {csv_file_path}")
    except IOError as e:
        logging.error(f"❌ Erro ao gravar o arquivo CSV de diagnóstico: {e}")

if __name__ == "__main__":
    start_time = time.time()
    try:
        if os.name == 'nt':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(debug_audience_dmo_query())
    except Exception as e:
        logging.error(f"Um erro inesperado durante o processo de diagnóstico: {e}", exc_info=True)
    finally:
        end_time = time.time()
        duration = end_time - start_time
        logging.info(f"\nTempo total de execução: {duration:.2f} segundos")