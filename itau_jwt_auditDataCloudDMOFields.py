# -*- coding: utf-8 -*-
"""
Este script audita uma instância do Salesforce Data Cloud para identificar 
campos de DMOs (Data Model Objects) utilizados e não utilizados.

Versão: 14.8 - Documentação Final das Regras de Negócio

================================================================================
REGRAS DE NEGÓCIO PARA CLASSIFICAÇÃO DE CAMPOS
================================================================================

Este script gera dois relatórios para fornecer uma visão completa do uso dos 
campos de DMOs customizados. As regras abaixo definem como um campo é 
classificado em cada relatório.

--------------------------------------------------------------------------------
REGRAS PARA UM CAMPO SER CONSIDERADO "UTILIZADO"
--------------------------------------------------------------------------------
Um campo é listado no relatório 'audit_campos_dmo_utilizados.csv' se UMA OU MAIS 
das seguintes condições for verdadeira:

1.  É encontrado nos critérios de pelo menos um **Segmento**.
2.  É encontrado em qualquer parte da configuração de pelo menos uma **Ativação**.
3.  É encontrado em qualquer parte da definição de pelo menos um **Calculated Insight**.
4.  Seu DMO pai foi criado **nos últimos 90 dias** (regra de carência para novos 
    objetos que ainda não foram implementados em outras áreas).

--------------------------------------------------------------------------------
REGRAS PARA UM CAMPO SER CONSIDERADO "NÃO UTILIZADO"
--------------------------------------------------------------------------------
Um campo é listado no relatório 'audit_campos_dmo_nao_utilizados.csv' SOMENTE 
SE TODAS as seguintes condições forem verdadeiras:

1.  **NÃO é encontrado** em nenhum Segmento, Ativação ou Calculated Insight.
2.  Seu DMO pai foi criado **há mais de 90 dias**.
3.  O campo e seu DMO **não são** objetos de sistema do Salesforce (o script 
    ignora nomes com prefixos como 'ssot__', 'unified__' ou nomes específicos 
    como 'DataSource__c').

================================================================================
"""
import os
import time
import asyncio
import csv
import json
import html
import logging
import re
from collections import defaultdict
from urllib.parse import urljoin, urlencode
from datetime import datetime, timedelta, timezone

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

# --- Autenticação ---
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


# --- API Fetching ---
async def fetch_api_data(session, instance_url, relative_url, semaphore, key_name=None):
    async with semaphore:
        all_records = []
        current_url = urljoin(instance_url, relative_url)
        try:
            while current_url:
                kwargs = {'ssl': VERIFY_SSL}
                if USE_PROXY:
                    kwargs['proxy'] = PROXY_URL

                async with session.get(current_url, **kwargs) as response:
                    response.raise_for_status(); data = await response.json()
                    if key_name:
                        all_records.extend(data.get(key_name, []))
                        next_page_url = data.get('nextRecordsUrl') or data.get('nextPageUrl')

                        if next_page_url and not next_page_url.startswith('http'):
                            current_url = urljoin(instance_url, next_page_url)
                        else:
                            current_url = next_page_url
                    else: 
                        return data
            return all_records
        except aiohttp.ClientError:
            return [] if key_name else {}

# --- Helper Functions ---
def _find_and_track_dependencies(obj, usage_type, object_name, object_api_name, used_fields_details):
    # (código inalterado)

# --- Main Audit Logic ---
async def audit_dmo_fields():
    auth_data = get_access_token()
    access_token, instance_url = auth_data['access_token'], auth_data['instance_url']
    logging.info('🚀 Iniciando auditoria de campos de DMO...')
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    
    CONCURRENT_REQUESTS = 50
    semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS)

    async with aiohttp.ClientSession(headers=headers) as session:
        logging.info("--- Etapa 1: Coletando metadados e listas de objetos ---")

        dmo_soql_query = "SELECT DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject"
        segment_soql_query = "SELECT Id FROM MarketSegment"
        
        initial_tasks = [
            fetch_api_data(session, instance_url, f"/services/data/v64.0/tooling/query?{urlencode({'q': dmo_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, f"/services/data/v64.0/query?{urlencode({'q': segment_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=DataModelObject", semaphore, 'metadata'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=CalculatedInsight", semaphore, 'metadata'),
        ]
        results = await asyncio.gather(*initial_tasks)
        dmo_details_records, segment_id_records, dmo_metadata_list, calculated_insights = results
        
        dmo_details_map = {rec['DeveloperName']: {'CreatedDate': rec['CreatedDate'], 'CreatedById': rec['CreatedById']} for rec in dmo_details_records}
        
        user_ids_to_fetch = {rec['CreatedById'] for rec in dmo_details_records if rec.get('CreatedById')}
        user_map = {}
        if user_ids_to_fetch:
            id_list_str = "','".join(user_ids_to_fetch)
            user_soql_query = f"SELECT Id, Name FROM User WHERE Id IN ('{id_list_str}')"
            user_records = await fetch_api_data(session, instance_url, f"/services/data/v64.0/query?{urlencode({'q': user_soql_query})}", semaphore, 'records')
            user_map = {rec['Id']: rec['Name'] for rec in user_records}

        segment_ids = [rec['Id'] for rec in segment_id_records]
        logging.info(f"✅ Etapa 1.1: {len(dmo_details_map)} detalhes de DMOs obtidos.")
        logging.info(f"✅ Etapa 1.2: {len(segment_ids)} IDs de segmentos encontrados.")
        
        logging.info(f"\n--- Etapa 2: Buscando detalhes de {len(segment_ids)} segmentos ---")
        segment_detail_tasks = [fetch_api_data(session, instance_url, f"/services/data/v64.0/sobjects/MarketSegment/{seg_id}", semaphore) for seg_id in segment_ids]
        segments_list = await tqdm.gather(*segment_detail_tasks, desc="Buscando detalhes dos Segmentos")
        
        logging.info(f"\n--- Etapa 3: Analisando DMOs de Activation Audience ---")
        audience_dmos = [dmo for dmo in dmo_metadata_list if dmo.get('name', '').startswith(('AA_', 'AAL_'))]
        logging.info(f"🔎 {len(audience_dmos)} DMOs de Activation Audience identificados.")
        
        activation_ids_by_dmo = defaultdict(list)
        group_by_tasks = []
        for dmo in audience_dmos:
            dmo_name = dmo.get("name")
            if dmo_name:
                query = f"SELECT Activation_Id__c FROM {dmo_name} GROUP BY Activation_Id__c"
                url = f"/services/data/v64.0/query?{urlencode({'q': query})}"
                group_by_tasks.append(fetch_api_data(session, instance_url, url, semaphore, 'records'))

        results_by_dmo = await tqdm.gather(*group_by_tasks, desc="Buscando IDs de Ativação nos DMOs")
        
        for i, records in enumerate(results_by_dmo):
            if records:
                dmo_name = audience_dmos[i].get("name")
                for rec in records:
                    if act_id := rec.get('Activation_Id__c'):
                         activation_ids_by_dmo[dmo_name].append(act_id)

        sample_record_tasks = []
        for dmo_name, activation_ids in activation_ids_by_dmo.items():
            for act_id in set(activation_ids):
                query = f"SELECT Activation_Record__c FROM {dmo_name} WHERE Activation_Id__c = '{act_id}' LIMIT 1"
                url = f"/services/data/v64.0/query?{urlencode({'q': query})}"
                sample_record_tasks.append(fetch_api_data(session, instance_url, url, semaphore, 'records'))

        logging.info(f"🔎 Buscando amostras para {len(sample_record_tasks)} ativações únicas encontradas...")
        audience_records_samples = await tqdm.gather(*sample_record_tasks, desc="Obtendo amostras de ativações")

    # ... (O restante do script para análise e geração de relatórios permanece o mesmo) ...

if __name__ == "__main__":
    start_time = time.time()
    try:
        if os.name == 'nt':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(audit_dmo_fields())
    except Exception as e:
        logging.error(f"Um erro inesperado durante o processo de auditoria: {e}", exc_info=True)
    finally:
        end_time = time.time()
        duration = end_time - start_time
        logging.info(f"\nTempo total de execução: {duration:.2f} segundos")