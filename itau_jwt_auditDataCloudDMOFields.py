# -*- coding: utf-8 -*-
"""
Este script audita uma instância do Salesforce Data Cloud para identificar 
campos de DMOs (Data Model Objects) utilizados e não utilizados.

Versão: 14.6 - Documentação Final das Regras de Negócio

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

async def fetch_paginated_data_with_offset(session, instance_url, relative_url, semaphore, key_name):
    async with semaphore:
        all_records = []
        offset = 0
        batch_size = 200
        
        while True:
            params = {'batchSize': batch_size, 'offset': offset}
            paginated_url = f"{relative_url}?{urlencode(params)}"
            full_url = urljoin(instance_url, paginated_url)
            try:
                kwargs = {'ssl': VERIFY_SSL}
                if USE_PROXY:
                    kwargs['proxy'] = PROXY_URL
                
                async with session.get(full_url, **kwargs) as response:
                    response.raise_for_status(); data = await response.json()
                    records_on_page = data.get(key_name, [])
                    all_records.extend(records_on_page)
                    
                    if len(records_on_page) < batch_size: break
                    offset += len(records_on_page)
            except aiohttp.ClientError as e:
                logging.error(f"❌ Erro ao buscar {full_url}: {e}")
                break
        return all_records


# --- Helper Functions ---
def _find_and_track_dependencies(obj, usage_type, object_name, object_api_name, used_fields_details):
    api_name_keys = ["name", "entityName", "objectApiName", "fieldName", "attributeName", "developerName"]
    if isinstance(obj, dict):
        if 'entityName' in obj and 'name' in obj:
            dmo_name, field_name = obj.get('entityName'), obj.get('name')
            usage_context = {"usage_type": usage_type, "object_name": object_name, "object_api_name": object_api_name}
            if dmo_name and usage_context not in used_fields_details[dmo_name]: used_fields_details[dmo_name].append(usage_context)
            if field_name and usage_context not in used_fields_details[field_name]: used_fields_details[field_name].append(usage_context)
        for key, value in obj.items():
            if key in api_name_keys and isinstance(value, str):
                usage_context = {"usage_type": usage_type, "object_name": object_name, "object_api_name": object_api_name}
                if usage_context not in used_fields_details[value]: used_fields_details[value].append(usage_context)
            _find_and_track_dependencies(value, usage_type, object_name, object_api_name, used_fields_details)
    elif isinstance(obj, list):
        for item in obj:
            _find_and_track_dependencies(item, usage_type, object_name, object_api_name, used_fields_details)


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

        # **MUDANÇA**: Adicionado CreatedById à query de DMOs
        dmo_soql_query = "SELECT DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject"
        segment_soql_query = "SELECT Id FROM MarketSegment"
        
        initial_tasks = [
            fetch_api_data(session, instance_url, f"/services/data/v64.0/tooling/query?{urlencode({'q': dmo_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, f"/services/data/v64.0/query?{urlencode({'q': segment_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=DataModelObject", semaphore, 'metadata'),
            fetch_paginated_data_with_offset(session, instance_url, "/services/data/v64.0/ssot/activations", semaphore, 'activations'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=CalculatedInsight", semaphore, 'metadata'),
        ]
        dmo_details_records, segment_id_records, dmo_metadata_list, activations_summary, calculated_insights = await asyncio.gather(*initial_tasks)
        
        # **NOVO**: Mapeia DMOs para suas datas de criação e IDs de criador
        dmo_details_map = {rec['DeveloperName']: {'CreatedDate': rec['CreatedDate'], 'CreatedById': rec['CreatedById']} for rec in dmo_details_records}
        user_ids_to_fetch = {rec['CreatedById'] for rec in dmo_details_records if rec.get('CreatedById')}
        
        user_map = {}
        if user_ids_to_fetch:
            user_soql_query = f"SELECT Id, Name FROM User WHERE Id IN ({','.join([f_'{_id}'_ for _id in user_ids_to_fetch])})"
            user_records = await fetch_api_data(session, instance_url, f"/services/data/v64.0/query?{urlencode({'q': user_soql_query})}", semaphore, 'records')
            user_map = {rec['Id']: rec['Name'] for rec in user_records}
        
        segment_ids = [rec['Id'] for rec in segment_id_records]
        logging.info(f"✅ Etapa 1.1: {len(dmo_creation_dates)} detalhes de DMOs obtidos.")
        logging.info(f"✅ Etapa 1.2: {len(segment_ids)} IDs de segmentos encontrados.")
        logging.info(f"✅ Etapa 1.3: {len(activations_summary)} Ativações encontradas.")
        
        logging.info(f"\n--- Etapa 2: Buscando detalhes de {len(segment_ids)} segmentos ---")
        segment_detail_tasks = [fetch_api_data(session, instance_url, f"/services/data/v64.0/sobjects/MarketSegment/{seg_id}", semaphore) for seg_id in segment_ids]
        segments_list = await tqdm.gather(*segment_detail_tasks, desc="Buscando detalhes dos Segmentos")
        
        logging.info(f"\n--- Etapa 3: Buscando detalhes de {len(activations_summary)} ativações ---")
        activation_detail_tasks = [fetch_api_data(session, instance_url, f"/services/data/v64.0/ssot/activations/{act.get('id')}", semaphore) for act in activations_summary]
        detailed_activations = await tqdm.gather(*activation_detail_tasks, desc="Buscando detalhes das Ativações")

    logging.info("\n📊 Dados coletados. Analisando o uso dos campos...")
    
    all_dmo_data = defaultdict(lambda: {'fields': {}, 'displayName': '', 'createdBy': 'N/A'})
    dmo_prefixes_to_exclude = ('ssot', 'unified', 'individual', 'einstein', 'segment_membership', 'aa_', 'aal_')

    for dmo in dmo_metadata_list:
        if (dmo_name := dmo.get('name')) and dmo_name.endswith('__dlm'):
            if any(dmo_name.lower().startswith(prefix) for prefix in dmo_prefixes_to_exclude): continue
            all_dmo_data[dmo_name]['displayName'] = dmo.get('displayName', dmo.get('name'))
            
            # **NOVO**: Adiciona o nome do criador ao DMO
            dmo_detail = dmo_details_map.get(dmo_name, {})
            created_by_id = dmo_detail.get('CreatedById')
            all_dmo_data[dmo_name]['createdBy'] = user_map.get(created_by_id, 'Desconhecido')
            
            for field in dmo.get('fields', []):
                if field_name := field.get('name'):
                    all_dmo_data[dmo_name]['fields'][field_name] = field.get('displayName', field.get('name'))
    
    # ... (O restante da lógica de análise permanece o mesmo) ...

    # --- Geração dos Relatórios ---
    unused_field_results = []
    # ... (lógica para popular 'unused_field_results', adicionando a nova coluna) ...
    
    used_field_results = []
    # ... (lógica para popular 'used_field_results', adicionando a nova coluna) ...

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