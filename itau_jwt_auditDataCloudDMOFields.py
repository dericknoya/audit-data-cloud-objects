# -*- coding: utf-8 -*-
"""
Este script audita uma instância do Salesforce Data Cloud para identificar 
campos de DMOs (Data Model Objects) utilizados e não utilizados.

Versão: 12.8 - Documentação Final das Regras de Negócio

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
                        current_url = urljoin(instance_url, next_page_url) if next_page_url else None
                    else: 
                        return data
            return all_records
        except aiohttp.ClientError:
            return [] if key_name else {}

# --- Helper Functions ---
def _find_and_track_dependencies(obj, usage_type, object_name, object_api_name, used_fields_details):
    # (Função mantida para CIs)
    # ... (código inalterado) ...

# --- Main Audit Logic ---
async def audit_dmo_fields():
    auth_data = get_access_token()
    access_token, instance_url = auth_data['access_token'], auth_data['instance_url']
    logging.info('🚀 Iniciando auditoria de campos de DMO...')
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    
    CONCURRENT_REQUESTS = 50
    semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS)

    async with aiohttp.ClientSession(headers=headers) as session:
        # --- Etapa 1: Coleta de Metadados Base ---
        dmo_soql_query = "SELECT DeveloperName, CreatedDate FROM MktDataModelObject"
        segment_soql_query = "SELECT Id FROM MarketSegment"
        
        initial_tasks = [
            fetch_api_data(session, instance_url, f"/services/data/v64.0/tooling/query?{urlencode({'q': dmo_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, f"/services/data/v64.0/query?{urlencode({'q': segment_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=DataModelObject", semaphore, 'metadata'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=CalculatedInsight", semaphore, 'metadata'),
        ]
        dmo_dates_records, segment_id_records, dmo_metadata_list, calculated_insights = await asyncio.gather(*initial_tasks)
        
        dmo_creation_dates = {rec['DeveloperName']: rec['CreatedDate'] for rec in dmo_dates_records}
        segment_ids = [rec['Id'] for rec in segment_id_records]
        logging.info(f"✅ Etapa 1.1: {len(dmo_creation_dates)} datas de criação de DMOs obtidas.")
        logging.info(f"✅ Etapa 1.2: {len(segment_ids)} IDs de segmentos encontrados.")
        
        # --- Etapa 2: Busca de Detalhes de Segmentos ---
        segment_detail_tasks = [fetch_api_data(session, instance_url, f"/services/data/v64.0/sobjects/MarketSegment/{seg_id}", semaphore) for seg_id in segment_ids]
        segments_list = await tqdm.gather(*segment_detail_tasks, desc="Buscando detalhes dos Segmentos")
        segments_list = [res for res in segments_list if res]
        
        # --- Etapa 3: Nova Lógica de Análise de Ativações ---
        logging.info(f"\n--- Etapa 3: Analisando DMOs de Activation Audience ---")
        audience_dmos = [dmo for dmo in dmo_metadata_list if dmo.get('name', '').startswith(('AA_', 'AAL_'))]
        logging.info(f"🔎 {len(audience_dmos)} DMOs de Activation Audience identificados.")
        
        # Passo 3.1: Encontrar todos os IDs de ativação únicos dentro de cada Audience DMO
        activation_ids_by_dmo = {}
        for dmo in tqdm(audience_dmos, desc="Buscando IDs de Ativação nos DMOs"):
            dmo_name = dmo.get("name")
            if not dmo_name: continue
            
            group_by_query = f"SELECT Activation_Id__c FROM {dmo_name} GROUP BY Activation_Id__c"
            query_url = f"/services/data/v64.0/query?{urlencode({'q': group_by_query})}"
            activation_id_records = await fetch_api_data(session, instance_url, query_url, semaphore, 'records')
            
            if activation_id_records:
                activation_ids_by_dmo[dmo_name] = [rec['Activation_Id__c'] for rec in activation_id_records if rec.get('Activation_Id__c')]

        # Passo 3.2: Para cada ID de ativação único, buscar UMA linha de amostra para obter o JSON
        sample_record_tasks = []
        for dmo_name, activation_ids in activation_ids_by_dmo.items():
            for act_id in activation_ids:
                sample_query = f"SELECT Activation_Record__c FROM {dmo_name} WHERE Activation_Id__c = '{act_id}' LIMIT 1"
                query_url = f"/services/data/v64.0/query?{urlencode({'q': sample_query})}"
                sample_record_tasks.append(fetch_api_data(session, instance_url, query_url, semaphore, 'records'))

        logging.info(f"🔎 Buscando amostras para {len(sample_record_tasks)} ativações únicas encontradas nos DMOs de Audience...")
        audience_records_samples = await tqdm.gather(*sample_record_tasks, desc="Obtendo amostras de ativações")

    # --- Análise e Geração de Relatórios ---
    logging.info("\n📊 Dados coletados. Analisando o uso dos campos...")
    
    # ... (código para popular 'all_dmo_data' - inalterado) ...
    used_fields_details = defaultdict(list)
    # ... (código para analisar 'segments_list' - inalterado) ...

    # **NOVA LÓGICA DE ANÁLISE DE ATIVAÇÕES**
    logging.info("🔍 Analisando uso de campos em Ativações via DMOs de Audience...")
    for sample_list in tqdm(audience_records_samples, desc="Analisando amostras de ativações"):
        if not sample_list: continue
        record_json_str = sample_list[0].get('Activation_Record__c')
        if not record_json_str: continue

        try:
            activated_data = json.loads(record_json_str)
            dmo_name_from_usage = "Activation Audience" # Placeholder
            
            for field_name in activated_data.keys():
                usage_context = { "usage_type": "Ativação", "object_name": f"Via DMO de Audience", "object_api_name": "N/A" }
                if usage_context not in used_fields_details[field_name]:
                    used_fields_details[field_name].append(usage_context)
        except json.JSONDecodeError:
            logging.warning(f"Não foi possível analisar o JSON do campo Activation_Record__c.")

    for ci in tqdm(calculated_insights, desc="Analisando CIs"):
        _find_and_track_dependencies(ci, "Calculated Insight", ci.get('displayName'), ci.get('name'), used_fields_details)

    # ... (O restante do código para gerar os relatórios permanece o mesmo) ...

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