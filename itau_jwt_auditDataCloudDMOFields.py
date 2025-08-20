# -*- coding: utf-8 -*-
"""
Este script audita uma instância do Salesforce Data Cloud para identificar 
campos de DMOs (Data Model Objects) utilizados e não utilizados.

Versão: 15.3 - Documentação Final das Regras de Negócio

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
    api_name_keys = ["name", "entityName", "objectApiName", "fieldName", "attributeName", "developerName"]
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in api_name_keys and isinstance(value, str):
                usage_context = {"usage_type": usage_type, "object_name": object_name, "object_api_name": object_api_name}
                if usage_context not in used_fields_details[value]:
                    used_fields_details[value].append(usage_context)
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

        dmo_soql_query = "SELECT DeveloperName, CreatedDate FROM MktDataModelObject"
        segment_soql_query = "SELECT Id FROM MarketSegment"
        activation_attributes_query = "SELECT Id, QueryPath, Name, MarketSegmentActivationId FROM MktSgmntActvtnAudAttribute"
        
        initial_tasks = [
            fetch_api_data(session, instance_url, f"/services/data/v60.0/tooling/query?{urlencode({'q': dmo_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, f"/services/data/v60.0/query?{urlencode({'q': segment_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, "/services/data/v60.0/ssot/metadata?entityType=DataModelObject", semaphore, 'metadata'),
            fetch_api_data(session, instance_url, f"/services/data/v60.0/query?{urlencode({'q': activation_attributes_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, "/services/data/v60.0/ssot/metadata?entityType=CalculatedInsight", semaphore, 'metadata'),
        ]
        results = await tqdm.gather(*initial_tasks, desc="Coletando metadados iniciais")
        dmo_details_records, segment_id_records, dmo_metadata_list, activation_attributes, calculated_insights = results
        
        dmo_creation_dates = {rec['DeveloperName']: rec['CreatedDate'] for rec in dmo_details_records}
        segment_ids = [rec['Id'] for rec in segment_id_records]
        logging.info(f"✅ Etapa 1.1: {len(dmo_creation_dates)} datas de criação de DMOs obtidas.")
        logging.info(f"✅ Etapa 1.2: {len(segment_ids)} IDs de segmentos encontrados.")
        logging.info(f"✅ Etapa 1.3: {len(activation_attributes)} atributos de ativação encontrados via SOQL.")
        
        logging.info(f"\n--- Etapa 2: Buscando detalhes de {len(segment_ids)} segmentos ---")
        segment_detail_tasks = [fetch_api_data(session, instance_url, f"/services/data/v60.0/sobjects/MarketSegment/{seg_id}", semaphore) for seg_id in segment_ids]
        segments_list = await tqdm.gather(*segment_detail_tasks, desc="Buscando detalhes dos Segmentos")
        
    logging.info("\n📊 Dados coletados. Analisando o uso dos campos...")
    
    all_dmo_data = defaultdict(lambda: {'fields': {}, 'displayName': ''})
    dmo_prefixes_to_exclude = ('ssot', 'unified', 'individual', 'einstein', 'segment_membership', 'aa_', 'aal_')

    for dmo in dmo_metadata_list:
        if (dmo_name := dmo.get('name')) and dmo_name.endswith('__dlm'):
            if any(dmo_name.lower().startswith(prefix) for prefix in dmo_prefixes_to_exclude): continue
            all_dmo_data[dmo_name]['displayName'] = dmo.get('displayName', dmo.get('name'))
            for field in dmo.get('fields', []):
                if field_name := field.get('name'):
                    all_dmo_data[dmo_name]['fields'][field_name] = field.get('displayName', field.get('name'))
    
    used_fields_details = defaultdict(list)
    all_field_names_set = {field_name for dmo in all_dmo_data.values() for field_name in dmo['fields']}
    field_name_pattern = re.compile(r'"(?:fieldApiName|fieldName)":"([^"]+)"')
    
    for seg in tqdm(segments_list, desc="Analisando Segmentos"):
        seg_criteria_text = str(seg.get('IncludeCriteria', '')) + str(seg.get('ExcludeCriteria', ''))
        found_fields = set(field_name_pattern.findall(html.unescape(seg_criteria_text)))
        for field_name in found_fields:
            if field_name in all_field_names_set:
                usage_context = { "usage_type": "Segmento", "object_name": seg.get('Name'), "object_api_name": seg.get('Id') }
                if usage_context not in used_fields_details[field_name]:
                    used_fields_details[field_name].append(usage_context)

    for attr in tqdm(activation_attributes, desc="Analisando Atributos de Ativação"):
        if query_path_str := attr.get('QueryPath'):
            try:
                query_path_json = json.loads(query_path_str)
                _find_and_track_dependencies(query_path_json, "Ativação", attr.get('Name'), attr.get('MarketSegmentActivationId'), used_fields_details)
            except (json.JSONDecodeError, TypeError):
                found_fields = set(field_name_pattern.findall(html.unescape(str(query_path_str))))
                for field_name in found_fields:
                     if field_name in all_field_names_set:
                        usage_context = { "usage_type": "Ativação", "object_name": attr.get('Name'), "object_api_name": attr.get('MarketSegmentActivationId')}
                        if usage_context not in used_fields_details[field_name]:
                            used_fields_details[field_name].append(usage_context)

    for ci in tqdm(calculated_insights, desc="Analisando CIs"):
        _find_and_track_dependencies(ci, "Calculated Insight", ci.get('displayName'), ci.get('name'), used_fields_details)

    unused_field_results = []
    ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
    
    field_prefixes_to_exclude = ('ssot__', 'KQ_')
    specific_fields_to_exclude = {'DataSource__c', 'DataSourceObject__c', 'InternalOrganization__c'}

    for dmo_name, data in all_dmo_data.items():
        if dmo_name in used_fields_details: continue
        is_new_dmo = False
        if created_date_str := dmo_creation_dates.get(dmo_name):
            try:
                dmo_created_date = datetime.fromisoformat(created_date_str.replace('Z', '+00:00'))
                if dmo_created_date > ninety_days_ago: is_new_dmo = True
            except (ValueError, TypeError):
                logging.warning(f"Não foi possível parsear a data para {dmo_name}: {created_date_str}")

        for field_api_name, field_display_name in data['fields'].items():
            if field_api_name not in used_fields_details:
                if is_new_dmo:
                    usage_context = { "usage_type": "N/A (Recém-criado)", "object_name": "DMO criado nos últimos 90 dias", "object_api_name": "N/A" }
                    used_fields_details[field_api_name].append(usage_context)
                else:
                    if not any(field_api_name.startswith(p) for p in field_prefixes_to_exclude) and \
                       field_api_name not in specific_fields_to_exclude:
                        unused_field_results.append({
                            'DELETAR': 'NAO', 'DMO_DISPLAY_NAME': data['displayName'], 'DMO_API_NAME': dmo_name,
                            'FIELD_DISPLAY_NAME': field_display_name, 'FIELD_API_NAME': field_api_name, 
                            'REASON': 'Não utilizado em Segmentos, Ativações ou CIs'
                        })
    
    logging.info(f"📊 Total de {len(used_fields_details)} campos e objetos únicos em uso.")
    
    if not unused_field_results:
        logging.info("\n🎉 Nenhum campo órfão (com mais de 90 dias) foi encontrado!")
    else:
        csv_file_path_unused = 'audit_campos_dmo_nao_utilizados.csv'
        header_unused = ['DELETAR', 'DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'REASON']
        try:
            with open(csv_file_path_unused, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=header_unused)
                writer.writeheader()
                writer.writerows(unused_field_results)
            logging.info(f"✅ Relatório de campos NÃO utilizados gerado: {csv_file_path_unused} ({len(unused_field_results)} campos)")
        except IOError as e:
            logging.error(f"❌ Erro ao gravar o arquivo CSV de não utilizados: {e}")

    used_field_results = []
    field_to_dmo_map = {}
    for dmo_name, data in all_dmo_data.items():
        for field_api_name, field_display_name in data['fields'].items():
            field_to_dmo_map[field_api_name] = {
                'DMO_API_NAME': dmo_name, 'DMO_DISPLAY_NAME': data['displayName'], 
                'FIELD_DISPLAY_NAME': field_display_name
            }

    for field_api_name, usages in used_fields_details.items():
        if not any(field_api_name.startswith(p) for p in field_prefixes_to_exclude) and \
           field_api_name not in specific_fields_to_exclude:
            dmo_info = field_to_dmo_map.get(field_api_name)
            if dmo_info:
                for usage in usages:
                    used_field_results.append({
                        'DMO_DISPLAY_NAME': dmo_info['DMO_DISPLAY_NAME'], 'DMO_API_NAME': dmo_info['DMO_API_NAME'],
                        'FIELD_DISPLAY_NAME': dmo_info['FIELD_DISPLAY_NAME'], 'FIELD_API_NAME': field_api_name,
                        'USAGE_TYPE': usage['usage_type'], 'USED_IN_OBJECT_NAME': usage['object_name'],
                        'USED_IN_OBJECT_API_NAME': usage['object_api_name']
                    })

    if not used_field_results:
        logging.info("ℹ️ Nenhum uso de campo de DMO customizado foi detectado.")
    else:
        csv_file_path_used = 'audit_campos_dmo_utilizados.csv'
        header_used = ['DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'USAGE_TYPE', 'USED_IN_OBJECT_NAME', 'USED_IN_OBJECT_API_NAME']
        try:
            with open(csv_file_path_used, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=header_used)
                writer.writeheader()
                writer.writerows(used_field_results)
            logging.info(f"✅ Relatório de campos UTILIZADOS gerado: {csv_file_path_used} ({len(used_field_results)} usos)")
        except IOError as e:
            logging.error(f"❌ Erro ao gravar o arquivo CSV de utilizados: {e}")


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