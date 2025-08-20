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

        dmo_soql_query = "SELECT DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject"
        segment_soql_query = "SELECT Id FROM MarketSegment"
        
        initial_tasks = [
            fetch_api_data(session, instance_url, f"/services/data/v64.0/tooling/query?{urlencode({'q': dmo_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, f"/services/data/v64.0/query?{urlencode({'q': segment_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=DataModelObject", semaphore, 'metadata'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=CalculatedInsight", semaphore, 'metadata'),
        ]
        results = await tqdm.gather(*initial_tasks, desc="Coletando metadados iniciais")
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
        audience_dmo_names = [rec['DeveloperName'] for rec in dmo_details_records if rec.get('DeveloperName', '').startswith(('AA_', 'AAL_'))]
        logging.info(f"🔎 {len(audience_dmo_names)} DMOs de Activation Audience identificados.")
        
        sample_tasks = []
        for dmo_name in audience_dmo_names:
            query = f"SELECT Activation_Id__c, Activation_Record__c FROM {dmo_name} LIMIT 200"
            url = f"/services/data/v64.0/query?{urlencode({'q': query})}"
            sample_tasks.append(fetch_api_data(session, instance_url, url, semaphore, 'records'))

        logging.info(f"🔎 Coletando amostras de registros dos {len(audience_dmo_names)} DMOs de Audience...")
        audience_samples_results = await tqdm.gather(*sample_tasks, desc="Coletando amostras de ativações")

    logging.info("\n📊 Dados coletados. Analisando o uso dos campos...")
    
    all_dmo_data = defaultdict(lambda: {'fields': {}, 'displayName': '', 'createdBy': 'N/A'})
    dmo_prefixes_to_exclude = ('ssot', 'unified', 'individual', 'einstein', 'segment_membership')

    for dmo in dmo_metadata_list:
        if (dmo_name := dmo.get('name')) and dmo_name.endswith('__dlm'):
            if any(dmo_name.lower().startswith(prefix) for prefix in dmo_prefixes_to_exclude): continue
            all_dmo_data[dmo_name]['displayName'] = dmo.get('displayName', dmo.get('name'))
            dmo_detail = dmo_details_map.get(dmo_name, {})
            created_by_id = dmo_detail.get('CreatedById')
            all_dmo_data[dmo_name]['createdBy'] = user_map.get(created_by_id, 'Desconhecido')
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
    
    unique_activation_samples = {}
    for sample_list in audience_samples_results:
        for record in sample_list:
            act_id = record.get('Activation_Id__c')
            if act_id and act_id not in unique_activation_samples:
                unique_activation_samples[act_id] = record.get('Activation_Record__c')
    
    logging.info(f"🔎 {len(unique_activation_samples)} ativações únicas encontradas para análise.")
    for record_json_str in tqdm(unique_activation_samples.values(), desc="Analisando amostras de ativações"):
        if not record_json_str: continue
        try:
            activated_data = json.loads(record_json_str)
            for field_name in activated_data.keys():
                if field_name in all_field_names_set or field_name.endswith('__c'):
                    usage_context = { "usage_type": "Ativação", "object_name": "N/A (via DMO de Audience)", "object_api_name": "N/A" }
                    if usage_context not in used_fields_details[field_name]:
                        used_fields_details[field_name].append(usage_context)
        except json.JSONDecodeError:
            logging.warning(f"Não foi possível analisar o JSON do campo Activation_Record__c.")

    for ci in tqdm(calculated_insights, desc="Analisando CIs"):
        _find_and_track_dependencies(ci, "Calculated Insight", ci.get('displayName'), ci.get('name'), used_fields_details)

    unused_field_results = []
    ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
    
    field_prefixes_to_exclude = ('ssot__', 'KQ_')
    specific_fields_to_exclude = {'DataSource__c', 'DataSourceObject__c', 'InternalOrganization__c'}

    for dmo_name, data in all_dmo_data.items():
        if dmo_name in used_fields_details: continue
        is_new_dmo = False
        if created_date_str := dmo_details_map.get(dmo_name, {}).get('CreatedDate'):
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
                            'DELETAR': 'NAO', 'DMO_DISPLAY_NAME': data['displayName'], 
                            'DMO_API_NAME': dmo_name, 'DMO_CREATED_BY': data['createdBy'],
                            'FIELD_DISPLAY_NAME': field_display_name, 'FIELD_API_NAME': field_api_name, 
                            'REASON': 'Não utilizado em Segmentos, Ativações ou CIs'
                        })
    
    logging.info(f"📊 Total de {len(used_fields_details)} campos e objetos únicos em uso.")
    
    if not unused_field_results:
        logging.info("\n🎉 Nenhum campo órfão (com mais de 90 dias) foi encontrado!")
    else:
        csv_file_path_unused = 'audit_campos_dmo_nao_utilizados.csv'
        header_unused = ['DELETAR', 'DMO_DISPLAY_NAME', 'DMO_API_NAME', 'DMO_CREATED_BY', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'REASON']
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
                'FIELD_DISPLAY_NAME': field_display_name, 'DMO_CREATED_BY': data['createdBy']
            }

    for field_api_name, usages in used_fields_details.items():
        if not any(field_api_name.startswith(p) for p in field_prefixes_to_exclude) and \
           field_api_name not in specific_fields_to_exclude:
            dmo_info = field_to_dmo_map.get(field_api_name)
            if dmo_info:
                for usage in usages:
                    used_field_results.append({
                        'DMO_DISPLAY_NAME': dmo_info['DMO_DISPLAY_NAME'], 'DMO_API_NAME': dmo_info['DMO_API_NAME'],
                        'DMO_CREATED_BY': dmo_info['DMO_CREATED_BY'], 'FIELD_DISPLAY_NAME': dmo_info['FIELD_DISPLAY_NAME'], 
                        'FIELD_API_NAME': field_api_name, 'USAGE_TYPE': usage['usage_type'], 
                        'USED_IN_OBJECT_NAME': usage['object_name'], 'USED_IN_OBJECT_API_NAME': usage['object_api_name']
                    })

    if not used_field_results:
        logging.info("ℹ️ Nenhum uso de campo de DMO customizado foi detectado.")
    else:
        csv_file_path_used = 'audit_campos_dmo_utilizados.csv'
        header_used = ['DMO_DISPLAY_NAME', 'DMO_API_NAME', 'DMO_CREATED_BY', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'USAGE_TYPE', 'USED_IN_OBJECT_NAME', 'USED_IN_OBJECT_API_NAME']
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