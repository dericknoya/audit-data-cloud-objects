# -*- coding: utf-8 -*-
"""
Este script audita uma instância do Salesforce Data Cloud para identificar 
campos de DMOs (Data Model Objects) utilizados e não utilizados.

Versão: 18.0 (Otimização Completa)

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
from collections import defaultdict
from urllib.parse import urljoin, urlencode
from datetime import datetime, timedelta, timezone

import jwt
import requests
import aiohttp
from dotenv import load_dotenv
from tqdm.asyncio import tqdm

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# --- Configuração ---
USE_PROXY = True
PROXY_URL = os.getenv("PROXY_URL")
VERIFY_SSL = False
CHUNK_SIZE = 400

# --- Configuração do Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Funções Reutilizáveis (Autenticação, API Fetching, etc.) ---

def get_access_token():
    logging.info("🔑 Autenticando com o Salesforce via JWT...")
    sf_client_id = os.getenv("SF_CLIENT_ID")
    sf_username = os.getenv("SF_USERNAME")
    sf_audience = os.getenv("SF_AUDIENCE")
    sf_login_url = os.getenv("SF_LOGIN_URL")
    if not all([sf_client_id, sf_username, sf_audience, sf_login_url]):
        raise ValueError("Uma ou mais variáveis de ambiente de autenticação estão faltando no .env.")
    if USE_PROXY and not PROXY_URL:
        logging.warning("⚠️ USE_PROXY=True, mas a variável PROXY_URL não foi encontrada no .env. Continuando sem proxy.")
    try:
        with open('private.pem', 'r') as f: private_key = f.read()
    except FileNotFoundError:
        logging.error("❌ Arquivo 'private.pem' não encontrado."); raise
    payload = {'iss': sf_client_id, 'sub': sf_username, 'aud': sf_audience, 'exp': int(time.time()) + 300}
    assertion = jwt.encode(payload, private_key, algorithm='RS256')
    params = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': assertion}
    token_url = f"{sf_login_url}/services/oauth2/token"
    try:
        proxies = {'http': PROXY_URL, 'https': PROXY_URL} if USE_PROXY and PROXY_URL else None
        res = requests.post(token_url, data=params, proxies=proxies, verify=VERIFY_SSL)
        res.raise_for_status()
        logging.info("✅ Autenticação bem-sucedida.")
        return res.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Erro na autenticação: {e.response.text if e.response else e}"); raise

async def fetch_api_data(session, relative_url, semaphore, key_name=None):
    async with semaphore:
        all_records = []
        current_url = relative_url
        try:
            while current_url:
                kwargs = {'ssl': VERIFY_SSL}
                if USE_PROXY and PROXY_URL: kwargs['proxy'] = PROXY_URL
                async with session.get(current_url, **kwargs) as response:
                    response.raise_for_status()
                    data = await response.json()
                    if key_name:
                        all_records.extend(data.get(key_name, []))
                        next_page_url = data.get('nextRecordsUrl')
                        current_url = urljoin(str(session._base_url), next_page_url) if next_page_url else None
                    else: 
                        return data
            return all_records
        except aiohttp.ClientError as e:
            logging.error(f"❌ Erro ao buscar dados da API REST: {e}")
            return [] if key_name else {}

async def execute_query_job(session, query, semaphore):
    async with semaphore:
        job_url_path = "/services/data/v60.0/jobs/query"
        payload = {"operation": "query", "query": query, "contentType": "CSV"}
        proxy = PROXY_URL if USE_PROXY and PROXY_URL else None
        try:
            async with session.post(job_url_path, data=json.dumps(payload), proxy=proxy, ssl=VERIFY_SSL) as response:
                response.raise_for_status()
                job_info = await response.json(); job_id = job_info.get('id')
                if not job_id: logging.error(f"❌ JobId não retornado para query: {query[:100]}..."); return []
            job_status_path = f"{job_url_path}/{job_id}"
            while True:
                await asyncio.sleep(5)
                async with session.get(job_status_path, proxy=proxy, ssl=VERIFY_SSL) as resp:
                    resp.raise_for_status()
                    status_info = await resp.json(); state = status_info.get('state')
                    if state == 'JobComplete': break
                    if state in ['Failed', 'Aborted']: logging.error(f"❌ Job de query {job_id} falhou: {status_info.get('errorMessage')}"); return []
            results_path = f"{job_status_path}/results"
            results_headers = {'Accept-Encoding': 'gzip'}
            async with session.get(results_path, headers=results_headers, proxy=proxy, ssl=VERIFY_SSL) as qr:
                qr.raise_for_status()
                content_bytes = await qr.read()
                csv_text = gzip.decompress(content_bytes).decode('utf-8') if qr.headers.get('Content-Encoding') == 'gzip' else content_bytes.decode('utf-8')
                lines = csv_text.strip().splitlines()
                if len(lines) > 1:
                    reader = csv.DictReader(lines)
                    reader.fieldnames = [field.strip('"') for field in reader.fieldnames]
                    return list(reader)
                return []
        except aiohttp.ClientError as e:
            error_text = ""
            if hasattr(e, 'response') and e.response:
                try: error_text = await e.response.text()
                except Exception: error_text = "[Could not decode error response]"
            logging.error(f"❌ Erro no job de query: status={getattr(e, 'status', 'N/A')}, message='{e}', response='{error_text}'")
            return []

async def fetch_records_in_bulk(session, semaphore, object_name, fields, record_ids):
    if not record_ids: return []
    all_records, tasks, field_str = [], [], ", ".join(fields)
    for i in range(0, len(record_ids), CHUNK_SIZE):
        chunk = record_ids[i:i + CHUNK_SIZE]; formatted_ids = "','".join(chunk)
        query = f"SELECT {field_str} FROM {object_name} WHERE Id IN ('{formatted_ids}')"
        tasks.append(execute_query_job(session, query, semaphore))
    results = await tqdm.gather(*tasks, desc=f"Buscando {object_name} (Bulk API)")
    for record_list in results: all_records.extend(record_list)
    return all_records

async def fetch_users_by_id(session, semaphore, user_ids):
    if not user_ids: return []
    all_users, tasks = [], []
    field_str = "Id, Name"
    for i in range(0, len(user_ids), CHUNK_SIZE):
        chunk = user_ids[i:i + CHUNK_SIZE]; formatted_ids = "','".join(chunk)
        query = f"SELECT {field_str} FROM User WHERE Id IN ('{formatted_ids}')"
        url = f"/services/data/v60.0/query?{urlencode({'q': query})}"
        tasks.append(fetch_api_data(session, url, semaphore, 'records'))
    results = await tqdm.gather(*tasks, desc="Buscando nomes de criadores (REST API)")
    for record_list in results: all_users.extend(record_list)
    return all_users

def find_fields_in_structure(obj, field_set):
    """Percorre recursivamente uma estrutura JSON/dict em busca de campos."""
    api_name_keys = ["fieldApiName", "fieldName", "attributeName", "developerName"]
    try:
        if isinstance(obj, str) and ('{' in obj or '[' in obj):
            obj = json.loads(html.unescape(obj))

        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in api_name_keys and isinstance(value, str):
                    field_set.add(value)
                find_fields_in_structure(value, field_set)
        elif isinstance(obj, list):
            for item in obj:
                find_fields_in_structure(item, field_set)
    except (json.JSONDecodeError, TypeError):
        return

# --- Lógica Principal da Auditoria ---
async def audit_dmo_fields():
    auth_data = get_access_token()
    access_token, instance_url = auth_data['access_token'], auth_data['instance_url']
    logging.info('🚀 Iniciando auditoria de campos de DMO...')
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json', 'Accept': 'application/json'}
    
    semaphore = asyncio.Semaphore(50)
    async with aiohttp.ClientSession(headers=headers, base_url=instance_url, connector=aiohttp.TCPConnector(ssl=VERIFY_SSL)) as session:
        logging.info("--- Etapa 1: Coletando metadados e listas de objetos ---")

        dmo_soql_query = "SELECT DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject"
        segment_soql_query = "SELECT Id FROM MarketSegment"
        activation_attributes_query = "SELECT Id, QueryPath, Name, MarketSegmentActivationId FROM MktSgmntActvtnAudAttribute"
        
        initial_tasks = [
            fetch_api_data(session, f"/services/data/v60.0/tooling/query?{urlencode({'q': dmo_soql_query})}", semaphore, 'records'),
            execute_query_job(session, segment_soql_query, semaphore),
            fetch_api_data(session, "/services/data/v60.0/ssot/metadata?entityType=DataModelObject", semaphore, 'metadata'),
            execute_query_job(session, activation_attributes_query, semaphore),
            fetch_api_data(session, "/services/data/v60.0/ssot/metadata?entityType=CalculatedInsight", semaphore, 'metadata'),
        ]
        results = await tqdm.gather(*initial_tasks, desc="Coletando metadados iniciais")
        dmo_tooling_data, segment_id_records, dmo_metadata_list, activation_attributes, calculated_insights = results
        
        dmo_creation_info = {rec['DeveloperName']: {'CreatedDate': rec['CreatedDate'], 'CreatedById': rec.get('CreatedById')} for rec in dmo_tooling_data}
        segment_ids = [rec['Id'] for rec in segment_id_records if rec.get('Id')]
        logging.info(f"✅ Etapa 1.1: {len(dmo_tooling_data)} DMOs, {len(segment_ids)} Segmentos e {len(activation_attributes)} Ativações carregadas.")
        
        logging.info(f"--- Etapa 2: Buscando detalhes de {len(segment_ids)} segmentos... ---")
        segment_fields_to_query = ["Id", "Name", "IncludeCriteria", "ExcludeCriteria"]
        segments_list = await fetch_records_in_bulk(session, "/services/data/v60.0/sobjects/MarketSegment/", semaphore, segment_fields_to_query, segment_ids)
        logging.info("✅ Detalhes de segmentos coletados.")

        creator_ids = {info['CreatedById'] for info in dmo_creation_info.values() if info.get('CreatedById')}
        user_id_to_name_map = {}
        if creator_ids:
             logging.info(f"--- Etapa 3: Buscando nomes de {len(creator_ids)} criadores de DMOs... ---")
             user_records = await fetch_users_by_id(session, semaphore, list(creator_ids))
             user_id_to_name_map = {user['Id']: user['Name'] for user in user_records}
             logging.info("✅ Nomes de criadores coletados.")
    
    logging.info("\n📊 Dados coletados. Analisando o uso dos campos...")
    
    all_dmo_fields = defaultdict(lambda: {'fields': {}, 'displayName': '', 'creatorName': 'Desconhecido'})
    dmo_prefixes_to_exclude = ('ssot', 'unified', 'individual', 'einstein', 'segment_membership', 'aa_', 'aal_')

    for dmo in dmo_metadata_list:
        if (dmo_name := dmo.get('name')) and dmo_name.endswith('__dlm'):
            if any(dmo_name.lower().startswith(prefix) for prefix in dmo_prefixes_to_exclude): continue
            all_dmo_fields[dmo_name]['displayName'] = dmo.get('displayName', dmo_name)
            if dmo_info := dmo_creation_info.get(dmo_name):
                creator_id = dmo_info.get('CreatedById')
                all_dmo_fields[dmo_name]['creatorName'] = user_id_to_name_map.get(creator_id, 'Desconhecido')
            for field in dmo.get('fields', []):
                if field_name := field.get('name'):
                    all_dmo_fields[dmo_name]['fields'][field_name] = field.get('displayName', field_name)

    used_fields_details = defaultdict(list)
    
    for seg in tqdm(segments_list, desc="Analisando Segmentos"):
        fields_found_in_seg = set()
        find_fields_in_structure(seg.get('IncludeCriteria', ''), fields_found_in_seg)
        find_fields_in_structure(seg.get('ExcludeCriteria', ''), fields_found_in_seg)
        for field_name in fields_found_in_seg:
            usage_context = {"usage_type": "Segmento", "object_name": seg.get('Name'), "object_api_name": seg.get('Id')}
            if usage_context not in used_fields_details[field_name]:
                used_fields_details[field_name].append(usage_context)

    for attr in tqdm(activation_attributes, desc="Analisando Ativações"):
        fields_found_in_attr = set()
        find_fields_in_structure(attr.get('QueryPath'), fields_found_in_attr)
        for field_name in fields_found_in_attr:
            usage_context = {"usage_type": "Ativação", "object_name": attr.get('Name'), "object_api_name": attr.get('MarketSegmentActivationId')}
            if usage_context not in used_fields_details[field_name]:
                used_fields_details[field_name].append(usage_context)

    for ci in tqdm(calculated_insights, desc="Analisando CIs"):
        fields_found_in_ci = set()
        find_fields_in_structure(ci, fields_found_in_ci)
        for field_name in fields_found_in_ci:
            usage_context = {"usage_type": "Calculated Insight", "object_name": ci.get('displayName'), "object_api_name": ci.get('name')}
            if usage_context not in used_fields_details[field_name]:
                used_fields_details[field_name].append(usage_context)

    ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
    field_prefixes_to_exclude = ('ssot__', 'KQ_')
    specific_fields_to_exclude = {'DataSource__c', 'DataSourceObject__c', 'InternalOrganization__c'}

    # Adiciona campos de DMOs recém-criados à lista de usados
    for dmo_name in all_dmo_fields:
        if created_date_str := dmo_creation_info.get(dmo_name, {}).get('CreatedDate'):
            try:
                dmo_created_date = datetime.fromisoformat(created_date_str.replace('Z', '+00:00'))
                if dmo_created_date > ninety_days_ago:
                    for field_api_name in all_dmo_fields[dmo_name]['fields']:
                        usage_context = {"usage_type": "N/A (DMO Recém-criado)", "object_name": "DMO criado nos últimos 90 dias", "object_api_name": dmo_name}
                        if usage_context not in used_fields_details[field_api_name]:
                            used_fields_details[field_api_name].append(usage_context)
            except (ValueError, TypeError):
                logging.warning(f"Não foi possível parsear a data para {dmo_name}: {created_date_str}")
    
    # Prepara os resultados para os CSVs
    used_field_results, unused_field_results = [], []
    
    for dmo_name, data in all_dmo_fields.items():
        for field_api_name, field_display_name in data['fields'].items():
            if any(field_api_name.startswith(p) for p in field_prefixes_to_exclude) or field_api_name in specific_fields_to_exclude:
                continue
            
            if field_api_name in used_fields_details:
                for usage in used_fields_details[field_api_name]:
                    used_field_results.append({
                        'DMO_DISPLAY_NAME': data['displayName'], 'DMO_API_NAME': dmo_name, 'CREATED_BY_NAME': data['creatorName'],
                        'FIELD_DISPLAY_NAME': field_display_name, 'FIELD_API_NAME': field_api_name,
                        'USAGE_TYPE': usage['usage_type'], 'USED_IN_OBJECT_NAME': usage['object_name'],
                        'USED_IN_OBJECT_API_NAME': usage['object_api_name']
                    })
            else:
                 unused_field_results.append({
                    'DELETAR': 'NAO', 'DMO_DISPLAY_NAME': data['displayName'], 'DMO_API_NAME': dmo_name, 'CREATED_BY_NAME': data['creatorName'],
                    'FIELD_DISPLAY_NAME': field_display_name, 'FIELD_API_NAME': field_api_name, 
                    'REASON': 'Não utilizado em Segmentos, Ativações ou CIs'
                })

    logging.info(f"📊 Total de {len(used_fields_details)} campos únicos em uso.")
    
    # Grava CSV de campos NÃO utilizados
    if unused_field_results:
        csv_file_path_unused = 'audit_campos_dmo_nao_utilizados.csv'
        header_unused = ['DELETAR', 'DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'REASON', 'CREATED_BY_NAME']
        with open(csv_file_path_unused, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=header_unused); writer.writeheader(); writer.writerows(unused_field_results)
        logging.info(f"✅ Relatório de campos NÃO utilizados gerado: {csv_file_path_unused} ({len(unused_field_results)} campos)")
    else:
        logging.info("🎉 Nenhum campo não utilizado foi encontrado!")
        
    # Grava CSV de campos UTILIZADOS
    if used_field_results:
        csv_file_path_used = 'audit_campos_dmo_utilizados.csv'
        header_used = ['DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'USAGE_TYPE', 'USED_IN_OBJECT_NAME', 'USED_IN_OBJECT_API_NAME', 'CREATED_BY_NAME']
        with open(csv_file_path_used, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=header_used); writer.writeheader(); writer.writerows(used_field_results)
        logging.info(f"✅ Relatório de campos UTILIZADOS gerado: {csv_file_path_used} ({len(used_field_results)} usos)")
    else:
        logging.info("ℹ️ Nenhum uso de campo de DMO customizado foi detectado.")


if __name__ == "__main__":
    start_time = time.time()
    try:
        asyncio.run(audit_dmo_fields())
    finally:
        end_time = time.time()
        duration = end_time - start_time
        logging.info(f"\nTempo total de execução: {duration:.2f} segundos")