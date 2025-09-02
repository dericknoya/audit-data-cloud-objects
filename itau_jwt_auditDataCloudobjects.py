"""
Script de auditoria Salesforce Data Cloud - Objetos órfãos e inativos

Versão: 10.45 (Versão Final Estável + Funcionalidades)
- BASE ESTÁVEL: Script construído a partir da v10.37 para garantir a ausência de
  erros '400 Bad Request' e 'AttributeError'.
- FUNCIONALIDADE COMPLETA: Inclui as funções para buscar o 'CreatedById' de
  Data Streams e Calculated Insights via query SOQL por Nome, preenchendo
  corretamente a coluna 'CREATED_BY_NAME'.
- CORREÇÃO (Data Stream): Colunas de identificação e nome de exibição ajustadas
  para usar os campos corretos do payload da API.
- NOVO: Adicionada contagem final dos objetos por tipo no log.

Gera CSV final: audit_objetos_para_exclusao.csv
"""

import os
import time
import asyncio
import csv
import json
import html
import logging
import gzip
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urljoin

import jwt
import requests
import aiohttp
from dotenv import load_dotenv
from tqdm.asyncio import tqdm

# Carrega as variáveis de ambiente do arquivo .env no início do script
load_dotenv()

# --- Configuration ---
USE_PROXY = True
PROXY_URL = os.getenv("PROXY_URL")
VERIFY_SSL = False
CHUNK_SIZE = 400
MAX_RETRIES = 3
RETRY_DELAY = 5 # segundos
API_VERSION = "v64.0" 

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Funções de Autenticação, API, e Helpers ---
def get_access_token():
    logging.info("🔑 Authenticating with Salesforce using JWT Bearer Flow...")
    sf_client_id = os.getenv("SF_CLIENT_ID")
    sf_username = os.getenv("SF_USERNAME")
    sf_audience = os.getenv("SF_AUDIENCE")
    sf_login_url = os.getenv("SF_LOGIN_URL")
    if not all([sf_client_id, sf_username, sf_audience, sf_login_url]):
        raise ValueError("Uma ou mais variáveis de ambiente de autenticação (SF_CLIENT_ID, SF_USERNAME, etc.) estão faltando no arquivo .env.")
    if USE_PROXY and not PROXY_URL:
        logging.warning("⚠️ USE_PROXY está como True, mas a variável PROXY_URL não foi encontrada no arquivo .env. O script continuará sem proxy.")
    try:
        with open('private.pem', 'r') as f: private_key = f.read()
    except FileNotFoundError:
        logging.error("❌ 'private.pem' file not found."); raise
    payload = {'iss': sf_client_id, 'sub': sf_username, 'aud': sf_audience, 'exp': int(time.time()) + 300}
    assertion = jwt.encode(payload, private_key, algorithm='RS256')
    params = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': assertion}
    token_url = f"{sf_login_url}/services/oauth2/token"
    try:
        proxies = {'http': PROXY_URL, 'https': PROXY_URL} if USE_PROXY and PROXY_URL else None
        res = requests.post(token_url, data=params, proxies=proxies, verify=VERIFY_SSL)
        res.raise_for_status()
        logging.info("✅ Authentication successful.")
        return res.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Salesforce authentication error: {e.response.text if e.response else e}"); raise

async def fetch_api_data(session, relative_url, semaphore, key_name=None):
    async with semaphore:
        for attempt in range(MAX_RETRIES):
            try:
                all_records = []
                current_url = relative_url
                is_tooling_api = "/tooling" in current_url
                
                while current_url:
                    kwargs = {'ssl': VERIFY_SSL}
                    if USE_PROXY and PROXY_URL: kwargs['proxy'] = PROXY_URL
                    
                    async with session.get(current_url, **kwargs) as response:
                        response.raise_for_status()
                        data = await response.json()
                        
                        if key_name:
                            all_records.extend(data.get(key_name, []))
                            next_page_url = data.get('nextRecordsUrl')
                            query_locator = data.get('queryLocator')

                            if next_page_url:
                                current_url = urljoin(str(session._base_url), next_page_url)
                            elif is_tooling_api and query_locator and not data.get('done', True):
                                version = API_VERSION
                                current_url = f"/services/data/{version}/tooling/query/{query_locator}"
                            else:
                                current_url = None
                        else: 
                            return data
                return all_records
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt < MAX_RETRIES - 1:
                    logging.warning(f" Tentativa {attempt + 1} de buscar {relative_url[:50]}... falhou: {e}. Tentando novamente em {RETRY_DELAY}s...")
                    await asyncio.sleep(RETRY_DELAY)
                else:
                    logging.error(f"❌ Todas as {MAX_RETRIES} tentativas falharam para {relative_url[:50]}...: {e}")
                    raise e

def parse_sf_date(date_str):
    if not date_str: return None
    try: return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except (ValueError, TypeError): return None

def days_since(date_obj):
    if not date_obj: return None
    return (datetime.now(timezone.utc) - date_obj).days

def normalize_api_name(name):
    if not isinstance(name, str): return ""
    return name.removesuffix('__dlm').removesuffix('__cio').removesuffix('__dll')

def find_items_in_criteria(criteria_str, key_to_find, item_set):
    if not criteria_str: return
    try:
        if isinstance(criteria_str, (dict, list)): criteria_json = criteria_str
        else: criteria_json = json.loads(html.unescape(str(criteria_str)))
        def recurse(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key == key_to_find and isinstance(value, str):
                        if key in ['objectName', 'entityName', 'developerName'] and value.endswith('__dlm'):
                            item_set.add(normalize_api_name(value))
                        elif key == 'segmentId':
                            item_set.add(str(value)[:15])
                    elif isinstance(value, (dict, list)): recurse(value)
            elif isinstance(obj, list):
                for item in obj: recurse(item)
        recurse(criteria_json)
    except (json.JSONDecodeError, TypeError): return

def get_segment_id(seg): return seg.get('Id')
def get_segment_name(seg): return seg.get('Name') or '(Sem nome)'
def get_dmo_display_name(dmo): return dmo.get('displayName') or dmo.get('name') or '(Sem nome)'

def read_activation_usage_csv(file_path='ativacoes_campos.csv'):
    used_dmos = set()
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if entity_name := row.get('entityName'):
                    used_dmos.add(normalize_api_name(entity_name))
        logging.info(f"✅ Arquivo '{file_path}' lido com sucesso. {len(used_dmos)} DMOs únicos encontrados em uso.")
        return used_dmos
    except FileNotFoundError:
        logging.warning(f"⚠️ Arquivo de uso de ativações '{file_path}' não encontrado. A auditoria de DMOs prosseguirá sem esta fonte de dados.")
        return used_dmos
    except Exception as e:
        logging.error(f"❌ Erro ao ler o arquivo '{file_path}': {e}")
        return used_dmos

async def execute_query_job(session, query, semaphore):
    async with semaphore:
        for attempt in range(MAX_RETRIES):
            try:
                job_url_path = f"/services/data/{API_VERSION}/jobs/query"
                payload = {"operation": "query", "query": query, "contentType": "CSV"}
                proxy = PROXY_URL if USE_PROXY and PROXY_URL else None
                
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
                    if len(lines) > 1: reader = csv.DictReader(lines); reader.fieldnames = [field.strip('"') for field in reader.fieldnames]; return list(reader)
                    return []
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt < MAX_RETRIES - 1:
                    logging.warning(f" Tentativa {attempt + 1} do job de query '{query[:50]}...' falhou: {e}. Tentando novamente em {RETRY_DELAY}s...")
                    await asyncio.sleep(RETRY_DELAY)
                else:
                    logging.error(f"❌ Todas as {MAX_RETRIES} tentativas falharam para o job de query '{query[:50]}...': {e}")
                    raise e

async def fetch_records_in_bulk(session, semaphore, object_name, fields, record_ids):
    if not record_ids: return []
    all_records, tasks, field_str = [], [], ", ".join(fields)
    for i in range(0, len(record_ids), CHUNK_SIZE):
        chunk = record_ids[i:i + CHUNK_SIZE]; formatted_ids = "','".join(chunk)
        query = f"SELECT {field_str} FROM {object_name} WHERE Id IN ('{formatted_ids}')"
        tasks.append(execute_query_job(session, query, semaphore))
    
    try:
        results = await tqdm.gather(*tasks, desc=f"Buscando {object_name} (Bulk API)")
        for record_list in results:
            if record_list: all_records.extend(record_list)
        return all_records
    except Exception as e:
        logging.error(f"❌ Falha crítica ao buscar registros em massa para '{object_name}': {e}. O script continuará com os dados que possui.")
        return []

async def fetch_users_by_id(session, semaphore, user_ids):
    if not user_ids: return []
    all_users, tasks = [], []
    field_str = "Id, Name"
    for i in range(0, len(user_ids), CHUNK_SIZE):
        chunk = user_ids[i:i + CHUNK_SIZE]; formatted_ids = "','".join(chunk)
        query = f"SELECT {field_str} FROM User WHERE Id IN ('{formatted_ids}')"
        url = f"/services/data/{API_VERSION}/query?{urlencode({'q': query})}"
        tasks.append(fetch_api_data(session, url, semaphore, 'records'))
    results = await tqdm.gather(*tasks, desc="Buscando nomes de criadores (REST API)")
    for record_list in results:
        if record_list: all_users.extend(record_list)
    return all_users

async def fetch_creators_by_name(session, semaphore, object_name, names, name_field='Name'):
    if not names: return {}
    records, tasks = [], []
    field_str = f"{name_field}, CreatedById"
    for i in range(0, len(names), CHUNK_SIZE):
        chunk = names[i:i + CHUNK_SIZE]
        escaped_names = [name.replace("'", "\\'") for name in chunk]
        formatted_names = "','".join(escaped_names)
        query = f"SELECT {field_str} FROM {object_name} WHERE {name_field} IN ('{formatted_names}')"
        url = f"/services/data/{API_VERSION}/query?{urlencode({'q': query})}"
        tasks.append(fetch_api_data(session, url, semaphore, 'records'))
    results = await tqdm.gather(*tasks, desc=f"Buscando criadores de {object_name} (REST API)")
    for record_list in results:
        if record_list: records.extend(record_list)
    return {rec[name_field]: rec.get('CreatedById') for rec in records}

# --- Main Audit Logic ---
async def main():
    auth_data = get_access_token()
    access_token, instance_url = auth_data['access_token'], auth_data['instance_url']
    logging.info('🚀 Iniciando auditoria de exclusão de objetos...')

    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json', 'Accept': 'application/json'}
    semaphore = asyncio.Semaphore(10)
    async with aiohttp.ClientSession(headers=headers, base_url=instance_url, connector=aiohttp.TCPConnector(ssl=VERIFY_SSL)) as session:
        logging.info("--- Etapa 1: Coletando metadados e listas de objetos ---")
        
        dmo_soql_query = "SELECT Id, DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject"
        segment_soql_query = "SELECT Id FROM MarketSegment"
        # Usando as queries simplificadas que se provaram estáveis
        activation_attributes_query = "SELECT Id, Name, MarketSegmentActivationId, CreatedById FROM MktSgmntActvtnAudAttribute"
        contact_point_query = "SELECT Id, CreatedById FROM MktSgmntActvtnContactPoint"
        
        initial_tasks = [
            fetch_api_data(session, f"/services/data/{API_VERSION}/tooling/query?{urlencode({'q': dmo_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, f"/services/data/{API_VERSION}/query?{urlencode({'q': segment_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, f"/services/data/{API_VERSION}/ssot/metadata?entityType=DataModelObject", semaphore, 'metadata'),
            execute_query_job(session, activation_attributes_query, semaphore),
            fetch_api_data(session, f"/services/data/{API_VERSION}/ssot/metadata?entityType=CalculatedInsight", semaphore, 'metadata'),
            fetch_api_data(session, f"/services/data/{API_VERSION}/ssot/data-streams", semaphore, 'dataStreams'),
            fetch_api_data(session, f"/services/data/{API_VERSION}/ssot/data-graphs/metadata", semaphore, 'dataGraphMetadata'),
            fetch_api_data(session, f"/services/data/{API_VERSION}/ssot/data-actions", semaphore, 'dataActions'),
            execute_query_job(session, contact_point_query, semaphore),
        ]
        
        results = await asyncio.gather(*initial_tasks, return_exceptions=True)
        
        task_names = ["DMO Tooling", "Segment IDs", "DMO Metadata", "Activation Attributes", "Calculated Insights", "Data Streams", "Data Graphs", "Data Actions", "Contact Points"]
        final_results = []
        for i, result in enumerate(results):
            task_name = task_names[i] if i < len(task_names) else f"Tarefa {i}"
            if isinstance(result, Exception):
                logging.error(f"❌ A coleta de '{task_name}' falhou definitivamente: {result}")
                final_results.append([])
            else:
                final_results.append(result)

        logging.info("✅ Coleta inicial de metadados concluída (com tratamento de falhas).")
        dmo_tooling_data, segment_id_records, dm_objects, activation_attributes, calculated_insights, data_streams, data_graphs, data_actions, contact_point_usages = final_results
        
        now = datetime.now(timezone.utc)
        thirty_days_ago = now - timedelta(days=30)
        ninety_days_ago = now - timedelta(days=90)

        dmo_info_map = {rec['DeveloperName']: rec for rec in dmo_tooling_data if rec.get('DeveloperName')}
        segment_ids = [rec['Id'] for rec in segment_id_records if rec.get('Id')]
        logging.info(f"✅ Etapa 1.1: {len(dmo_info_map)} DMOs, {len(segment_ids)} Segmentos, {len(activation_attributes)} Ativações e {len(contact_point_usages)} Pontos de Contato carregados.")

        activation_ids = list(set(attr['MarketSegmentActivationId'] for attr in activation_attributes if attr.get('MarketSegmentActivationId')))
        
        logging.info(f"--- Etapa 2: Buscando detalhes de {len(activation_ids)} ativações únicas... ---")
        activation_fields_to_query = ["Id", "MarketSegmentId", "LastModifiedDate", "CreatedById"]
        activation_details = await fetch_records_in_bulk(session, semaphore, "MarketSegmentActivation", activation_fields_to_query, activation_ids)
        logging.info("✅ Detalhes de ativação coletados.")

        segment_publications = { str(act.get('MarketSegmentId') or '')[:15]: parse_sf_date(act.get('LastModifiedDate')) for act in activation_details if act.get('MarketSegmentId') and act.get('LastModifiedDate')}

        logging.info(f"--- Etapa 3: Buscando detalhes de {len(segment_ids)} segmentos... ---")
        segment_fields_to_query = ["Id", "Name", "SegmentMembershipTable", "IncludeCriteria", "ExcludeCriteria", "SegmentStatus", "CreatedById"]
        segments = await fetch_records_in_bulk(session, semaphore, "MarketSegment", segment_fields_to_query, segment_ids)
        logging.info("✅ Detalhes de segmento coletados. Iniciando busca por nomes de criadores...")

        all_creator_ids = set()
        collections_with_creators = [dmo_tooling_data, activation_attributes, activation_details, segments]
        for collection in collections_with_creators:
            if not isinstance(collection, list):
                continue
            for item in collection:
                if isinstance(item, dict):
                    if creator_id := (item.get('CreatedById') or item.get('createdById')):
                        all_creator_ids.add(creator_id)

        inactive_ds_names = [ds.get('name') for ds in data_streams if ds.get('name') and (not (ds.get('lastRefreshDate') or ds.get('lastIngestDate')) or parse_sf_date(ds.get('lastRefreshDate') or ds.get('lastIngestDate')) < thirty_days_ago)]
        inactive_ci_names = [ci.get('name') for ci in calculated_insights if ci.get('name') and (not ci.get('lastSuccessfulProcessingDate') or parse_sf_date(ci.get('lastSuccessfulProcessingDate')) < ninety_days_ago)]
        
        ds_name_to_creator_map, ci_name_to_creator_map = await asyncio.gather(
            fetch_creators_by_name(session, semaphore, "DataStream", inactive_ds_names, "Name"),
            fetch_creators_by_name(session, semaphore, "MktCalculatedInsight", inactive_ci_names, "Name")
        )
        
        for creator_id in ds_name_to_creator_map.values():
            if creator_id: all_creator_ids.add(creator_id)
        for creator_id in ci_name_to_creator_map.values():
            if creator_id: all_creator_ids.add(creator_id)
        
        logging.info(f"Coletados {len(all_creator_ids)} IDs de criadores únicos para buscar nomes.")
        user_id_to_name_map = {}
        if all_creator_ids:
            logging.info(f"--- Etapa 4: Buscando nomes de {len(all_creator_ids)} criadores... ---")
            user_records = await fetch_users_by_id(session, semaphore, list(all_creator_ids))
            user_id_to_name_map = {user['Id']: user['Name'] for user in user_records}
            logging.info(f"{len(user_id_to_name_map)} nomes de usuários foram encontrados com sucesso.")
        
        dmo_prefixes_to_exclude = ('ssot', 'unified', 'individual', 'einstein', 'segment_membership', 'aa_', 'aal_')
        
        dmos_from_activation_csv = read_activation_usage_csv()
        
        dmos_used_by_segments = {normalize_api_name(s.get('SegmentMembershipTable')) for s in segments if s.get('SegmentMembershipTable')}
        dmos_used_by_data_graphs = {normalize_api_name(obj.get('developerName')) for dg in data_graphs for obj in [dg.get('dgObject', {})] + dg.get('dgObject', {}).get('relatedObjects', []) if obj.get('developerName')}
        dmos_used_by_ci_relationships = {normalize_api_name(rel.get('fromEntity')) for ci in calculated_insights for rel in ci.get('relationships', []) if rel.get('fromEntity')}
        
        dmos_used_in_data_actions = set()
        for da in data_actions:
            find_items_in_criteria(da, 'developerName', dmos_used_in_data_actions)
            
        dmos_used_in_contact_points = set()
        for cp in contact_point_usages:
            find_items_in_criteria(cp.get('ContactPointPath'), 'developerName', dmos_used_in_contact_points)
            find_items_in_criteria(cp.get('ContactPointFilterExpression'), 'developerName', dmos_used_in_contact_points)
            
        nested_segment_parents = {}
        dmos_used_in_segment_criteria = set()
        logging.info("Analisando critérios de segmentos para DMOs e aninhamento...")
        for seg in tqdm(segments, desc="Analisando Critérios de Segmentos"):
            parent_name = get_segment_name(seg)
            for criteria_field in ['IncludeCriteria', 'ExcludeCriteria']:
                criteria_str = seg.get(criteria_field)
                find_items_in_criteria(criteria_str, 'developerName', dmos_used_in_segment_criteria)
                nested_ids_found = set()
                find_items_in_criteria(criteria_str, 'segmentId', nested_ids_found)
                for nested_id in nested_ids_found:
                    nested_segment_parents.setdefault(nested_id, []).append(parent_name)

        audit_results = []
        deletable_segment_ids = set()
        
        logging.info("Auditando Segmentos...")
        for seg in tqdm(segments, desc="Auditando Segmentos"):
            seg_id = str(get_segment_id(seg) or '')[:15];
            if not seg_id: continue
            last_pub_date = segment_publications.get(seg_id)
            if not (last_pub_date and last_pub_date >= thirty_days_ago):
                is_used_as_filter = seg_id in nested_segment_parents
                days_since_pub = days_since(last_pub_date)
                seg_name = get_segment_name(seg)
                creator_name = user_id_to_name_map.get(seg.get('CreatedById'), 'Desconhecido')
                status = seg.get('SegmentStatus', 'N/A')
                if not is_used_as_filter:
                    deletable_segment_ids.add(seg_id)
                    reason = 'Inativo (sem atividade recente e não é filtro aninhado)'
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': seg_id, 'DISPLAY_NAME': seg_name, 'OBJECT_TYPE': 'SEGMENT', 'STATUS': status, 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Atividade', 'DIAS_ATIVIDADE': days_since_pub if days_since_pub is not None else 'N/A', 'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': seg_name})
                else:
                    reason = f"Inativo (sem atividade recente, mas usado como filtro em: {', '.join(nested_segment_parents.get(seg_id, []))})"
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': seg_id, 'DISPLAY_NAME': seg_name, 'OBJECT_TYPE': 'SEGMENT', 'STATUS': status, 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Atividade', 'DIAS_ATIVIDADE': days_since_pub if days_since_pub is not None else 'N/A', 'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': seg_name})

        logging.info("Auditando Ativações...")
        for act_detail in activation_details:
            seg_id = str(act_detail.get('MarketSegmentId') or '')[:15]
            if seg_id in deletable_segment_ids:
                act_id = act_detail.get('Id')
                act_name = next((attr.get('Name') for attr in activation_attributes if attr.get('MarketSegmentActivationId') == act_id), 'Nome não encontrado')
                creator_name = user_id_to_name_map.get(act_detail.get('CreatedById'), 'Desconhecido')
                reason = f'Órfã (associada a segmento inativo e sem vínculos: {seg_id})'
                audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': act_id, 'DISPLAY_NAME': act_name, 'OBJECT_TYPE': 'ACTIVATION', 'STATUS': 'N/A', 'REASON': reason, 'TIPO_ATIVIDADE': 'N/A', 'DIAS_ATIVIDADE': 'N/A', 'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': act_id})

        logging.info("Auditando Data Model Objects (DMOs)...")
        all_used_dmos = (dmos_used_by_segments | dmos_used_by_data_graphs | dmos_used_by_ci_relationships | dmos_used_in_data_actions | dmos_used_in_segment_criteria | dmos_from_activation_csv | dmos_used_in_contact_points)
        
        for dmo in dm_objects:
            dmo_name = dmo.get('name', '')
            if not dmo_name.endswith('__dlm') or any(dmo_name.lower().startswith(p) for p in dmo_prefixes_to_exclude):
                continue
            
            lookup_key = normalize_api_name(dmo_name)
            dmo_details = dmo_info_map.get(lookup_key, {})

            if not dmo_details:
                continue

            created_date = parse_sf_date(dmo_details.get('CreatedDate'))
            
            if not created_date or created_date < ninety_days_ago:
                normalized_dmo_name_for_usage_check = normalize_api_name(dmo_name)
                if normalized_dmo_name_for_usage_check not in all_used_dmos:
                    days_created = days_since(created_date)
                    reason = "Órfão (não utilizado em nenhum objeto e criado > 90d)"
                    display_name = get_dmo_display_name(dmo)
                    deletion_id = dmo_name
                    dmo_tooling_id = dmo_details.get('Id', 'ID não encontrado')
                    
                    creator_id = dmo_details.get('CreatedById') or dmo_details.get('createdbyid')
                    
                    if not creator_id:
                        creator_name = "ID Não Retornado pela API"
                    else:
                        creator_name = user_id_to_name_map.get(creator_id, f"ID Não Encontrado ({creator_id})")

                    audit_results.append({
                        'DELETAR': 'NAO', 
                        'ID_OR_API_NAME': dmo_tooling_id, 
                        'DISPLAY_NAME': display_name, 
                        'OBJECT_TYPE': 'DMO', 
                        'STATUS': 'N/A', 
                        'REASON': reason, 
                        'TIPO_ATIVIDADE': 'Criação', 
                        'DIAS_ATIVIDADE': days_created if days_created is not None else '>90', 
                        'CREATED_BY_NAME': creator_name, 
                        'DELETION_IDENTIFIER': deletion_id
                    })
        
        logging.info("Auditando Data Streams...")
        for ds in data_streams:
            last_updated_str = ds.get('lastRefreshDate') or ds.get('lastIngestDate')
            last_updated = parse_sf_date(last_updated_str)
            if not last_updated or last_updated < thirty_days_ago:
                days_inactive = days_since(last_updated)
                
                ds_label = ds.get('label')
                ds_api_name = ds.get('name')
                dlo_info = ds.get('dataLakeObjectInfo', {})
                deletion_id = dlo_info.get('name') 

                if not ds_label:
                    ds_label = dlo_info.get('label') or ds_api_name or "Nome não encontrado"
                if not deletion_id:
                    deletion_id = f"{ds_api_name}__dll" if ds_api_name else "ID de Exclusão não encontrado"

                creator_id = ds_name_to_creator_map.get(ds_api_name)
                creator_name = user_id_to_name_map.get(creator_id, 'Desconhecido')

                has_mappings = bool(ds.get('mappings'))
                
                if not has_mappings:
                    reason = "Inativo (sem ingestão > 30d e sem mapeamentos)"
                else:
                    reason = "Inativo (sem ingestão > 30d, mas possui mapeamentos)"
                
                audit_results.append({
                    'DELETAR': 'NAO', 
                    'ID_OR_API_NAME': ds_label, 
                    'DISPLAY_NAME': ds_label, 
                    'OBJECT_TYPE': 'DATA_STREAM', 
                    'STATUS': 'N/A', 
                    'REASON': reason, 
                    'TIPO_ATIVIDADE': 'Última Ingestão', 
                    'DIAS_ATIVIDADE': days_inactive if days_inactive is not None else '>30', 
                    'CREATED_BY_NAME': creator_name, 
                    'DELETION_IDENTIFIER': deletion_id
                })
        
        logging.info("Auditando Calculated Insights...")
        for ci in calculated_insights:
            last_processed = parse_sf_date(ci.get('lastSuccessfulProcessingDate'))
            if not last_processed or last_processed < ninety_days_ago:
                days_inactive = days_since(last_processed)
                ci_name = ci.get('name')
                
                creator_id = ci_name_to_creator_map.get(ci_name)
                creator_name = user_id_to_name_map.get(creator_id, 'Desconhecido')

                reason = "Inativo (último processamento bem-sucedido > 90d)"
                audit_results.append({
                    'DELETAR': 'NAO', 
                    'ID_OR_API_NAME': ci_name, 
                    'DISPLAY_NAME': ci.get('displayName'), 
                    'OBJECT_TYPE': 'CALCULATED_INSIGHT', 
                    'STATUS': 'N/A', 
                    'REASON': reason, 
                    'TIPO_ATIVIDADE': 'Último Processamento', 
                    'DIAS_ATIVIDADE': days_inactive if days_inactive is not None else '>90', 
                    'CREATED_BY_NAME': creator_name, 
                    'DELETION_IDENTIFIER': ci_name
                })

        if audit_results:
            csv_file = "audit_objetos_para_exclusao.csv"
            with open(csv_file, mode='w', newline='', encoding='utf-8') as f:
                fieldnames = ['DELETAR', 'ID_OR_API_NAME', 'DISPLAY_NAME', 'OBJECT_TYPE', 'STATUS', 'REASON', 'TIPO_ATIVIDADE', 'DIAS_ATIVIDADE', 'CREATED_BY_NAME', 'DELETION_IDENTIFIER']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(audit_results)
            logging.info(f"✅ Auditoria concluída. CSV gerado: {csv_file}")
            
            counts = {'DMO': 0, 'DATA_STREAM': 0, 'CALCULATED_INSIGHT': 0, 'SEGMENT': 0, 'ACTIVATION': 0}
            for result in audit_results:
                obj_type = result.get('OBJECT_TYPE')
                if obj_type in counts:
                    counts[obj_type] += 1
            
            summary_parts = [f"{key}: {value}" for key, value in counts.items() if value > 0]
            if summary_parts:
                logging.info(f"📊 Resumo de objetos identificados: {' | '.join(summary_parts)}")

        else:
            logging.info("🎉 Nenhum objeto órfão ou inativo encontrado com as regras atuais.")

if __name__ == "__main__":
    start_time = time.time()
    try:
        asyncio.run(main())
    except Exception as e:
        logging.error(f"Um erro inesperado ocorreu durante a auditoria: {e}", exc_info=True)
    finally:
        duration = time.time() - start_time
        logging.info(f"\nTempo total de execução: {duration:.2f} segundos")