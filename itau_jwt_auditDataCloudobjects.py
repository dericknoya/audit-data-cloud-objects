# -*- coding: utf-8 -*-
"""
Script de auditoria Salesforce Data Cloud - Objetos órfãos e inativos

Versão: 11.1 (Correção de Query SOQL na Bulk API)
- CORREÇÃO CRÍTICA: Corrigido um erro de formatação na cláusula IN das queries
  SOQL geradas para a Bulk API (ex: ao buscar MarketSegment). Isso resolve
  o erro 'Bad Request' (400) que impedia a execução. A formatação agora
  corresponde à da versão funcional 10.24.
- MANTÉM: Todas as correções de precisão da versão 11.0 para Data Streams
  e nomes de criadores.

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
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urljoin

import jwt
import requests
import aiohttp
from dotenv import load_dotenv
from tqdm.asyncio import tqdm

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# --- Configuração ---
class Config:
    USE_PROXY = os.getenv("USE_PROXY", "True").lower() == "true"
    PROXY_URL = os.getenv("PROXY_URL")
    VERIFY_SSL = os.getenv("VERIFY_SSL", "False").lower() == "true"
    API_VERSION = "v60.0"
    CHUNK_SIZE = 400
    MAX_RETRIES = 3
    RETRY_DELAY = 5
    
    # Períodos de inatividade (em dias)
    DATA_STREAM_INACTIVITY_DAYS = 30
    SEGMENT_INACTIVITY_DAYS = 30
    CI_INACTIVITY_DAYS = 90
    DMO_GRACE_PERIOD_DAYS = 90
    
    # Nomes de arquivos
    ACTIVATION_USAGE_CSV = 'ativacoes_campos.csv'
    FINAL_REPORT_CSV = 'audit_objetos_para_exclusao.csv'

# --- Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Funções Auxiliares ---
def get_access_token():
    logging.info("🔑 Autenticando com o Salesforce via JWT...")
    sf_client_id, sf_username, sf_audience, sf_login_url = (
        os.getenv("SF_CLIENT_ID"), os.getenv("SF_USERNAME"),
        os.getenv("SF_AUDIENCE"), os.getenv("SF_LOGIN_URL"),
    )
    if not all([sf_client_id, sf_username, sf_audience, sf_login_url]):
        raise ValueError("Variáveis de ambiente de autenticação faltando no .env.")
    try:
        with open('private.pem', 'r') as f: private_key = f.read()
    except FileNotFoundError:
        logging.error("❌ 'private.pem' não encontrado."); raise
    
    payload = {'iss': sf_client_id, 'sub': sf_username, 'aud': sf_audience, 'exp': int(time.time()) + 300}
    assertion = jwt.encode(payload, private_key, algorithm='RS256')
    params = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': assertion}
    token_url = urljoin(sf_login_url, "/services/oauth2/token")
    
    proxies = {'http': Config.PROXY_URL, 'https': Config.PROXY_URL} if Config.USE_PROXY and Config.PROXY_URL else None
    
    try:
        res = requests.post(token_url, data=params, proxies=proxies, verify=Config.VERIFY_SSL)
        res.raise_for_status()
        logging.info("✅ Autenticação bem-sucedida.")
        return res.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Erro na autenticação: {e.response.text if e.response else e}"); raise

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

def find_items_in_criteria(criteria, key_to_find, item_set):
    if not criteria: return
    try:
        criteria_json = json.loads(html.unescape(str(criteria))) if isinstance(criteria, str) else criteria
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

def read_activation_usage_csv(file_path):
    used_dmos = set()
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if entity_name := row.get('entityName'):
                    used_dmos.add(normalize_api_name(entity_name))
        logging.info(f"✅ Arquivo '{file_path}' lido. {len(used_dmos)} DMOs únicos encontrados.")
    except FileNotFoundError:
        logging.warning(f"⚠️ Arquivo '{file_path}' não encontrado. A auditoria prosseguirá sem esta fonte de dados.")
    except Exception as e:
        logging.error(f"❌ Erro ao ler '{file_path}': {e}")
    return used_dmos

async def fetch_api_data(session, relative_url, semaphore, key_name=None):
    async with semaphore:
        for attempt in range(Config.MAX_RETRIES):
            try:
                all_records, current_url = [], relative_url
                is_tooling = "/tooling" in current_url
                while current_url:
                    kwargs = {'ssl': Config.VERIFY_SSL}
                    if Config.USE_PROXY: kwargs['proxy'] = Config.PROXY_URL
                    async with session.get(current_url, **kwargs) as response:
                        response.raise_for_status()
                        data = await response.json()
                        if key_name:
                            all_records.extend(data.get(key_name, []))
                            next_page = data.get('nextRecordsUrl')
                            query_locator = data.get('queryLocator')
                            if next_page: current_url = urljoin(str(session._base_url), next_page)
                            elif is_tooling and query_locator and not data.get('done', True):
                                current_url = f"/services/data/{Config.API_VERSION}/tooling/query/{query_locator}"
                            else: current_url = None
                        else: return data
                return all_records
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt < Config.MAX_RETRIES - 1:
                    logging.warning(f" Tentativa {attempt + 1} para {relative_url[:50]} falhou: {e}. Tentando novamente...")
                    await asyncio.sleep(Config.RETRY_DELAY)
                else:
                    logging.error(f"❌ Falha definitiva em {relative_url[:50]}: {e}"); raise

async def execute_query_job(session, query, semaphore):
    async with semaphore:
        for attempt in range(Config.MAX_RETRIES):
            try:
                job_url = f"/services/data/{Config.API_VERSION}/jobs/query"
                payload = {"operation": "query", "query": query, "contentType": "CSV"}
                proxy = Config.PROXY_URL if Config.USE_PROXY else None
                async with session.post(job_url, json=payload, proxy=proxy, ssl=Config.VERIFY_SSL) as res:
                    res.raise_for_status(); job_info = await res.json(); job_id = job_info['id']
                
                status_url = f"{job_url}/{job_id}"
                while True:
                    await asyncio.sleep(5)
                    async with session.get(status_url, proxy=proxy, ssl=Config.VERIFY_SSL) as res:
                        res.raise_for_status(); status_info = await res.json()
                        if status_info['state'] == 'JobComplete': break
                        if status_info['state'] in ['Failed', 'Aborted']:
                            logging.error(f"❌ Job {job_id} falhou: {status_info.get('errorMessage')}"); return []
                
                results_url = f"{status_url}/results"
                async with session.get(results_url, headers={'Accept-Encoding': 'gzip'}, proxy=proxy, ssl=Config.VERIFY_SSL) as res:
                    res.raise_for_status()
                    content = await res.read()
                    csv_text = (gzip.decompress(content) if res.headers.get('Content-Encoding') == 'gzip' else content).decode('utf-8')
                    lines = csv_text.strip().splitlines()
                    return list(csv.DictReader(lines)) if len(lines) > 1 else []
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt < Config.MAX_RETRIES - 1:
                    logging.warning(f" Tentativa {attempt + 1} no job '{query[:50]}...' falhou: {e}. Tentando novamente...")
                    await asyncio.sleep(Config.RETRY_DELAY)
                else:
                    logging.error(f"❌ Falha definitiva no job '{query[:50]}...': {e}"); raise

async def fetch_records_in_bulk(session, semaphore, object_name, fields, record_ids):
    if not record_ids: return []
    tasks = []
    for i in range(0, len(record_ids), Config.CHUNK_SIZE):
        chunk = record_ids[i:i + Config.CHUNK_SIZE]
        # <<< INÍCIO DA CORREÇÃO (V11.1) >>>
        # Formata a lista de IDs corretamente, com cada ID entre aspas
        formatted_ids = "','".join(chunk)
        query = f"SELECT {', '.join(fields)} FROM {object_name} WHERE Id IN ('{formatted_ids}')"
        # <<< FIM DA CORREÇÃO (V11.1) >>>
        tasks.append(execute_query_job(session, query, semaphore))
    results = await tqdm.gather(*tasks, desc=f"Buscando {object_name} (Bulk API)")
    return [record for record_list in results if record_list for record in record_list]

async def fetch_users_by_id(session, semaphore, user_ids):
    if not user_ids: return {}
    users = await fetch_records_in_bulk(session, semaphore, 'User', ['Id', 'Name'], list(user_ids))
    return {user['Id']: user['Name'] for user in users if 'Id' in user and 'Name' in user}

async def main():
    auth_data = get_access_token()
    access_token, instance_url = auth_data['access_token'], auth_data['instance_url']
    logging.info('🚀 Iniciando auditoria de objetos...')

    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    semaphore = asyncio.Semaphore(10)
    async with aiohttp.ClientSession(headers=headers, base_url=instance_url, connector=aiohttp.TCPConnector(ssl=Config.VERIFY_SSL)) as session:
        logging.info("--- Etapa 1: Coletando metadados e listas de objetos ---")
        
        initial_tasks = {
            "dmo_tooling": fetch_api_data(session, f"/services/data/{Config.API_VERSION}/tooling/query?{urlencode({'q': 'SELECT Id, DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject'})}", semaphore, 'records'),
            "segments": execute_query_job(session, "SELECT Id FROM MarketSegment", semaphore),
            "dmo_metadata": fetch_api_data(session, f"/services/data/{Config.API_VERSION}/ssot/metadata?entityType=DataModelObject", semaphore, 'metadata'),
            "ci_metadata": fetch_api_data(session, f"/services/data/{Config.API_VERSION}/ssot/metadata?entityType=CalculatedInsight", semaphore, 'metadata'),
            "data_streams": fetch_api_data(session, f"/services/data/{Config.API_VERSION}/ssot/data-streams", semaphore, 'dataStreams'),
            "data_graphs": fetch_api_data(session, f"/services/data/{Config.API_VERSION}/ssot/data-graphs/metadata", semaphore, 'dataGraphMetadata'),
            "data_actions": fetch_api_data(session, f"/services/data/{Config.API_VERSION}/ssot/data-actions", semaphore, 'dataActions'),
            "contact_points": execute_query_job(session, "SELECT ContactPointFilterExpression, ContactPointPath FROM MktSgmntActvtnContactPoint", semaphore),
        }
        
        results = await asyncio.gather(*initial_tasks.values(), return_exceptions=True)
        
        data = {}
        for i, task_name in enumerate(initial_tasks.keys()):
            if isinstance(results[i], Exception):
                logging.error(f"❌ Falha na coleta de '{task_name}': {results[i]}")
                data[task_name] = []
            else:
                data[task_name] = results[i]

        dmo_info_map = {rec['DeveloperName']: rec for rec in data["dmo_tooling"]}
        segment_ids = [rec['Id'] for rec in data["segments"] if rec.get('Id')]

        logging.info("--- Etapa 2: Buscando detalhes de Segmentos e Ativações ---")
        activations = await execute_query_job(session, "SELECT MarketSegmentId, LastModifiedDate FROM MarketSegmentActivation", semaphore)
        segment_publications = { str(act.get('MarketSegmentId', ''))[:15]: parse_sf_date(act.get('LastModifiedDate')) 
                                for act in activations if act.get('MarketSegmentId')}

        segments = await fetch_records_in_bulk(session, semaphore, "MarketSegment", 
                                               ["Id", "Name", "SegmentMembershipTable", "IncludeCriteria", "ExcludeCriteria", "SegmentStatus", "CreatedById"], 
                                               segment_ids)

        logging.info("--- Etapa 3: Coletando todos os IDs de criadores ---")
        all_creator_ids = set()
        collections_with_creators = [data["dmo_tooling"], segments, data["ci_metadata"], data["data_streams"]]
        for collection in collections_with_creators:
            for item in collection:
                if creator_id := (item.get('CreatedById') or item.get('createdById')):
                    all_creator_ids.add(creator_id)

        user_id_to_name_map = await fetch_users_by_id(session, semaphore, all_creator_ids)
        logging.info(f"✅ Nomes de {len(user_id_to_name_map)} criadores encontrados.")

        logging.info("--- Etapa 4: Analisando uso e inatividade dos objetos ---")
        
        mapped_dlos = set()
        for dmo in data["dmo_metadata"]:
            for field in dmo.get("fields", []):
                if dlo_source := field.get("sourceObject"):
                    mapped_dlos.add(dlo_source)
        logging.info(f"Encontrados {len(mapped_dlos)} Data Lake Objects com mapeamentos ativos para DMOs.")

        dmos_from_activation_csv = read_activation_usage_csv(Config.ACTIVATION_USAGE_CSV)
        dmos_used_by_segments = {normalize_api_name(s.get('SegmentMembershipTable')) for s in segments if s.get('SegmentMembershipTable')}
        dmos_used_by_data_graphs = {normalize_api_name(obj.get('developerName')) for dg in data["data_graphs"] for obj in [dg.get('dgObject', {})] + dg.get('dgObject', {}).get('relatedObjects', []) if obj.get('developerName')}
        dmos_used_by_ci_relationships = {normalize_api_name(rel.get('fromEntity')) for ci in data["ci_metadata"] for rel in ci.get('relationships', []) if rel.get('fromEntity')}
        
        dmos_used_in_criteria = set()
        nested_segment_parents = {}
        for s in segments: find_items_in_criteria(s.get('IncludeCriteria'), 'developerName', dmos_used_in_criteria); find_items_in_criteria(s.get('ExcludeCriteria'), 'developerName', dmos_used_in_criteria); find_items_in_criteria(s.get('IncludeCriteria'), 'segmentId', nested_segment_parents); find_items_in_criteria(s.get('ExcludeCriteria'), 'segmentId', nested_segment_parents)
        for da in data["data_actions"]: find_items_in_criteria(da, 'developerName', dmos_used_in_criteria)
        for cp in data["contact_points"]: find_items_in_criteria(cp.get('ContactPointPath'), 'developerName', dmos_used_in_criteria); find_items_in_criteria(cp.get('ContactPointFilterExpression'), 'developerName', dmos_used_in_criteria)
        
        all_used_dmos = (dmos_used_by_segments | dmos_used_by_data_graphs | dmos_used_by_ci_relationships | dmos_used_in_criteria | dmos_from_activation_csv)

        audit_results = []
        now = datetime.now(timezone.utc)
        
        for seg in tqdm(segments, desc="Auditando Segmentos"):
            seg_id = str(seg.get('Id', ''))[:15]
            if not seg_id: continue
            last_pub_date = segment_publications.get(seg_id)
            if not last_pub_date or last_pub_date < (now - timedelta(days=Config.SEGMENT_INACTIVITY_DAYS)):
                is_nested = seg_id in nested_segment_parents
                reason = f"Inativo, mas usado como filtro em outros segmentos" if is_nested else 'Inativo (sem atividade recente e não é filtro aninhado)'
                audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': seg_id, 'DISPLAY_NAME': seg.get('Name'), 'OBJECT_TYPE': 'SEGMENT', 'STATUS': seg.get('SegmentStatus'), 'REASON': reason, 'DIAS_ATIVIDADE': days_since(last_pub_date), 'CREATED_BY_NAME': user_id_to_name_map.get(seg.get('CreatedById'), 'Desconhecido'), 'DELETION_IDENTIFIER': seg.get('Name')})

        for dmo in tqdm(data["dmo_metadata"], desc="Auditando DMOs"):
            dmo_name = dmo.get('name', '')
            if not dmo_name.endswith('__dlm') or any(dmo_name.lower().startswith(p) for p in ('ssot', 'unified', 'individual')): continue
            lookup_key = normalize_api_name(dmo_name)
            dmo_details = dmo_info_map.get(lookup_key, {})
            created_date = parse_sf_date(dmo_details.get('CreatedDate'))
            if created_date and created_date < (now - timedelta(days=Config.DMO_GRACE_PERIOD_DAYS)):
                if lookup_key not in all_used_dmos:
                    creator_id = dmo_details.get('CreatedById')
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': dmo_details.get('Id'), 'DISPLAY_NAME': dmo.get('displayName'), 'OBJECT_TYPE': 'DMO', 'STATUS': 'N/A', 'REASON': "Órfão (não utilizado e criado > 90d)", 'DIAS_ATIVIDADE': days_since(created_date), 'CREATED_BY_NAME': user_id_to_name_map.get(creator_id, 'Desconhecido'), 'DELETION_IDENTIFIER': dmo_name})

        for ds in tqdm(data["data_streams"], desc="Auditando Data Streams"):
            last_updated = parse_sf_date(ds.get('lastIngestDate'))
            if not last_updated or last_updated < (now - timedelta(days=Config.DATA_STREAM_INACTIVITY_DAYS)):
                has_mapping = ds.get('dataLakeObjectName') in mapped_dlos
                reason = "Inativo (sem ingestão > 30d, mas POSSUI mapeamentos)" if has_mapping else "Inativo (sem ingestão > 30d e sem mapeamentos)"
                creator_id = ds.get('createdById')
                audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': ds.get('id'), 'DISPLAY_NAME': ds.get('name'), 'OBJECT_TYPE': 'DATA_STREAM', 'STATUS': ds.get('status'), 'REASON': reason, 'DIAS_ATIVIDADE': days_since(last_updated), 'CREATED_BY_NAME': user_id_to_name_map.get(creator_id, 'Desconhecido'), 'DELETION_IDENTIFIER': ds.get('id')})

        for ci in tqdm(data["ci_metadata"], desc="Auditando CIs"):
            last_processed = parse_sf_date(ci.get('lastSuccessfulProcessingDate'))
            if not last_processed or last_processed < (now - timedelta(days=Config.CI_INACTIVITY_DAYS)):
                creator_id = ci.get('createdById')
                audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': ci.get('name'), 'DISPLAY_NAME': ci.get('displayName'), 'OBJECT_TYPE': 'CALCULATED_INSIGHT', 'STATUS': ci.get('status'), 'REASON': "Inativo (último processamento bem-sucedido > 90d)", 'DIAS_ATIVIDADE': days_since(last_processed), 'CREATED_BY_NAME': user_id_to_name_map.get(creator_id, 'Desconhecido'), 'DELETION_IDENTIFIER': ci.get('name')})

        if audit_results:
            with open(Config.FINAL_REPORT_CSV, mode='w', newline='', encoding='utf-8-sig') as f:
                fieldnames = ['DELETAR', 'ID_OR_API_NAME', 'DISPLAY_NAME', 'OBJECT_TYPE', 'STATUS', 'REASON', 'DIAS_ATIVIDADE', 'CREATED_BY_NAME', 'DELETION_IDENTIFIER']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(audit_results)
            logging.info(f"✅ Auditoria concluída. CSV gerado: {Config.FINAL_REPORT_CSV} ({len(audit_results)} linhas)")
        else:
            logging.info("🎉 Nenhum objeto órfão ou inativo encontrado.")

if __name__ == "__main__":
    start_time = time.time()
    try: asyncio.run(main())
    except Exception as e: logging.critical(f"❌ Erro fatal durante a execução: {e}", exc_info=True)
    finally: logging.info(f"\nTempo total de execução: {time.time() - start_time:.2f} segundos")