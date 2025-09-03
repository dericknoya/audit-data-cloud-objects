"""
Script de auditoria Salesforce Data Cloud - Objetos órfãos e inativos

Versão: 14.02 (Versão Final Estável)
- BASE ESTÁVEL: Script construído a partir da v13.01.
- CORREÇÃO (NameError): Corrigido o erro 'NameError: name 'get_segment_id' is
  not defined' que ocorria devido à remoção acidental da função auxiliar
  correspondente.
- REGRAS DE NEGÓCIO: Mantida a lógica de auditoria redefinida na v14.00.

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
CHUNK_SIZE = 100 
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
                            next_page_url_v1 = data.get('nextRecordsUrl')
                            next_page_url_v2 = data.get('nextPageUrl')
                            query_locator = data.get('queryLocator')
                            next_page_path = next_page_url_v1 or next_page_url_v2

                            if next_page_path:
                                current_url = urljoin(str(session._base_url), next_page_path)
                            elif is_tooling_api and query_locator and not data.get('done', True):
                                current_url = f"/services/data/{API_VERSION}/tooling/query/{query_locator}"
                            else:
                                current_url = None
                        else: 
                            return data
                return all_records
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY)
                else:
                    raise e

async def fetch_records_by_ids_rest(session, semaphore, object_name, fields, record_ids, desc_text):
    if not record_ids: return []
    all_records = []
    field_str = ", ".join(fields)
    tasks = []
    for i in range(0, len(record_ids), CHUNK_SIZE):
        chunk = record_ids[i:i + CHUNK_SIZE]
        formatted_ids = "','".join(chunk)
        query = f"SELECT {field_str} FROM {object_name} WHERE Id IN ('{formatted_ids}')"
        url = f"/services/data/{API_VERSION}/query?{urlencode({'q': query})}"
        tasks.append(fetch_api_data(session, url, semaphore, 'records'))
    
    results = await tqdm.gather(*tasks, desc=desc_text)
    for record_list in results:
        if record_list: all_records.extend(record_list)
    return all_records

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

def find_dmos_in_payload(payload, dmo_set):
    if not payload: return
    try:
        data = json.loads(html.unescape(str(payload))) if isinstance(payload, str) else payload
        dmo_keys = {'objectName', 'entityName', 'developerName'}
        def recurse(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in dmo_keys and isinstance(value, str) and value.endswith('__dlm'):
                        dmo_set.add(normalize_api_name(value))
                    elif isinstance(value, (dict, list)):
                        recurse(value)
            elif isinstance(obj, list):
                for item in obj:
                    recurse(item)
        recurse(data)
    except (json.JSONDecodeError, TypeError): return

def find_segments_in_criteria(criteria_str, segment_set):
    if not criteria_str: return
    try:
        criteria_json = json.loads(html.unescape(str(criteria_str))) if isinstance(criteria_str, str) else criteria_json
        def recurse(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key == 'segmentId' and isinstance(value, str):
                        segment_set.add(value[:15])
                    elif isinstance(value, (dict, list)):
                        recurse(value)
            elif isinstance(obj, list):
                for item in obj:
                    recurse(item)
        recurse(criteria_json)
    except (json.JSONDecodeError, TypeError): return

def get_segment_id(seg): return seg.get('Id') # <-- FUNÇÃO ADICIONADA DE VOLTA
def get_segment_name(seg): return seg.get('Name') or '(Sem nome)'
def get_dmo_display_name(dmo): return dmo.get('displayName') or dmo.get('name') or '(Sem nome)'

# --- Main Audit Logic ---
async def main():
    auth_data = get_access_token()
    instance_url = auth_data['instance_url']
    headers = {'Authorization': f'Bearer {auth_data["access_token"]}', 'Content-Type': 'application/json'}
    semaphore = asyncio.Semaphore(10)
    async with aiohttp.ClientSession(headers=headers, base_url=instance_url, connector=aiohttp.TCPConnector(ssl=VERIFY_SSL)) as session:
        logging.info("--- Etapa 1: Coletando metadados e listas de objetos ---")
        
        dmo_soql_query = "SELECT Id, DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject"
        segment_soql_query = "SELECT Id FROM MarketSegment"
        activation_attributes_query = "SELECT Id, Name, MarketSegmentActivationId, CreatedById FROM MktSgmntActvtnAudAttribute"
        
        initial_tasks = [
            fetch_api_data(session, f"/services/data/{API_VERSION}/tooling/query?{urlencode({'q': dmo_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, f"/services/data/{API_VERSION}/query?{urlencode({'q': segment_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, f"/services/data/{API_VERSION}/ssot/metadata?entityType=DataModelObject", semaphore, 'metadata'),
            fetch_api_data(session, f"/services/data/{API_VERSION}/query?{urlencode({'q': activation_attributes_query})}", semaphore, 'records'),
            fetch_api_data(session, f"/services/data/{API_VERSION}/ssot/metadata?entityType=CalculatedInsight", semaphore, 'metadata'),
            fetch_api_data(session, f"/services/data/{API_VERSION}/ssot/data-streams", semaphore, 'dataStreams'),
            fetch_api_data(session, f"/services/data/{API_VERSION}/ssot/data-graphs/metadata", semaphore, 'dataGraphMetadata'),
            fetch_api_data(session, f"/services/data/{API_VERSION}/ssot/data-actions", semaphore, 'dataActions'),
        ]
        
        async def run_safely(coro):
            try: return await coro
            except Exception as e: return e

        safe_initial_tasks = [run_safely(task) for task in initial_tasks]
        results = await tqdm.gather(*safe_initial_tasks, desc="Coletando metadados iniciais")
        
        task_names = ["DMO Tooling", "Segment IDs", "DMO Metadata", "Activation Attributes", "Calculated Insights", "Data Streams", "Data Graphs", "Data Actions"]
        dmo_tooling_data, segment_id_records, dm_objects, activation_attributes, calculated_insights, data_streams, data_graphs, data_actions = [
            res if not isinstance(res, Exception) else [] for res in results
        ]
        
        now = datetime.now(timezone.utc)
        thirty_days_ago = now - timedelta(days=30)
        ninety_days_ago = now - timedelta(days=90)

        dmo_info_map = {rec['DeveloperName']: rec for rec in dmo_tooling_data}
        segment_ids = [rec['Id'] for rec in segment_id_records]

        logging.info(f"--- Etapa 2: Buscando detalhes de ativações e segmentos ---")
        activation_ids = list(set(attr['MarketSegmentActivationId'] for attr in activation_attributes))
        
        activation_fields = ["Id", "MarketSegmentId", "LastModifiedDate", "CreatedById"]
        segment_fields = ["Id", "Name", "SegmentMembershipTable", "IncludeCriteria", "ExcludeCriteria", "SegmentStatus", "CreatedById"]

        activation_details, segments = await asyncio.gather(
            fetch_records_by_ids_rest(session, semaphore, "MarketSegmentActivation", activation_fields, activation_ids, "Buscando Ativações (API REST)"),
            fetch_records_by_ids_rest(session, semaphore, "MarketSegment", segment_fields, segment_ids, "Buscando Segmentos (API REST)")
        )
        
        segment_publications = {str(act.get('MarketSegmentId', ''))[:15]: parse_sf_date(act.get('LastModifiedDate')) for act in activation_details if act.get('MarketSegmentId')}

        all_creator_ids = set()
        for collection in [dmo_tooling_data, activation_attributes, activation_details, segments]:
            for item in collection:
                if creator_id := item.get('CreatedById'):
                    all_creator_ids.add(creator_id)

        user_id_to_name_map = {}
        if all_creator_ids:
            logging.info(f"--- Etapa 3: Buscando nomes de {len(all_creator_ids)} criadores... ---")
            user_records = await fetch_records_by_ids_rest(session, semaphore, "User", ["Id", "Name"], list(all_creator_ids), "Buscando Nomes de Criadores")
            user_id_to_name_map = {user['Id']: user['Name'] for user in user_records}

        # --- Etapa 4: Auditoria e Análise de Exclusão ---
        audit_results = []
        
        logging.info("Analisando dependências de DMOs...")
        dmos_used_in_segments = set()
        nested_segment_parents = {}
        for seg in tqdm(segments, desc="Analisando Critérios de Segmentos"):
            for field in ['IncludeCriteria', 'ExcludeCriteria']:
                find_dmos_in_payload(seg.get(field), dmos_used_in_segments)
                temp_nested_ids = set()
                find_segments_in_criteria(seg.get(field), temp_nested_ids)
                for nested_id in temp_nested_ids:
                    nested_segment_parents.setdefault(nested_id, []).append(get_segment_name(seg))

        dmos_used_in_data_graphs, dmos_used_in_cis, dmos_used_in_data_actions = set(), set(), set()
        for dg in data_graphs: find_dmos_in_payload(dg, dmos_used_in_data_graphs)
        for ci in calculated_insights: find_dmos_in_payload(ci, dmos_used_in_cis)
        for da in data_actions: find_dmos_in_payload(da, dmos_used_in_data_actions)
            
        all_used_dmos = dmos_used_in_segments.union(dmos_used_in_data_graphs, dmos_used_in_cis, dmos_used_in_data_actions)

        logging.info("Auditando Segmentos e Ativações...")
        deletable_segment_ids = set()
        for seg in tqdm(segments, desc="Auditando Segmentos"):
            seg_id_short = str(get_segment_id(seg) or '')[:15]
            if not seg_id_short: continue
            
            last_pub_date = segment_publications.get(seg_id_short)
            if not last_pub_date or last_pub_date < thirty_days_ago:
                is_used_as_filter = seg_id_short in nested_segment_parents
                reason, status = "", ""
                if not is_used_as_filter:
                    deletable_segment_ids.add(seg_id_short)
                    reason = "Órfão: Não publicado nos últimos 30 dias E não utilizado como filtro aninhado."
                    status = "Órfão"
                else:
                    reason = f"Inativo: Última publicação > 30 dias, MAS é utilizado como filtro em: {', '.join(nested_segment_parents.get(seg_id_short, []))}"
                    status = "Inativo"
                
                audit_results.append({
                    'DELETAR': 'NAO', 'ID_OR_API_NAME': seg_id_short,
                    'DISPLAY_NAME': get_segment_name(seg), 'OBJECT_TYPE': 'SEGMENT', 'STATUS': status,
                    'REASON': reason, 'TIPO_ATIVIDADE': 'Última Publicação',
                    'DIAS_ATIVIDADE': days_since(last_pub_date) if last_pub_date else '>30',
                    'CREATED_BY_NAME': user_id_to_name_map.get(seg.get('CreatedById'), 'Desconhecido'),
                    'DELETION_IDENTIFIER': get_segment_name(seg)
                })

        for act_detail in activation_details:
            seg_id_short = str(act_detail.get('MarketSegmentId', ''))[:15]
            if seg_id_short in deletable_segment_ids:
                act_id = act_detail.get('Id')
                act_name = next((attr.get('Name') for attr in activation_attributes if attr.get('MarketSegmentActivationId') == act_id), act_id)
                audit_results.append({
                    'DELETAR': 'NAO', 'ID_OR_API_NAME': act_id,
                    'DISPLAY_NAME': act_name, 'OBJECT_TYPE': 'ACTIVATION', 'STATUS': 'Órfã',
                    'REASON': f'Órfã: Associada a um segmento que foi identificado como órfão ({seg_id_short}).', 'TIPO_ATIVIDADE': 'N/A',
                    'DIAS_ATIVIDADE': 'N/A', 'CREATED_BY_NAME': user_id_to_name_map.get(act_detail.get('CreatedById'), 'Desconhecido'),
                    'DELETION_IDENTIFIER': act_name
                })

        logging.info("Auditando Data Model Objects (DMOs)...")
        for dmo in dm_objects:
            dmo_name = dmo.get('name')
            if not dmo_name or not dmo_name.endswith('__dlm'): continue
            
            normalized_dmo_name = normalize_api_name(dmo_name)
            dmo_details = dmo_info_map.get(dmo_name, {})
            created_date = parse_sf_date(dmo_details.get('CreatedDate'))
            
            if (not created_date or created_date < ninety_days_ago) and normalized_dmo_name not in all_used_dmos:
                audit_results.append({
                    'DELETAR': 'NAO', 'ID_OR_API_NAME': dmo_details.get('Id', dmo_name),
                    'DISPLAY_NAME': get_dmo_display_name(dmo), 'OBJECT_TYPE': 'DMO', 'STATUS': 'Órfão',
                    'REASON': "Órfão: Criado > 90 dias (ou data desconhecida) e não utilizado em Segmentos, Data Graphs, CIs ou Data Actions.", 
                    'TIPO_ATIVIDADE': 'Criação',
                    'DIAS_ATIVIDADE': days_since(created_date) if created_date else '>90',
                    'CREATED_BY_NAME': user_id_to_name_map.get(dmo_details.get('CreatedById'), 'Desconhecido'),
                    'DELETION_IDENTIFIER': dmo_name
                })
        
        logging.info("Auditando Data Streams...")
        for ds in data_streams:
            last_updated = parse_sf_date(ds.get('lastIngestDate'))
            if not last_updated or last_updated < thirty_days_ago:
                has_mappings = bool(ds.get('mappings'))
                reason, status = "", ""
                dlo_name = ds.get('dataLakeObjectInfo', {}).get('name', 'N/A')
                if not has_mappings:
                    reason = "Órfão: A última atualização foi > 30 dias e o array 'mappings' está vazio."
                    status = "Órfão"
                else:
                    reason = f"Inativo: A última atualização foi > 30 dias, mas possui mapeamentos para o DLO: {dlo_name}"
                    status = "Inativo"
                
                audit_results.append({
                    'DELETAR': 'NAO', 'ID_OR_API_NAME': ds.get('name'),
                    'DISPLAY_NAME': ds.get('label'), 'OBJECT_TYPE': 'DATA_STREAM', 'STATUS': status,
                    'REASON': reason, 'TIPO_ATIVIDADE': 'Última Ingestão',
                    'DIAS_ATIVIDADE': days_since(last_updated) if last_updated else ">30",
                    'CREATED_BY_NAME': 'Desconhecido',
                    'DELETION_IDENTIFIER': dlo_name or ds.get('name')
                })
        
        logging.info("Auditando Calculated Insights...")
        for ci in calculated_insights:
            last_processed = parse_sf_date(ci.get('lastSuccessfulProcessingDate'))
            if not last_processed or last_processed < ninety_days_ago:
                 audit_results.append({
                    'DELETAR': 'NAO', 'ID_OR_API_NAME': ci.get('name'),
                    'DISPLAY_NAME': ci.get('displayName'), 'OBJECT_TYPE': 'CALCULATED_INSIGHT', 'STATUS': 'Inativo',
                    'REASON': "Inativo: Último processamento bem-sucedido > 90 dias.", 'TIPO_ATIVIDADE': 'Último Processamento',
                    'DIAS_ATIVIDADE': days_since(last_processed) if last_processed else '>90',
                    'CREATED_BY_NAME': 'Desconhecido',
                    'DELETION_IDENTIFIER': ci.get('name')
                })

        if audit_results:
            csv_file = "audit_objetos_para_exclusao.csv"
            with open(csv_file, mode='w', newline='', encoding='utf-8') as f:
                fieldnames = ['DELETAR', 'ID_OR_API_NAME', 'DISPLAY_NAME', 'OBJECT_TYPE', 'STATUS', 'REASON', 'TIPO_ATIVIDADE', 'DIAS_ATIVIDADE', 'CREATED_BY_NAME', 'DELETION_IDENTIFIER']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(audit_results)
            logging.info(f"✅ Auditoria concluída. CSV gerado: {csv_file}")
            
            counts = {t: 0 for t in ['DMO', 'DATA_STREAM', 'CALCULATED_INSIGHT', 'SEGMENT', 'ACTIVATION']}
            for result in audit_results:
                 if result.get('OBJECT_TYPE') in counts:
                    counts[result['OBJECT_TYPE']] += 1
            
            summary = " | ".join(f"{k}: {v}" for k, v in counts.items() if v > 0)
            logging.info(f"📊 Resumo de objetos identificados: {summary}")
        else:
            logging.info("🎉 Nenhum objeto para exclusão encontrado.")

if __name__ == "__main__":
    start_time = time.time()
    try:
        asyncio.run(main())
    except Exception as e:
        logging.error(f"Um erro inesperado ocorreu durante a auditoria: {e}", exc_info=True)
    finally:
        duration = time.time() - start_time
        logging.info(f"\nTempo total de execução: {duration:.2f} segundos")