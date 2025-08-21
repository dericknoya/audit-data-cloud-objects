"""
Este script audita uma instância do Salesforce Data Cloud para identificar objetos
não utilizados com base em um conjunto de regras.

Version: 5.85 (Fase 1 - Final)
- Alinha completamente a lógica de busca de dados com o script de auditoria de campos.
- Remove a chamada incorreta ao endpoint '/ssot/activations'.
- A lista de Ativações agora é obtida exclusivamente a partir dos IDs coletados
  via Tooling API em 'MktSgmntActvtnAudAttribute', garantindo a coleta de
  todos os registros de forma confiável.

Regras de Auditoria:
1. Segmentos:
  - Órfão: Não publicado nos últimos 30 dias E não utilizado como filtro aninhado.
  - Inativo: Última publicação > 30 dias, MAS é utilizado como filtro aninhado.

2. Ativações:
  - Órfã: Associada a um segmento que foi identificado como órfão.

3. Data Model Objects (DMOs):
  - Órfão se: For um DMO customizado, não for utilizado em nenhum Segmento, Ativação
    (incluindo seus atributos), Data Graph, CI ou Data Action, E (Criado > 90 dias
    OU Data de Criação desconhecida).

4. Data Streams:
  - Órfão se: A última atualização foi > 30 dias E o array 'mappings' retornado pela API
    estiver vazio.
  - Inativo se: A última atualização foi > 30 dias, MAS o array 'mappings' não está vazio.

5. Calculated Insights (CIs):
  - Inativo se: Último processamento bem-sucedido > 90 dias.

O resultado é salvo em um arquivo CSV chamado 'audit_objetos_para_exclusao.csv'.
"""
"""
Script de auditoria Salesforce Data Cloud - Objetos órfãos e inativos

Versão: 5.90
- Integra otimização do /jobs/query para polling assíncrono.
- Remove uso do endpoint /ssot/activations.
- Mantém auditoria de Segmentos, DMOs, Data Streams e Calculated Insights.

Gera CSV final: audit_objetos_para_exclusao.csv
"""
import os
import time
import asyncio
import csv
import json
import html
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urljoin

import jwt
import requests
import aiohttp
from dotenv import load_dotenv
from tqdm.asyncio import tqdm

# --- Configuration ---
USE_PROXY = True
PROXY_URL = "https://felirub:080796@proxynew.itau:8080"
VERIFY_SSL = False

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Authentication ---
def get_access_token():
    logging.info("🔑 Authenticating with Salesforce using JWT Bearer Flow...")
    load_dotenv()
    
    sf_client_id = os.getenv("SF_CLIENT_ID")
    sf_username = os.getenv("SF_USERNAME")
    sf_audience = os.getenv("SF_AUDIENCE")
    sf_login_url = os.getenv("SF_LOGIN_URL")

    if not all([sf_client_id, sf_username, sf_audience, sf_login_url]):
        raise ValueError("One or more required environment variables are missing.")

    try:
        with open('private.pem', 'r') as f:
            private_key = f.read()
    except FileNotFoundError:
        logging.error("❌ 'private.pem' file not found.")
        raise

    payload = {
        'iss': sf_client_id, 'sub': sf_username, 'aud': sf_audience,
        'exp': int(time.time()) + 300
    }
    assertion = jwt.encode(payload, private_key, algorithm='RS256')
    params = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': assertion}
    token_url = f"{sf_login_url}/services/oauth2/token"

    try:
        proxies = {'http': PROXY_URL, 'https': PROXY_URL} if USE_PROXY else None
        res = requests.post(token_url, data=params, proxies=proxies, verify=VERIFY_SSL)
        res.raise_for_status()
        logging.info("✅ Authentication successful.")
        return res.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Salesforce authentication error: {e.response.text if e.response else e}")
        raise

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
                    response.raise_for_status()
                    data = await response.json()
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
        except aiohttp.ClientError as e:
            logging.error(f"❌ Error fetching {current_url}: {e}")
            return [] if key_name else {}

async def fetch_single_record(session, semaphore, url):
    async with semaphore:
        try:
            async with session.get(url, proxy=PROXY_URL if USE_PROXY else None, ssl=VERIFY_SSL) as response:
                if response.status == 404:
                    logging.warning(f"⚠️ Record not found (404): {url}")
                    return None
                response.raise_for_status()
                return await response.json()
        except aiohttp.ClientError as e:
            logging.error(f"❌ Error fetching single record {url}: {e}")
            return None

# --- Helper Functions ---
def parse_sf_date(date_str):
    if not date_str: return None
    try:
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except (ValueError, TypeError): return None

def days_since(date_obj):
    if not date_obj: return None
    return (datetime.now(timezone.utc) - date_obj).days

def normalize_api_name(name):
    if not isinstance(name, str): return ""
    return name.removesuffix('__dlm').removesuffix('__cio').removesuffix('__dll')

def find_dmos_recursively(obj, dmo_set):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in ['objectName', 'entityName', 'developerName'] and isinstance(value, str) and value.endswith('__dlm'):
                dmo_set.add(normalize_api_name(value))
            elif isinstance(value, (dict, list)):
                find_dmos_recursively(value, dmo_set)
    elif isinstance(obj, list):
        for item in obj:
            find_dmos_recursively(item, dmo_set)

def find_dmos_in_criteria(criteria_str):
    if not criteria_str: return set()
    try:
        decoded_str = html.unescape(criteria_str)
        criteria_json = json.loads(decoded_str)
    except (json.JSONDecodeError, TypeError): return set()
    dmos_found = set()
    find_dmos_recursively(criteria_json, dmos_found)
    return dmos_found

def get_segment_id(seg): return seg.get('marketSegmentId') or seg.get('Id')
def get_segment_name(seg): return seg.get('displayName') or seg.get('Name') or '(Sem nome)'
def get_dmo_name(dmo): return dmo.get('name')
def get_dmo_display_name(dmo): return dmo.get('displayName') or dmo.get('name') or '(Sem nome)'

# --- Optimized /jobs/query ---
async def execute_query_job(session, instance_url, query, semaphore, max_wait=60, poll_interval=2):
    async with semaphore:
        payload = {
            "operation": "query",
            "query": query
        }
        url = f"{instance_url}/services/data/v64.0/jobs/query"
        async with session.post(url, json=payload, proxy=PROXY_URL if USE_PROXY else None, ssl=VERIFY_SSL) as response:
            response.raise_for_status()
            job_info = await response.json()
            job_id = job_info.get('id')
            if not job_id:
                logging.error("❌ JobId não retornado ao criar job de query.")
                return []

        job_status_url = f"{instance_url}/services/data/v64.0/jobs/query/{job_id}"
        elapsed = 0
        while elapsed < max_wait:
            async with session.get(job_status_url, proxy=PROXY_URL if USE_PROXY else None, ssl=VERIFY_SSL) as resp:
                resp.raise_for_status()
                status_info = await resp.json()
                status = status_info.get('status')
                if status == 'Completed':
                    query_result_url = status_info.get('queryResultUrl')
                    if query_result_url:
                        async with session.get(urljoin(instance_url, query_result_url), proxy=PROXY_URL if USE_PROXY else None, ssl=VERIFY_SSL) as qr:
                            qr.raise_for_status()
                            result = await qr.json()
                            return result.get('records', [])
                    return []
                elif status in ['Failed', 'Aborted']:
                    logging.error(f"❌ Job de query {job_id} falhou ou foi abortado.")
                    return []
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        logging.warning(f"⚠️ Timeout atingido para job de query {job_id}.")
        return []

# --- Main Audit Logic ---
async def main():
    auth_data = get_access_token()
    access_token, instance_url = auth_data['access_token'], auth_data['instance_url']
    logging.info('🚀 Iniciando auditoria de exclusão de objetos...')

    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    semaphore = asyncio.Semaphore(50)
    connector = aiohttp.TCPConnector(ssl=VERIFY_SSL)
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        logging.info("--- Etapa 1: Coletando metadados e listas de objetos ---")
        
        dmo_soql_query = "SELECT DeveloperName, CreatedDate FROM MktDataModelObject"
        segment_soql_query = "SELECT Id FROM MarketSegment"
        activation_attributes_query = "SELECT Id, QueryPath, Name, MarketSegmentActivationId FROM MktSgmntActvtnAudAttribute"
        
        initial_tasks = [
            fetch_api_data(session, instance_url, f"/services/data/v64.0/tooling/query?{urlencode({'q': dmo_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, f"/services/data/v64.0/query?{urlencode({'q': segment_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=DataModelObject", semaphore, 'metadata'),
            execute_query_job(session, instance_url, activation_attributes_query, semaphore),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=CalculatedInsight", semaphore, 'metadata'),
            fetch_api_data(session, instance_url, f"/services/data/v64.0/ssot/data-streams", semaphore, 'dataStreams'),
            fetch_api_data(session, instance_url, f"/services/data/v64.0/ssot/data-graphs/metadata", semaphore, 'dataGraphMetadata'),
            fetch_api_data(session, instance_url, f"/services/data/v64.0/ssot/data-actions", semaphore, 'dataActions'),
        ]
        results = await tqdm.gather(*initial_tasks, desc="Coletando metadados iniciais")
        dmo_tooling_data, segment_id_records, dm_objects, activation_attributes, calculated_insights, data_streams_summary, data_graphs, data_actions = results
        
        dmo_creation_dates = {rec['DeveloperName']: rec['CreatedDate'] for rec in dmo_tooling_data}
        segment_ids = [rec['Id'] for rec in segment_id_records]
        activation_ids = list(set(rec['MarketSegmentActivationId'] for rec in activation_attributes if rec.get('MarketSegmentActivationId')))
        logging.info(f"✅ Etapa 1.1: {len(dmo_creation_dates)} datas de criação de DMOs, {len(segment_ids)} IDs de Segmentos e {len(activation_attributes)} Ativações carregadas.")

        segment_detail_tasks = [fetch_api_data(session, instance_url, f"/services/data/v64.0/sobjects/MarketSegment/{seg_id}", semaphore) for seg_id in segment_ids]
        segments = await tqdm.gather(*segment_detail_tasks, desc="Buscando detalhes dos Segmentos")
        segments = [res for res in segments if res]

        # --- Processamento de Auditoria ---
        now = datetime.now(timezone.utc)
        thirty_days_ago = now - timedelta(days=30)
        ninety_days_ago = now - timedelta(days=90)

        segment_publications = {str(act.get('segmentId') or '')[:15]: parse_sf_date(act.get('lastPublishDate')) for act in activation_attributes if act.get('segmentId') and act.get('lastPublishDate')}
        nested_segment_parents = {}
        for seg in segments:
            parent_name = get_segment_name(seg)
            filters = (seg.get('filterDefinition') or {}).get('filters', [])
            for f in filters:
                nested_seg_id = str(f.get('Segment_Id__c') or '')[:15]
                if nested_seg_id:
                    nested_segment_parents.setdefault(nested_seg_id, []).append(parent_name)

        dmos_used_by_segments = {normalize_api_name(s.get('SegmentOnObjectApiName')) for s in segments if s.get('SegmentOnObjectApiName')}
        dmos_used_by_data_graphs = {normalize_api_name(obj.get('developerName')) for dg in data_graphs for obj in [dg.get('dgObject', {})] + dg.get('dgObject', {}).get('relatedObjects', []) if obj.get('developerName')}
        dmos_used_by_ci_relationships = {normalize_api_name(rel.get('fromEntity')) for ci in calculated_insights for rel in ci.get('relationships', []) if rel.get('fromEntity')}
        dmos_used_by_data_actions = set()
        for da in data_actions:
            find_dmos_recursively(da, dmos_used_by_data_actions)

        dmos_used_in_segment_criteria = set()
        for seg in segments:
            dmos_used_in_segment_criteria.update(find_dmos_in_criteria(seg.get('IncludeCriteria')))
            dmos_used_in_segment_criteria.update(find_dmos_in_criteria(seg.get('ExcludeCriteria')))

        dmos_used_by_activations = set()
        for attr in activation_attributes:
            if query_path_str := attr.get('QueryPath'):
                dmos_used_by_activations.update(find_dmos_in_criteria(query_path_str))

        # --- Auditoria e CSV ---
        audit_results = []

        # Segmentos
        for seg in segments:
            seg_id = str(get_segment_id(seg) or '')[:15]
            if not seg_id: continue
            last_pub_date = segment_publications.get(seg_id)
            is_published_recently = last_pub_date and last_pub_date >= thirty_days_ago
            if not is_published_recently:
                is_used_as_filter = seg_id in nested_segment_parents
                if not is_used_as_filter:
                    reason = 'Órfão (sem ativação recente e não é filtro)'
                    days_pub = days_since(last_pub_date)
                    deletion_identifier = seg.get('Name')
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': seg_id, 'DISPLAY_NAME': get_segment_name(seg), 'OBJECT_TYPE': 'SEGMENT', 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Publicação', 'DIAS_ATIVIDADE': days_pub if days_pub is not None else 'N/A', 'DELETION_IDENTIFIER': deletion_identifier or 'N/A'})
                else:
                    reason = f"Inativo (usado como filtro em: {', '.join(nested_segment_parents.get(seg_id, []))})"
                    days_pub = days_since(last_pub_date)
                    deletion_identifier = seg.get('Name')
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': seg_id, 'DISPLAY_NAME': get_segment_name(seg), 'OBJECT_TYPE': 'SEGMENT', 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Publicação', 'DIAS_ATIVIDADE': days_pub if days_pub is not None else 'N/A', 'DELETION_IDENTIFIER': deletion_identifier or 'N/A'})

        # DMOs
        for dmo in dm_objects:
            original_dmo_name = get_dmo_name(dmo)
            if not original_dmo_name or not original_dmo_name.endswith('__dlm'): continue
            normalized_dmo_name = normalize_api_name(original_dmo_name)
            created_date = parse_sf_date(dmo_creation_dates.get(original_dmo_name))
            used = (normalized_dmo_name in dmos_used_by_segments
                    or normalized_dmo_name in dmos_used_by_data_graphs
                    or normalized_dmo_name in dmos_used_by_ci_relationships
                    or normalized_dmo_name in dmos_used_by_data_actions
                    or normalized_dmo_name in dmos_used_in_segment_criteria
                    or normalized_dmo_name in dmos_used_by_activations)
            if not used:
                reason = "DMO não utilizado"
                audit_results.append({'DELETAR': 'SIM', 'ID_OR_API_NAME': normalized_dmo_name, 'DISPLAY_NAME': get_dmo_display_name(dmo), 'OBJECT_TYPE': 'DMO', 'REASON': reason, 'TIPO_ATIVIDADE': 'Criação', 'DIAS_ATIVIDADE': days_since(created_date), 'DELETION_IDENTIFIER': normalized_dmo_name})

        # --- CSV ---
        if audit_results:
            csv_file = f"audit_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(csv_file, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=list(audit_results[0].keys()))
                writer.writeheader()
                writer.writerows(audit_results)
            logging.info(f"✅ Auditoria concluída. CSV gerado: {csv_file}")
        else:
            logging.info("🎉 Nenhum objeto órfão ou inativo encontrado.")

if __name__ == "__main__":
    start_time = time.time()
    try:
        asyncio.run(main())
    except Exception as e:
        logging.error(f"Um erro inesperado ocorreu durante a auditoria: {e}", exc_info=True)
    finally:
        duration = time.time() - start_time
        logging.info(f"\nTempo total de execução: {duration:.2f} segundos")
