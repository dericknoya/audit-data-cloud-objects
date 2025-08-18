"""
Este script audita uma instância do Salesforce Data Cloud para identificar objetos
não utilizados com base em um conjunto de regras.

Version: 5.47 (Fase 1 - Final)
- Aumenta o timeout global das requisições para dar mais tempo para a API
  responder, especialmente em redes com proxies ou para segmentos complexos.
- Mantém a lógica de retry para garantir a resiliência contra falhas de rede
  intermitentes.

Regras de Auditoria:
1. Segmentos:
  - Órfão: Não publicado nos últimos 30 dias E não utilizado como filtro aninhado.
  - Inativo: Última publicação > 30 dias, MAS é utilizado como filtro aninhado.

2. Ativações:
  - Órfã: Associada a um segmento que foi identificado como órfão.

3. Data Model Objects (DMOs):
  - Órfão se: For um DMO customizado, não for utilizado em nenhum Segmento (diretamente, 
    em relacionamentos ou nos critérios de filtro), Data Graph, CI ou Data Action, 
    E (Criado > 90 dias OU Data de Criação desconhecida).

4. Data Streams:
  - Órfão se: A última atualização foi > 30 dias E o array 'mappings' retornado pela API
    estiver vazio.
  - Inativo se: A última atualização foi > 30 dias, MAS o array 'mappings' não está vazio.

5. Calculated Insights (CIs):
  - Inativo se: Último processamento bem-sucedido > 90 dias.

O resultado é salvo em um arquivo CSV chamado 'audit_objetos_para_exclusao.csv'.
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

# --- Configuration ---
CONCURRENCY_LIMIT = 10
USE_PROXY = True
PROXY_URL = "https://felirub:080796@proxynew.itau:8080"
VERIFY_SSL = False
MAX_RETRIES = 3
RETRY_DELAY = 5 # Segundos
TIMEOUT_SECONDS = 300 # Aumentado para 5 minutos

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Authentication ---
def get_access_token():
    """Authenticates with Salesforce using the JWT Bearer Flow."""
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

# --- API Fetching with Production Safeguards ---
async def fetch_api_data(session, semaphore, base_url, relative_url, key_name=None, ignore_404=False):
    """Fetches data from a Data Cloud API endpoint, handling pagination and retries."""
    all_records = []
    current_url = urljoin(base_url, relative_url)
    logging.info(f"Iniciando busca em: {relative_url}")

    for attempt in range(MAX_RETRIES):
        try:
            page_count = 1
            while current_url:
                async with semaphore:
                    kwargs = {'ssl': VERIFY_SSL}
                    if USE_PROXY:
                        kwargs['proxy'] = PROXY_URL
                    
                    async with session.get(current_url, **kwargs) as response:
                        if response.status == 404 and ignore_404:
                            logging.warning(f"⚠️ Endpoint não encontrado (404): {current_url}. O script continuará.")
                            return [] if key_name else {}
                        response.raise_for_status()
                        data = await response.json()
                        
                        if key_name:
                            records_on_page = data.get(key_name, [])
                            all_records.extend(records_on_page)
                            logging.info(f"   Página {page_count}: {len(records_on_page)} registros de '{key_name}' encontrados.")
                        else:
                            return data

                        next_page_url = data.get('nextRecordsUrl') or data.get('nextPageUrl')
                        
                        if next_page_url and not next_page_url.startswith('http'):
                            next_page_url = urljoin(base_url, next_page_url)

                        if current_url == next_page_url: break
                        current_url = next_page_url
                        page_count += 1
            return all_records # Success
        except aiohttp.ClientError as e:
            logging.warning(f"⚠️ Tentativa {attempt + 1}/{MAX_RETRIES} falhou para {current_url}: {e}")
            if attempt + 1 == MAX_RETRIES:
                logging.error(f"❌ Todas as {MAX_RETRIES} tentativas falharam para {current_url}.")
                return [] if key_name else {}
            await asyncio.sleep(RETRY_DELAY)

async def fetch_single_record(session, semaphore, url):
    """Fetches a single record from a specific URL with retries."""
    for attempt in range(MAX_RETRIES):
        try:
            async with semaphore:
                async with session.get(url, proxy=PROXY_URL if USE_PROXY else None, ssl=VERIFY_SSL) as response:
                    if response.status == 404:
                        logging.warning(f"⚠️ Record not found (404): {url}")
                        return None
                    response.raise_for_status()
                    return await response.json()
        except aiohttp.ClientError as e:
            logging.warning(f"⚠️ Tentativa {attempt + 1}/{MAX_RETRIES} falhou para {url}: {e}")
            if attempt + 1 == MAX_RETRIES:
                logging.error(f"❌ Todas as {MAX_RETRIES} tentativas falharam para {url}.")
                return None
            await asyncio.sleep(RETRY_DELAY)

async def fetch_tooling_api_query(session, semaphore, base_url, soql_query, object_name=""):
    """Fetches data from the Tooling API using a SOQL query with retries."""
    params = {'q': soql_query}
    url = f"{base_url}/services/data/v64.0/tooling/query?{urlencode(params)}"
    logging.info(f"🔎 Querying Tooling API for {object_name}...")
    for attempt in range(MAX_RETRIES):
        try:
            async with semaphore:
                async with session.get(url, proxy=PROXY_URL if USE_PROXY else None, ssl=VERIFY_SSL) as response:
                    response.raise_for_status()
                    data = await response.json()
                    logging.info(f"✅ Found {data.get('size', 0)} {object_name} records in Tooling API.")
                    return data.get('records', [])
        except aiohttp.ClientError as e:
            logging.warning(f"⚠️ Tentativa {attempt + 1}/{MAX_RETRIES} falhou para Tooling API query: {e}")
            if attempt + 1 == MAX_RETRIES:
                logging.error(f"❌ Todas as {MAX_RETRIES} tentativas falharam para a query da Tooling API.")
                return []
            await asyncio.sleep(RETRY_DELAY)

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

def find_dmos_in_criteria(criteria_str):
    if not criteria_str: return set()
    try:
        decoded_str = html.unescape(criteria_str)
        criteria_json = json.loads(decoded_str)
    except (json.JSONDecodeError, TypeError): return set()
    dmos_found = set()
    def recursive_search(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == 'objectApiName' and isinstance(value, str):
                    dmos_found.add(normalize_api_name(value))
                elif isinstance(value, (dict, list)):
                    recursive_search(value)
        elif isinstance(obj, list):
            for item in obj:
                recursive_search(item)
    recursive_search(criteria_json)
    return dmos_found

def get_segment_id(seg): return seg.get('marketSegmentId') or seg.get('Id')
def get_segment_name(seg): return seg.get('displayName') or seg.get('Name') or '(Sem nome)'
def get_dmo_name(dmo): return dmo.get('name')
def get_dmo_display_name(dmo): return dmo.get('displayName') or dmo.get('name') or '(Sem nome)'

# --- Main Audit Logic ---
async def main():
    auth_data = get_access_token()
    access_token, instance_url = auth_data['access_token'], auth_data['instance_url']
    logging.info('🚀 Iniciando auditoria de exclusão de objetos...')

    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
    connector = aiohttp.TCPConnector(ssl=VERIFY_SSL)
    async with aiohttp.ClientSession(headers=headers, connector=connector, timeout=timeout) as session:
        soql_query = "SELECT Id FROM MarketSegment"
        encoded_soql = urlencode({'q': soql_query})
        soql_url = f"/services/data/v64.0/query?{encoded_soql}"
        segment_id_records = await fetch_api_data(session, semaphore, instance_url, soql_url, 'records')
        segment_ids = [rec['Id'] for rec in segment_id_records]
        logging.info(f"✅ Etapa 1.1: {len(segment_ids)} IDs de segmentos encontrados via SOQL.")

        segment_detail_tasks = [fetch_api_data(session, semaphore, instance_url, f"/services/data/v64.0/sobjects/MarketSegment/{seg_id}") for seg_id in segment_ids]
        
        other_tasks = [
            fetch_api_data(session, semaphore, instance_url, f"/services/data/v64.0/ssot/activations", 'activations'),
            fetch_api_data(session, semaphore, instance_url, f"/services/data/v64.0/ssot/data-streams", 'dataStreams'),
            fetch_api_data(session, semaphore, instance_url, f"/services/data/v64.0/ssot/data-graphs/metadata", 'dataGraphMetadata'),
            fetch_api_data(session, semaphore, instance_url, f"/services/data/v64.0/ssot/metadata?entityType=DataModelObject", 'metadata'),
            fetch_api_data(session, semaphore, instance_url, f"/services/data/v64.0/ssot/metadata?entityType=CalculatedInsight", 'metadata'),
            fetch_tooling_api_query(session, semaphore, instance_url, "SELECT DeveloperName, CreatedDate FROM MktDataModelObject", "DMOs"),
            fetch_api_data(session, semaphore, instance_url, f"/services/data/v64.0/ssot/data-actions", 'dataActions'),
        ]
        
        results = await asyncio.gather(*(segment_detail_tasks + other_tasks))
        
        segments = [res for res in results[:len(segment_detail_tasks)] if res]
        activations, data_streams_summary, data_graphs, dm_objects, calculated_insights, dmo_tooling_data, data_actions = results[len(segment_detail_tasks):]
        
        logging.info(f"✅ Etapa 1.2: {len(segments)} detalhes de segmentos obtidos.")

        logging.info(f"🔎 Fetching detailed information for {len(data_streams_summary)} data streams to check mappings...")
        ds_detail_tasks = []
        for ds in data_streams_summary:
            ds_name = ds.get('name')
            if ds_name:
                url = f"{instance_url}/services/data/v64.0/ssot/data-streams/{ds_name}?includeMappings=true"
                ds_detail_tasks.append(fetch_single_record(session, semaphore, url))
        
        data_streams = await asyncio.gather(*ds_detail_tasks)
        data_streams = [ds for ds in data_streams if ds is not None]

    logging.info("📊 Data fetched. Analyzing dependencies...")
    
    now = datetime.now(timezone.utc)
    thirty_days_ago = now - timedelta(days=30)
    ninety_days_ago = now - timedelta(days=90)

    segment_publications = {str(act.get('segmentId') or '')[:15]: parse_sf_date(act.get('lastPublishDate')) for act in activations if act.get('segmentId') and act.get('lastPublishDate')}
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
        for source in da.get('dataActionSources', []):
            if source.get('objectDevName'): dmos_used_by_data_actions.add(normalize_api_name(source.get('objectDevName')))
        for condition in da.get('actionConditions', []):
            if condition.get('objectName'): dmos_used_by_data_actions.add(normalize_api_name(condition.get('objectName')))
        for enrichment in da.get('dataActionEnrichmentProperties', []):
            for field in enrichment.get('dataActionProjectedFields', []):
                if field.get('objectApiName'): dmos_used_by_data_actions.add(normalize_api_name(field.get('objectApiName')))
            for edge in enrichment.get('dataActionRelationshipEdges', []):
                if edge.get('sourceObjectApiName'): dmos_used_by_data_actions.add(normalize_api_name(edge.get('sourceObjectApiName')))
                if edge.get('targetObjectApiName'): dmos_used_by_data_actions.add(normalize_api_name(edge.get('targetObjectApiName')))

    dmos_used_in_segment_criteria = set()
    for seg in segments:
        dmos_used_in_segment_criteria.update(find_dmos_in_criteria(seg.get('IncludeCriteria')))
        dmos_used_in_segment_criteria.update(find_dmos_in_criteria(seg.get('ExcludeCriteria')))

    dmo_creation_dates = {normalize_api_name(dmo.get('DeveloperName')): parse_sf_date(dmo.get('CreatedDate')) for dmo in dmo_tooling_data}
    
    audit_results = []

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
                deletion_identifier = seg.get('DeveloperName')
                if not deletion_identifier:
                    logging.warning(f"Não foi possível encontrar o 'DeveloperName' para o segmento {get_segment_name(seg)} (ID: {seg_id}).")
                audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': seg_id, 'DISPLAY_NAME': get_segment_name(seg), 'OBJECT_TYPE': 'SEGMENT', 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Publicação', 'DIAS_ATIVIDADE': days_pub if days_pub is not None else 'N/A', 'DELETION_IDENTIFIER': deletion_identifier or 'N/A'})
                for act in activations:
                    if str(act.get('segmentId') or '')[:15] == seg_id:
                        act_id = act.get('id')
                        act_name = act.get('name')
                        act_reason = f"Órfã (associada ao segmento órfão: '{get_segment_name(seg)}')"
                        audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': act_id, 'DISPLAY_NAME': act_name, 'OBJECT_TYPE': 'ACTIVATION', 'REASON': act_reason, 'TIPO_ATIVIDADE': 'N/A', 'DIAS_ATIVIDADE': 'N/A', 'DELETION_IDENTIFIER': act_id})
            else:
                reason = f"Inativo (usado como filtro em: {', '.join(nested_segment_parents.get(seg_id, []))})"
                days_pub = days_since(last_pub_date)
                deletion_identifier = seg.get('DeveloperName')
                audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': seg_id, 'DISPLAY_NAME': get_segment_name(seg), 'OBJECT_TYPE': 'SEGMENT', 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Publicação', 'DIAS_ATIVIDADE': days_pub if days_pub is not None else 'N/A', 'DELETION_IDENTIFIER': deletion_identifier or 'N/A'})

    for dmo in dm_objects:
        original_dmo_name = get_dmo_name(dmo)
        if not original_dmo_name or not original_dmo_name.endswith('__dlm'): continue
        normalized_dmo_name = normalize_api_name(original_dmo_name)
        is_unused = (normalized_dmo_name not in dmos_used_by_segments and 
                     normalized_dmo_name not in dmos_used_by_ci_relationships and 
                     normalized_dmo_name not in dmos_used_by_data_graphs and
                     normalized_dmo_name not in dmos_used_by_data_actions and
                     normalized_dmo_name not in dmos_used_in_segment_criteria)
        if is_unused:
            created_date = dmo_creation_dates.get(normalized_dmo_name)
            days_creation = days_since(created_date)
            if (days_creation is not None and days_creation > 90) or created_date is None:
                reason = 'Órfão (sem uso e criado > 90 dias)' if created_date else 'Órfão (sem uso, data de criação desconhecida)'
                audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': original_dmo_name, 'DISPLAY_NAME': get_dmo_display_name(dmo), 'OBJECT_TYPE': 'DATA MODEL', 'REASON': reason, 'TIPO_ATIVIDADE': 'Criação', 'DIAS_ATIVIDADE': days_creation if days_creation is not None else 'N/A', 'DELETION_IDENTIFIER': original_dmo_name})

    for ds in data_streams:
        ds_name = ds['name']
        refreshed_date = parse_sf_date(ds.get('lastRefreshDate'))
        is_stale = not refreshed_date or refreshed_date < thirty_days_ago
        if not is_stale: continue
        has_mapping = bool(ds.get('mappings'))
        days_since_refresh = days_since(refreshed_date)
        if not has_mapping:
            reason = 'Órfão (sem mapeamento para DMO e não atualizado > 30 dias)'
            audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': ds_name, 'DISPLAY_NAME': ds.get('displayName') or ds_name, 'OBJECT_TYPE': 'DATA STREAM', 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Atualização', 'DIAS_ATIVIDADE': days_since_refresh if refreshed_date else 'N/A', 'DELETION_IDENTIFIER': ds_name})
        else:
            reason = "Inativo (não atualizado > 30 dias, mas possui mapeamento para DMO)"
            audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': ds_name, 'DISPLAY_NAME': ds.get('displayName') or ds_name, 'OBJECT_TYPE': 'DATA STREAM', 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Atualização', 'DIAS_ATIVIDADE': days_since_refresh if refreshed_date else 'N/A', 'DELETION_IDENTIFIER': ds_name})

    for ci in calculated_insights:
        last_processed_date = parse_sf_date(ci.get('latestSuccessfulProcessTime'))
        days_processed = days_since(last_processed_date)
        if days_processed is not None and days_processed > 90:
            audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': ci['name'], 'DISPLAY_NAME': ci.get('displayName') or ci['name'], 'OBJECT_TYPE': 'CALCULATED INSIGHT', 'REASON': 'Inativo (não processado com sucesso > 90 dias)', 'TIPO_ATIVIDADE': 'Último Processamento', 'DIAS_ATIVIDADE': days_processed, 'DELETION_IDENTIFIER': ci['name']})
            
    if not audit_results:
        logging.info("🎉 Nenhum objeto órfão ou inativo encontrado.")
        return

    csv_file_path = 'audit_objetos_para_exclusao.csv'
    header = ['DELETAR', 'ID_OR_API_NAME', 'DISPLAY_NAME', 'OBJECT_TYPE', 'REASON', 'TIPO_ATIVIDADE', 'DIAS_ATIVIDADE', 'DELETION_IDENTIFIER']
    
    try:
        with open(csv_file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()
            writer.writerows(audit_results)
        logging.info(f"✅ Auditoria finalizada. {len(audit_results)} objetos encontrados. Arquivo CSV gerado: {csv_file_path}")
    except IOError as e:
        logging.error(f"❌ Erro ao gravar o arquivo CSV: {e}")

if __name__ == "__main__":
    start_time = time.time()
    try:
        asyncio.run(main())
    except Exception as e:
        logging.error(f"Um erro inesperado ocorreu durante a auditoria: {e}", exc_info=True)
    finally:
        end_time = time.time()
        duration = end_time - start_time
        logging.info(f"\nTempo total de execução: {duration:.2f} segundos")
