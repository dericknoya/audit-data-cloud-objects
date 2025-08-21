"""
Script de auditoria Salesforce Data Cloud - Objetos órfãos e inativos

Versão: 6.0 (Otimizado por Gemini)
- Otimização massiva: Substitui N+1 chamadas individuais para Segmentos por
  consultas SOQL em massa (bulk), reduzindo drasticamente o tempo de execução.
- Reintegra a lógica de auditoria para Data Streams e Calculated Insights,
  conforme descrito na documentação do script.
- Remove chamadas de API desnecessárias para endpoints não utilizados.
- Melhora a legibilidade e a manutenção do código.

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

Gera CSV final: audit_results_{timestamp}.csv
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
SEGMENT_ID_CHUNK_SIZE = 400 # NOVO: Tamanho do lote para consulta de segmentos em massa

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

def get_segment_id(seg): return seg.get('Id')
def get_segment_name(seg): return seg.get('Name') or '(Sem nome)'
def get_dmo_name(dmo): return dmo.get('name')
def get_dmo_display_name(dmo): return dmo.get('displayName') or dmo.get('name') or '(Sem nome)'

# --- Optimized /jobs/query ---
async def execute_query_job(session, query, semaphore, max_wait=120, poll_interval=3):
    """Executa uma query assíncrona e aguarda os resultados."""
    # NOVO: instance_url foi removido dos argumentos, pois já está no objeto session.
    # A função agora pode ser mais genérica.
    async with semaphore:
        instance_url = str(session._base_url)
        url = f"{instance_url}/services/data/v64.0/jobs/query"
        payload = {"operation": "query", "query": query}
        
        try:
            # Inicia o job
            async with session.post(url, json=payload, proxy=PROXY_URL if USE_PROXY else None, ssl=VERIFY_SSL) as response:
                response.raise_for_status()
                job_info = await response.json()
                job_id = job_info.get('id')
                if not job_id:
                    logging.error(f"❌ JobId não retornado para query: {query[:100]}...")
                    return []

            # Polling para o status do job
            job_status_url = f"{url}/{job_id}"
            elapsed = 0
            while elapsed < max_wait:
                async with session.get(job_status_url, proxy=PROXY_URL if USE_PROXY else None, ssl=VERIFY_SSL) as resp:
                    resp.raise_for_status()
                    status_info = await resp.json()
                    status = status_info.get('state') # Corrigido de 'status' para 'state'
                    
                    if status == 'JobComplete':
                        results_url = f"{job_status_url}/results"
                        all_records = []
                        # Paginação dos resultados
                        while results_url:
                            async with session.get(results_url, proxy=PROXY_URL if USE_PROXY else None, ssl=VERIFY_SSL) as qr:
                                qr.raise_for_status()
                                result_data = await qr.json()
                                all_records.extend(result_data.get('records', []))
                                next_locator = qr.headers.get("Sforce-Locator")
                                results_url = f"{job_status_url}/results?locator={next_locator}" if next_locator and next_locator != "null" else None
                        return all_records
                        
                    elif status in ['Failed', 'Aborted']:
                        logging.error(f"❌ Job de query {job_id} falhou ou foi abortado. Query: {query[:100]}...")
                        return []
                        
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval

            logging.warning(f"⚠️ Timeout atingido para job de query {job_id}.")
            return []
        except aiohttp.ClientError as e:
            logging.error(f"❌ Erro na execução do job de query: {e}")
            return []

# NOVO: Função para buscar detalhes de segmentos em massa
async def fetch_all_segments_in_bulk(session, semaphore, segment_ids):
    """Busca detalhes de múltiplos segmentos usando queries SOQL em lotes."""
    if not segment_ids:
        return []
        
    all_segments = []
    tasks = []
    # Divide os IDs em lotes para não exceder o limite de caracteres da query SOQL
    for i in range(0, len(segment_ids), SEGMENT_ID_CHUNK_SIZE):
        chunk = segment_ids[i:i + SEGMENT_ID_CHUNK_SIZE]
        formatted_ids = "','".join(chunk)
        query = (
            "SELECT Id, Name, SegmentOnObjectApiName, IncludeCriteria, ExcludeCriteria, "
            "FilterDefinition FROM MarketSegment WHERE Id IN ('{}')".format(formatted_ids)
        )
        # Usa a função otimizada de jobs/query que já lida com polling e paginação
        tasks.append(execute_query_job(session, query, semaphore))

    results = await tqdm.gather(*tasks, desc="Buscando detalhes dos Segmentos em massa")
    for record_list in results:
        all_segments.extend(record_list)
    return all_segments


# --- Main Audit Logic ---
async def main():
    auth_data = get_access_token()
    access_token, instance_url = auth_data['access_token'], auth_data['instance_url']
    logging.info('🚀 Iniciando auditoria de exclusão de objetos...')

    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    semaphore = asyncio.Semaphore(50)
    # NOVO: Base URL configurada na sessão para simplificar chamadas
    async with aiohttp.ClientSession(headers=headers, base_url=instance_url, connector=aiohttp.TCPConnector(ssl=VERIFY_SSL)) as session:
        logging.info("--- Etapa 1: Coletando metadados e listas de objetos ---")
        
        dmo_soql_query = "SELECT DeveloperName, CreatedDate FROM MktDataModelObject"
        segment_soql_query = "SELECT Id FROM MarketSegment"
        activation_attributes_query = "SELECT Id, QueryPath, Name, MarketSegmentId, LastPublishDate FROM MktSgmntActvtnAudAttribute" # Adicionado LastPublishDate
        
        initial_tasks = [
            fetch_api_data(session, instance_url, f"/services/data/v64.0/tooling/query?{urlencode({'q': dmo_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, f"/services/data/v64.0/query?{urlencode({'q': segment_soql_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=DataModelObject", semaphore, 'metadata'),
            execute_query_job(session, activation_attributes_query, semaphore),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=CalculatedInsight", semaphore, 'metadata'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/data-streams", semaphore, 'dataStreams'), # REINTEGRADO
            fetch_api_data(session, instance_url, f"/services/data/v64.0/ssot/data-graphs/metadata", semaphore, 'dataGraphMetadata'),
            fetch_api_data(session, instance_url, f"/services/data/v64.0/ssot/data-actions", semaphore, 'dataActions'),
        ]
        results = await tqdm.gather(*initial_tasks, desc="Coletando metadados iniciais")
        # ALTERADO: Desempacotamento atualizado
        dmo_tooling_data, segment_id_records, dm_objects, activation_attributes, calculated_insights, data_streams, data_graphs, data_actions = results
        
        dmo_creation_dates = {rec['DeveloperName']: rec['CreatedDate'] for rec in dmo_tooling_data}
        segment_ids = [rec['Id'] for rec in segment_id_records]
        logging.info(f"✅ Etapa 1.1: {len(dmo_creation_dates)} DMOs, {len(segment_ids)} Segmentos e {len(activation_attributes)} Atributos de Ativação carregados.")

        # ALTERADO: Substitui o loop N+1 pela chamada em massa
        segments = await fetch_all_segments_in_bulk(session, semaphore, segment_ids)
        if not segments:
            logging.warning("⚠️ Nenhum detalhe de segmento foi retornado da busca em massa.")

        # --- Processamento de Auditoria ---
        now = datetime.now(timezone.utc)
        thirty_days_ago = now - timedelta(days=30)
        ninety_days_ago = now - timedelta(days=90)

        # ALTERADO: a query já traz o LastPublishDate do MarketSegmentId, simplificando a lógica
        segment_publications = {str(attr.get('MarketSegmentId') or '')[:15]: parse_sf_date(attr.get('LastPublishDate'))
                                for attr in activation_attributes if attr.get('MarketSegmentId') and attr.get('LastPublishDate')}

        nested_segment_parents = {}
        for seg in segments:
            parent_name = get_segment_name(seg)
            try:
                # O filterDefinition pode ser uma string JSON
                filter_def = json.loads(seg.get('FilterDefinition') or '{}')
                filters = filter_def.get('filters', [])
                for f in filters:
                    nested_seg_id = str(f.get('Segment_Id__c') or '')[:15]
                    if nested_seg_id:
                        nested_segment_parents.setdefault(nested_seg_id, []).append(parent_name)
            except (json.JSONDecodeError, TypeError):
                continue # Pula segmentos com FilterDefinition malformado

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

        # --- Auditoria e Geração de Resultados ---
        audit_results = []
        orphan_segment_ids = set()

        # Auditoria de Segmentos
        logging.info("Auditing Segments...")
        for seg in segments:
            seg_id = str(get_segment_id(seg) or '')[:15]
            if not seg_id: continue

            last_pub_date = segment_publications.get(seg_id)
            is_published_recently = last_pub_date and last_pub_date >= thirty_days_ago
            
            if not is_published_recently:
                is_used_as_filter = seg_id in nested_segment_parents
                days_pub = days_since(last_pub_date)
                deletion_identifier = get_segment_name(seg)
                
                if not is_used_as_filter:
                    reason = 'Órfão (sem publicação recente e não é filtro aninhado)'
                    orphan_segment_ids.add(seg_id) # Marca como órfão para auditoria de Ativações
                    audit_results.append({'DELETAR': 'SIM', 'ID_OR_API_NAME': seg_id, 'DISPLAY_NAME': deletion_identifier, 'OBJECT_TYPE': 'SEGMENT', 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Publicação', 'DIAS_ATIVIDADE': days_pub if days_pub is not None else 'N/A', 'DELETION_IDENTIFIER': deletion_identifier})
                else:
                    reason = f"Inativo (publicação > 30d, usado como filtro em: {', '.join(nested_segment_parents.get(seg_id, []))})"
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': seg_id, 'DISPLAY_NAME': deletion_identifier, 'OBJECT_TYPE': 'SEGMENT', 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Publicação', 'DIAS_ATIVIDADE': days_pub if days_pub is not None else 'N/A', 'DELETION_IDENTIFIER': deletion_identifier})

        # Auditoria de Ativações
        logging.info("Auditing Activations...")
        for act_attr in activation_attributes:
            seg_id = str(act_attr.get('MarketSegmentId') or '')[:15]
            if seg_id in orphan_segment_ids:
                act_id = act_attr.get('Id') # Usando o ID do atributo como referência
                act_name = act_attr.get('Name')
                reason = f'Órfã (associada ao segmento órfão ID: {seg_id})'
                audit_results.append({'DELETAR': 'SIM', 'ID_OR_API_NAME': act_id, 'DISPLAY_NAME': act_name, 'OBJECT_TYPE': 'ACTIVATION', 'REASON': reason, 'TIPO_ATIVIDADE': 'N/A', 'DIAS_ATIVIDADE': 'N/A', 'DELETION_IDENTIFIER': act_name})

        # Auditoria de DMOs
        logging.info("Auditing DMOs...")
        all_used_dmos = (dmos_used_by_segments | dmos_used_by_data_graphs | 
                         dmos_used_by_ci_relationships | dmos_used_by_data_actions | 
                         dmos_used_in_segment_criteria | dmos_used_by_activations)

        for dmo in dm_objects:
            original_dmo_name = get_dmo_name(dmo)
            if not original_dmo_name or not original_dmo_name.endswith('__dlm'): continue
            
            normalized_dmo_name = normalize_api_name(original_dmo_name)
            created_date = parse_sf_date(dmo_creation_dates.get(original_dmo_name))
            
            if normalized_dmo_name not in all_used_dmos:
                is_old = not created_date or created_date < ninety_days_ago
                if is_old:
                    reason = "Órfão (não utilizado em nenhum objeto e criado > 90d)"
                    days_created = days_since(created_date)
                    audit_results.append({'DELETAR': 'SIM', 'ID_OR_API_NAME': original_dmo_name, 'DISPLAY_NAME': get_dmo_display_name(dmo), 'OBJECT_TYPE': 'DMO', 'REASON': reason, 'TIPO_ATIVIDADE': 'Criação', 'DIAS_ATIVIDADE': days_created if days_created is not None else '>90 (Data N/A)', 'DELETION_IDENTIFIER': original_dmo_name})

        # Auditoria de Data Streams (REINTEGRADO)
        logging.info("Auditing Data Streams...")
        for ds in data_streams:
            last_updated = parse_sf_date(ds.get('lastIngestDate'))
            if last_updated and last_updated < thirty_days_ago:
                days_inactive = days_since(last_updated)
                ds_name = ds.get('name')
                ds_id = ds.get('id')
                if not ds.get('mappings'):
                    reason = "Órfão (sem ingestão > 30d e sem mapeamentos)"
                    audit_results.append({'DELETAR': 'SIM', 'ID_OR_API_NAME': ds_id, 'DISPLAY_NAME': ds_name, 'OBJECT_TYPE': 'DATA_STREAM', 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Ingestão', 'DIAS_ATIVIDADE': days_inactive, 'DELETION_IDENTIFIER': ds_name})
                else:
                    reason = "Inativo (sem ingestão > 30d, mas possui mapeamentos)"
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': ds_id, 'DISPLAY_NAME': ds_name, 'OBJECT_TYPE': 'DATA_STREAM', 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Ingestão', 'DIAS_ATIVIDADE': days_inactive, 'DELETION_IDENTIFIER': ds_name})
        
        # Auditoria de Calculated Insights (REINTEGRADO)
        logging.info("Auditing Calculated Insights...")
        for ci in calculated_insights:
            last_processed = parse_sf_date(ci.get('lastSuccessfulProcessingDate'))
            if last_processed and last_processed < ninety_days_ago:
                days_inactive = days_since(last_processed)
                ci_name = ci.get('name')
                reason = "Inativo (último processamento bem-sucedido > 90d)"
                audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': ci_name, 'DISPLAY_NAME': ci.get('displayName'), 'OBJECT_TYPE': 'CALCULATED_INSIGHT', 'REASON': reason, 'TIPO_ATIVIDADE': 'Último Processamento', 'DIAS_ATIVIDADE': days_inactive, 'DELETION_IDENTIFIER': ci_name})


        # --- Gravação do CSV ---
        if audit_results:
            csv_file = f"audit_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(csv_file, mode='w', newline='', encoding='utf-8') as f:
                fieldnames = ['DELETAR', 'ID_OR_API_NAME', 'DISPLAY_NAME', 'OBJECT_TYPE', 'REASON', 'TIPO_ATIVIDADE', 'DIAS_ATIVIDADE', 'DELETION_IDENTIFIER']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
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