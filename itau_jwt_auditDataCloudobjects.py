"""
Script de auditoria Salesforce Data Cloud - Objetos órfãos e inativos

Versão: 9.4 (Produção Final)
- Consolida todas as correções de API e lógica de dados desenvolvidas.
- Reintegra a auditoria completa para DMOs, Data Streams e Calculated Insights,
  além de Segmentos e Ativações.
- O script agora está totalmente alinhado com o schema de dados da organização
  e deve executar de forma estável para produzir o relatório de auditoria completo.

Regras de Auditoria:
1. Segmentos:
  - Órfão: Última atividade > 30 dias E não utilizado como filtro aninhado.
  - Inativo: Última atividade > 30 dias, MAS é utilizado como filtro aninhado.
2. Ativações:
  - Órfã: Associada a um segmento que foi identificado como órfão.
3. Data Model Objects (DMOs):
  - Órfão se: For um DMO customizado, não for utilizado em nenhum Segmento, Ativação
    (incluindo seus atributos), Data Graph, CI ou Data Action, E (Criado > 90 dias
    OU Data de Criação desconhecida).
4. Data Streams:
  - Órfão se: A última atualização foi > 30 dias E o array 'mappings' estiver vazio.
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
import gzip
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
CHUNK_SIZE = 400

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Funções de Autenticação, API, e Helpers ---
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
    payload = {'iss': sf_client_id, 'sub': sf_username, 'aud': sf_audience, 'exp': int(time.time()) + 300}
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

async def fetch_api_data(session, relative_url, semaphore, key_name=None):
    async with semaphore:
        all_records = []
        current_url = relative_url
        try:
            while current_url:
                kwargs = {'ssl': VERIFY_SSL}
                if USE_PROXY: kwargs['proxy'] = PROXY_URL
                async with session.get(current_url, **kwargs) as response:
                    response.raise_for_status()
                    data = await response.json()
                    if key_name:
                        all_records.extend(data.get(key_name, []))
                        next_page_url = data.get('nextRecordsUrl') or data.get('nextPageUrl')
                        if next_page_url and next_page_url.startswith('http'):
                            base_host = str(session._base_url)
                            current_url = urljoin(base_host, next_page_url)
                        else:
                            current_url = next_page_url
                    else: 
                        return data
            return all_records
        except aiohttp.ClientError as e:
            logging.error(f"❌ Error fetching {current_url}: {e}")
            return [] if key_name else {}

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
        if isinstance(criteria_str, (dict, list)):
            criteria_json = criteria_str
        else:
            decoded_str = html.unescape(str(criteria_str))
            criteria_json = json.loads(decoded_str)
        
        def recurse(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key == key_to_find and isinstance(value, str):
                        if key in ['objectName', 'entityName', 'developerName'] and value.endswith('__dlm'):
                            item_set.add(normalize_api_name(value))
                        elif key == 'segmentId':
                            item_set.add(str(value)[:15])
                    elif isinstance(value, (dict, list)):
                        recurse(value)
            elif isinstance(obj, list):
                for item in obj:
                    recurse(item)
        
        recurse(criteria_json)
    except (json.JSONDecodeError, TypeError): return

def get_segment_id(seg): return seg.get('Id')
def get_segment_name(seg): return seg.get('Name') or '(Sem nome)'
def get_dmo_display_name(dmo): return dmo.get('displayName') or dmo.get('name') or '(Sem nome)'

async def execute_query_job(session, query, semaphore):
    async with semaphore:
        job_url_path = "/services/data/v64.0/jobs/query"
        payload = {"operation": "query", "query": query, "contentType": "CSV"}
        try:
            async with session.post(job_url_path, data=json.dumps(payload), proxy=PROXY_URL if USE_PROXY else None, ssl=VERIFY_SSL) as response:
                response.raise_for_status()
                job_info = await response.json()
                job_id = job_info.get('id')
                if not job_id:
                    logging.error(f"❌ JobId não retornado para query: {query[:100]}...")
                    return []
            job_status_path = f"{job_url_path}/{job_id}"
            while True:
                await asyncio.sleep(5)
                async with session.get(job_status_path, proxy=PROXY_URL if USE_PROXY else None, ssl=VERIFY_SSL) as resp:
                    resp.raise_for_status()
                    status_info = await resp.json()
                    state = status_info.get('state')
                    logging.info(f"⏳ Status do Job {job_id}: {state}")
                    if state == 'JobComplete': break
                    if state in ['Failed', 'Aborted']:
                        logging.error(f"❌ Job de query {job_id} falhou: {status_info.get('errorMessage')}")
                        return []
            results_path = f"{job_status_path}/results"
            results_headers = {'Accept-Encoding': 'gzip'}
            async with session.get(results_path, headers=results_headers, proxy=PROXY_URL if USE_PROXY else None, ssl=VERIFY_SSL) as qr:
                qr.raise_for_status()
                content_bytes = await qr.read()
                if qr.headers.get('Content-Encoding') == 'gzip':
                    csv_text = gzip.decompress(content_bytes).decode('utf-8')
                else:
                    csv_text = content_bytes.decode('utf-8')
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
            logging.error(f"❌ Erro na execução do job de query: status={getattr(e, 'status', 'N/A')}, message='{e}', response='{error_text}'")
            return []

async def fetch_records_in_bulk(session, semaphore, object_name, fields, record_ids):
    if not record_ids: return []
    all_records = []
    tasks = []
    field_str = ", ".join(fields)
    for i in range(0, len(record_ids), CHUNK_SIZE):
        chunk = record_ids[i:i + CHUNK_SIZE]
        formatted_ids = "','".join(chunk)
        query = f"SELECT {field_str} FROM {object_name} WHERE Id IN ('{formatted_ids}')"
        tasks.append(execute_query_job(session, query, semaphore))
    results = await tqdm.gather(*tasks, desc=f"Buscando detalhes de {object_name} em massa")
    for record_list in results:
        all_records.extend(record_list)
    return all_records

# --- Main Audit Logic ---
async def main():
    auth_data = get_access_token()
    access_token, instance_url = auth_data['access_token'], auth_data['instance_url']
    logging.info('🚀 Iniciando auditoria de exclusão de objetos...')

    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json', 'Accept': 'application/json'}
    semaphore = asyncio.Semaphore(10)
    async with aiohttp.ClientSession(headers=headers, base_url=instance_url, connector=aiohttp.TCPConnector(ssl=VERIFY_SSL)) as session:
        logging.info("--- Etapa 1: Coletando metadados e listas de objetos ---")
        
        dmo_soql_query = "SELECT DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject"
        segment_soql_query = "SELECT Id FROM MarketSegment"
        activation_attributes_query = "SELECT Id, QueryPath, Name, MarketSegmentActivationId, CreatedById FROM MktSgmntActvtnAudAttribute"
        
        initial_tasks = [
            fetch_api_data(session, f"/services/data/v64.0/tooling/query?{urlencode({'q': dmo_soql_query})}", semaphore, 'records'),
            execute_query_job(session, segment_soql_query, semaphore),
            fetch_api_data(session, "/services/data/v64.0/ssot/metadata?entityType=DataModelObject", semaphore, 'metadata'),
            execute_query_job(session, activation_attributes_query, semaphore),
            fetch_api_data(session, "/services/data/v64.0/ssot/metadata?entityType=CalculatedInsight", semaphore, 'metadata'),
            fetch_api_data(session, "/services/data/v64.0/ssot/data-streams", semaphore, 'dataStreams'),
            fetch_api_data(session, f"/services/data/v64.0/ssot/data-graphs/metadata", semaphore, 'dataGraphMetadata'),
            fetch_api_data(session, f"/services/data/v64.0/ssot/data-actions", semaphore, 'dataActions'),
        ]
        results = await tqdm.gather(*initial_tasks, desc="Coletando metadados iniciais")
        logging.info("✅ Coleta inicial de metadados concluída.")
        dmo_tooling_data, segment_id_records, dm_objects, activation_attributes, calculated_insights, data_streams, data_graphs, data_actions = results
        
        dmo_creation_dates = {rec['DeveloperName']: rec['CreatedDate'] for rec in dmo_tooling_data if rec.get('DeveloperName')}
        segment_ids = [rec['Id'] for rec in segment_id_records if rec.get('Id')]
        logging.info(f"✅ Etapa 1.1: {len(dmo_creation_dates)} DMOs, {len(segment_ids)} Segmentos e {len(activation_attributes)} Atributos de Ativação carregados.")

        activation_ids = list(set(attr['MarketSegmentActivationId'] for attr in activation_attributes if attr.get('MarketSegmentActivationId')))
        
        logging.info(f"--- Etapa 2: Buscando detalhes de {len(activation_ids)} ativações únicas... ---")
        activation_fields_to_query = ["Id", "MarketSegmentId", "LastModifiedDate", "CreatedById"]
        activation_details = await fetch_records_in_bulk(session, semaphore, "MarketSegmentActivation", activation_fields_to_query, activation_ids)
        logging.info("✅ Detalhes de ativação coletados.")

        segment_publications = {
            str(act.get('MarketSegmentId') or '')[:15]: parse_sf_date(act.get('LastModifiedDate'))
            for act in activation_details if act.get('MarketSegmentId') and act.get('LastModifiedDate')
        }

        logging.info(f"--- Etapa 3: Buscando detalhes de {len(segment_ids)} segmentos... ---")
        segment_fields_to_query = ["Id", "Name", "SegmentMembershipTable", "IncludeCriteria", "ExcludeCriteria", "SegmentStatus", "CreatedById"]
        segments = await fetch_records_in_bulk(session, semaphore, "MarketSegment", segment_fields_to_query, segment_ids)
        logging.info("✅ Detalhes de segmento coletados. Iniciando busca por nomes de criadores...")

        all_creator_ids = set()
        for collection in [dmo_tooling_data, activation_attributes, activation_details, segments, calculated_insights, data_streams]:
            for item in collection:
                if creator_id := item.get('CreatedById') or item.get('createdById'):
                    all_creator_ids.add(creator_id)
        
        user_id_to_name_map = {}
        if all_creator_ids:
            logging.info(f"--- Etapa 4: Buscando nomes de {len(all_creator_ids)} criadores... ---")
            user_records = await fetch_records_in_bulk(session, semaphore, "User", ["Id", "Username"], list(all_creator_ids))
            user_id_to_name_map = {user['Id']: user['Username'] for user in user_records}
            logging.info("✅ Nomes de criadores coletados.")

        now = datetime.now(timezone.utc)
        thirty_days_ago = now - timedelta(days=30)
        ninety_days_ago = now - timedelta(days=90)
        
        dmos_used_by_segments = {normalize_api_name(s.get('SegmentMembershipTable')) for s in segments if s.get('SegmentMembershipTable')}
        dmos_used_by_data_graphs = {normalize_api_name(obj.get('developerName')) for dg in data_graphs for obj in [dg.get('dgObject', {})] + dg.get('dgObject', {}).get('relatedObjects', []) if obj.get('developerName')}
        dmos_used_by_ci_relationships = {normalize_api_name(rel.get('fromEntity')) for ci in calculated_insights for rel in ci.get('relationships', []) if rel.get('fromEntity')}
        
        dmos_used_in_activations = set()
        for attr in activation_attributes:
            find_items_in_criteria(attr.get('QueryPath'), 'developerName', dmos_used_in_activations)
            
        dmos_used_in_data_actions = set()
        for da in data_actions:
            find_items_in_criteria(da, 'developerName', dmos_used_in_data_actions)
            
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
            seg_id = str(get_segment_id(seg) or '')[:15]
            if not seg_id: continue
            
            last_pub_date = segment_publications.get(seg_id)
            is_published_recently = last_pub_date and last_pub_date >= thirty_days_ago
            
            if not is_published_recently:
                is_used_as_filter = seg_id in nested_segment_parents
                days_since_pub = days_since(last_pub_date)
                seg_name = get_segment_name(seg)
                creator_name = user_id_to_name_map.get(seg.get('CreatedById'), 'Desconhecido')
                
                if not is_used_as_filter:
                    deletable_segment_ids.add(seg_id)
                    reason = 'Inativo (sem atividade recente e não é filtro aninhado)'
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': seg_id, 'DISPLAY_NAME': seg_name, 'OBJECT_TYPE': 'SEGMENT', 'STATUS': seg.get('SegmentStatus', 'N/A'), 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Atividade', 'DIAS_ATIVIDADE': days_since_pub if days_since_pub is not None else 'N/A', 'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': seg_name})
                else:
                    reason = f"Inativo (sem atividade recente, mas usado como filtro em: {', '.join(nested_segment_parents.get(seg_id, []))})"
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': seg_id, 'DISPLAY_NAME': seg_name, 'OBJECT_TYPE': 'SEGMENT', 'STATUS': seg.get('SegmentStatus', 'N/A'), 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Atividade', 'DIAS_ATIVIDADE': days_since_pub if days_since_pub is not None else 'N/A', 'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': seg_name})

        logging.info("Auditando Ativações...")
        for act_detail in activation_details:
            seg_id = str(act_detail.get('MarketSegmentId') or '')[:15]
            if seg_id in deletable_segment_ids:
                act_id = act_detail.get('Id')
                act_name = next((attr.get('Name') for attr in activation_attributes if attr.get('MarketSegmentActivationId') == act_id), 'Nome não encontrado')
                creator_name = user_id_to_name_map.get(act_detail.get('CreatedById'), 'Desconhecido')
                reason = f'Órfã (associada a segmento inativo e sem vínculos: {seg_id})'
                audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': act_id, 'DISPLAY_NAME': act_name, 'OBJECT_TYPE': 'ACTIVATION', 'STATUS': 'N/A', 'REASON': reason, 'TIPO_ATIVIDADE': 'N/A', 'DIAS_ATIVIDADE': 'N/A', 'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': act_name})

        logging.info("Auditando Data Model Objects (DMOs)...")
        dmo_creators = {rec['DeveloperName']: rec.get('CreatedById') for rec in dmo_tooling_data}
        all_used_dmos = (dmos_used_by_segments | dmos_used_by_data_graphs | dmos_used_by_ci_relationships | 
                         dmos_used_in_activations | dmos_used_in_data_actions | dmos_used_in_segment_criteria)
        for dmo in dm_objects:
            dmo_name = dmo.get('name', '')
            if not dmo_name.endswith('__dlm'): continue
            
            normalized_dmo_name = normalize_api_name(dmo_name)
            if normalized_dmo_name not in all_used_dmos:
                created_date = parse_sf_date(dmo_creation_dates.get(dmo_name))
                if not created_date or created_date < ninety_days_ago:
                    days_created = days_since(created_date)
                    reason = "Órfão (não utilizado em nenhum objeto e criado > 90d)"
                    display_name = get_dmo_display_name(dmo)
                    creator_id = dmo_creators.get(dmo_name)
                    creator_name = user_id_to_name_map.get(creator_id, 'Desconhecido')
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': dmo_name, 'DISPLAY_NAME': display_name, 'OBJECT_TYPE': 'DMO', 'STATUS': 'N/A', 'REASON': reason, 'TIPO_ATIVIDADE': 'Criação', 'DIAS_ATIVIDADE': days_created if days_created is not None else '>90', 'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': dmo_name})

        logging.info("Auditando Data Streams...")
        for ds in data_streams:
            last_updated = parse_sf_date(ds.get('lastIngestDate'))
            if not last_updated or last_updated < thirty_days_ago:
                days_inactive = days_since(last_updated)
                ds_name = ds.get('name')
                ds_id = ds.get('id')
                creator_name = user_id_to_name_map.get(ds.get('createdById'), 'Desconhecido')
                
                if not ds.get('mappings'):
                    reason = "Inativo (sem ingestão > 30d e sem mapeamentos)"
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': ds_id, 'DISPLAY_NAME': ds_name, 'OBJECT_TYPE': 'DATA_STREAM', 'STATUS': 'N/A', 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Ingestão', 'DIAS_ATIVIDADE': days_inactive if days_inactive is not None else '>30', 'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': ds_name})
                else:
                    reason = "Inativo (sem ingestão > 30d, mas possui mapeamentos)"
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': ds_id, 'DISPLAY_NAME': ds_name, 'OBJECT_TYPE': 'DATA_STREAM', 'STATUS': 'N/A', 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Ingestão', 'DIAS_ATIVIDADE': days_inactive if days_inactive is not None else '>30', 'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': ds_name})
        
        logging.info("Auditando Calculated Insights...")
        for ci in calculated_insights:
            last_processed = parse_sf_date(ci.get('lastSuccessfulProcessingDate'))
            if not last_processed or last_processed < ninety_days_ago:
                days_inactive = days_since(last_processed)
                ci_name = ci.get('name')
                reason = "Inativo (último processamento bem-sucedido > 90d)"
                creator_name = user_id_to_name_map.get(ci.get('createdById'), 'Desconhecido')
                audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': ci_name, 'DISPLAY_NAME': ci.get('displayName'), 'OBJECT_TYPE': 'CALCULATED_INSIGHT', 'STATUS': 'N/A', 'REASON': reason, 'TIPO_ATIVIDADE': 'Último Processamento', 'DIAS_ATIVIDADE': days_inactive if days_inactive is not None else '>90', 'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': ci_name})

        if audit_results:
            csv_file = f"audit_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(csv_file, mode='w', newline='', encoding='utf-8') as f:
                fieldnames = ['DELETAR', 'ID_OR_API_NAME', 'DISPLAY_NAME', 'OBJECT_TYPE', 'STATUS', 'REASON', 'TIPO_ATIVIDADE', 'DIAS_ATIVIDADE', 'CREATED_BY_NAME', 'DELETION_IDENTIFIER']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(audit_results)
            logging.info(f"✅ Auditoria concluída. CSV gerado: {csv_file}")
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