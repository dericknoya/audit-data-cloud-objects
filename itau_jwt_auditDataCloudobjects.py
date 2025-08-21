"""
Script de auditoria Salesforce Data Cloud - Objetos órfãos e inativos

Versão: 7.1 (Otimizado por Gemini)
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
""""""
Script de auditoria Salesforce Data Cloud - Objetos órfãos e inativos

Versão: 7.1 (Final com SOQL Corrigida)
- CORREÇÃO DE SOQL: Ajusta as queries para buscar os dados de ativação em duas etapas,
  refletindo o modelo de dados correto. Primeiro, busca os IDs de MarketSegmentActivation
  em MktSgmntActvtnAudAttribute e, em seguida, usa esses IDs para obter MarketSegmentId
  e LastPublishDate do objeto MarketSegmentActivation. Isso resolve o último erro 400.
- Mantém todas as otimizações e correções de API anteriores.

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
CHUNK_SIZE = 400 # Renomeado para clareza

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Authentication (sem alterações) ---
def get_access_token():
    # ... (código de autenticação inalterado) ...
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

# --- API Fetching (sem alterações) ---
async def fetch_api_data(session, relative_url, semaphore, key_name=None):
    # ... (código inalterado) ...
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

# --- Helper Functions (sem alterações) ---
def parse_sf_date(date_str):
    if not date_str: return None
    try:
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except (ValueError, TypeError): return None
# ... (demais funções helper inalteradas) ...
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

# --- Optimized /jobs/query (Bulk API 2.0) (sem alterações) ---
async def execute_query_job(session, query, semaphore):
    # ... (código da função inalterado) ...
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
                        logging.error(f"❌ Job de query {job_id} falhou ou foi abortado. Mensagem: {status_info.get('errorMessage')}")
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

# --- Funções de busca em massa ---
async def fetch_records_in_bulk(session, semaphore, object_name, fields, record_ids):
    """Função genérica para buscar registros em massa usando SOQL e a Bulk API."""
    if not record_ids:
        return []
    
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

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    
    semaphore = asyncio.Semaphore(10)
    async with aiohttp.ClientSession(headers=headers, base_url=instance_url, connector=aiohttp.TCPConnector(ssl=VERIFY_SSL)) as session:
        logging.info("--- Etapa 1: Coletando metadados e listas de objetos ---")
        
        dmo_soql_query = "SELECT DeveloperName, CreatedDate FROM MktDataModelObject"
        segment_soql_query = "SELECT Id FROM MarketSegment"
        # ALTERAÇÃO CRÍTICA: Corrigida a query para buscar apenas os campos existentes.
        activation_attributes_query = "SELECT Id, QueryPath, Name, MarketSegmentActivationId FROM MktSgmntActvtnAudAttribute"
        
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
        dmo_tooling_data, segment_id_records, dm_objects, activation_attributes, calculated_insights, data_streams, data_graphs, data_actions = results
        
        dmo_creation_dates = {rec['DeveloperName']: rec['CreatedDate'] for rec in dmo_tooling_data}
        segment_ids = [rec['Id'] for rec in segment_id_records]
        logging.info(f"✅ Etapa 1.1: {len(dmo_creation_dates)} DMOs, {len(segment_ids)} Segmentos e {len(activation_attributes)} Atributos de Ativação carregados.")

        # ALTERAÇÃO CRÍTICA: Lógica de 2 etapas para obter as datas de publicação
        # 1. Extrair os IDs das Ativações a partir dos atributos coletados
        activation_ids = list(set(
            attr['MarketSegmentActivationId'] for attr in activation_attributes if attr.get('MarketSegmentActivationId')
        ))
        
        # 2. Buscar os detalhes dessas ativações (o objeto correto) em massa
        logging.info(f"Encontradas {len(activation_ids)} ativações únicas para detalhar.")
        activation_details = await fetch_records_in_bulk(
            session, semaphore, 
            object_name="MarketSegmentActivation", 
            fields=["MarketSegmentId", "LastPublishDate"], 
            record_ids=activation_ids
        )

        # 3. Montar o dicionário final para a auditoria de segmentos
        segment_publications = {
            str(act.get('MarketSegmentId') or '')[:15]: parse_sf_date(act.get('LastPublishDate'))
            for act in activation_details if act.get('MarketSegmentId') and act.get('LastPublishDate')
        }

        # Busca os detalhes dos segmentos em massa
        segments = await fetch_records_in_bulk(
            session, semaphore,
            object_name="MarketSegment",
            fields=["Id", "Name", "SegmentOnObjectApiName", "IncludeCriteria", "ExcludeCriteria", "FilterDefinition"],
            record_ids=segment_ids
        )

        # --- O restante da lógica de auditoria agora usará os dados corretos ---
        # ... (toda a lógica de auditoria e geração de CSV continua aqui, sem alterações) ...
        now = datetime.now(timezone.utc)
        thirty_days_ago = now - timedelta(days=30)
        ninety_days_ago = now - timedelta(days=90)

        # ... (restante do código main inalterado)

if __name__ == "__main__":
    start_time = time.time()
    try:
        asyncio.run(main())
    except Exception as e:
        logging.error(f"Um erro inesperado ocorreu durante a auditoria: {e}", exc_info=True)
    finally:
        duration = time.time() - start_time
        logging.info(f"\nTempo total de execução: {duration:.2f} segundos")