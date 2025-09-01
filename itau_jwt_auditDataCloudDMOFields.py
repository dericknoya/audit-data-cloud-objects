# -*- coding: utf-8 -*-
"""
Este script audita uma instância do Salesforce Data Cloud para identificar 
campos de DMOs (Data Model Objects) utilizados e não utilizados.

Versão: 36.2-stable-file-logging (Registra a saída detalhada em arquivo de log)
- LOGGING: A saída do script (logs de info, warning, erro) agora é salva
  automaticamente em um arquivo 'audit_script_run.log', além de ser exibida
  no console. Isso facilita a análise post-mortem da execução.
- LÓGICA MANTIDA: Nenhuma alteração na lógica de análise de uso ou de
  mapeamentos. Baseado na v36.1.
"""
import os
import time
import asyncio
import csv
import json
import html
import logging
import re
import gzip
from collections import defaultdict
from urllib.parse import urljoin, urlencode
from datetime import datetime, timedelta, timezone

import jwt
import requests 
import aiohttp
from dotenv import load_dotenv
from tqdm.asyncio import tqdm

# ==============================================================================
# --- ⚙️ CONFIGURAÇÃO ---
# ==============================================================================
load_dotenv()

class Config:
    USE_PROXY = os.getenv("USE_PROXY", "True").lower() == "true"
    PROXY_URL = os.getenv("PROXY_URL")
    VERIFY_SSL = os.getenv("VERIFY_SSL", "False").lower() == "true"
    API_VERSION = "v60.0"
    SF_CLIENT_ID = os.getenv("SF_CLIENT_ID")
    SF_USERNAME = os.getenv("SF_USERNAME")
    SF_AUDIENCE = os.getenv("SF_AUDIENCE")
    SF_LOGIN_URL = os.getenv("SF_LOGIN_URL")
    SEMAPHORE_LIMIT = 50
    BULK_CHUNK_SIZE = 400
    MAX_RETRIES = 3
    RETRY_DELAY_SECONDS = 5
    GRACE_PERIOD_DAYS = 90
    DMO_PREFIXES_TO_EXCLUDE = ('ssot', 'unified', 'individual', 'einstein', 'segment_membership', 'aa_', 'aal_')
    FIELD_PREFIXES_TO_EXCLUDE = ('ssot__', 'KQ_')
    SPECIFIC_FIELDS_TO_EXCLUDE = {'DataSource__c', 'DataSourceObject__c', 'InternalOrganization__c'}
    USED_FIELDS_CSV = 'audit_campos_dmo_utilizados.csv'
    UNUSED_FIELDS_CSV = 'audit_campos_dmo_nao_utilizados.csv'
    ACTIVATION_FIELDS_CSV = 'ativacoes_campos.csv'
    ACTIVATION_DMO_COLUMN = 'entityname'
    ACTIVATION_FIELD_COLUMN = 'fieldname'
    MAPPINGS_DUMP_CSV = 'unused_dmos_mappings_dump.csv'
    FIELD_NAME_PATTERN = re.compile(r'["\'](?:fieldApiName|fieldName|attributeName|developerName)["\']\s*:\s*["\']([^"\']+)["\']')
    
    # --- NOVO ARQUIVO DE LOG ---
    LOG_FILE = 'audit_script_run.log'

# ==============================================================================
# --- 헬 Helpers & Funções Auxiliares ---
# ==============================================================================
# --- NOVA FUNÇÃO DE SETUP DE LOGGING ---
def setup_logging(config: Config):
    """Configura o logging para salvar em arquivo e exibir no console."""
    logger = logging.getLogger()
    # Evita adicionar handlers duplicados em execuções repetidas (ex: notebooks)
    if logger.hasHandlers():
        logger.handlers.clear()
        
    logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Handler para o arquivo (sobrescreve a cada execução)
    file_handler = logging.FileHandler(config.LOG_FILE, mode='w', encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Handler para o console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

def get_access_token():
    logging.info("🔑 Autenticando com o Salesforce via JWT (método robusto)...")
    config = Config()
    if not all([config.SF_CLIENT_ID, config.SF_USERNAME, config.SF_AUDIENCE, config.SF_LOGIN_URL]):
        raise ValueError("Variáveis de ambiente de autenticação faltando no .env.")
    try:
        with open('private.pem', 'r') as f: private_key = f.read()
    except FileNotFoundError:
        logging.error("❌ Arquivo 'private.pem' não encontrado."); raise
    payload = {'iss': config.SF_CLIENT_ID, 'sub': config.SF_USERNAME, 'aud': config.SF_AUDIENCE, 'exp': int(time.time()) + 300}
    assertion = jwt.encode(payload, private_key, algorithm='RS256')
    params = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': assertion}
    token_url = urljoin(config.SF_LOGIN_URL, "/services/oauth2/token")
    proxies = {'http': config.PROXY_URL, 'https': config.PROXY_URL} if config.USE_PROXY and config.PROXY_URL else None
    try:
        res = requests.post(token_url, data=params, proxies=proxies, verify=config.VERIFY_SSL)
        res.raise_for_status()
        logging.info("✅ Autenticação bem-sucedida.")
        return res.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Erro na autenticação: {e.response.text if e.response else e}"); raise

def read_used_field_pairs_from_csv(config: Config) -> set:
    used_field_pairs = set()
    file_path = config.ACTIVATION_FIELDS_CSV
    dmo_col, field_col = config.ACTIVATION_DMO_COLUMN, config.ACTIVATION_FIELD_COLUMN
    try:
        with open(file_path, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            if not headers or (dmo_col not in headers or field_col not in headers):
                 logging.warning(f"⚠️ Arquivo '{file_path}' encontrado, mas as colunas '{dmo_col}' e/ou '{field_col}' não existem. Pulando.")
                 return used_field_pairs
            for row in reader:
                dmo_name, field_name = row.get(dmo_col), row.get(field_col)
                if dmo_name and field_name:
                    normalized_dmo = dmo_name.strip().removesuffix('__dlm')
                    used_field_pairs.add((normalized_dmo, field_name.strip()))
        logging.info(f"✅ Arquivo '{file_path}' lido. {len(used_field_pairs)} pares (DMO, Campo) únicos encontrados.")
    except FileNotFoundError:
        logging.warning(f"⚠️ Arquivo '{file_path}' não encontrado.")
    except Exception as e:
        logging.error(f"❌ Erro ao ler '{file_path}': {e}")
    return used_field_pairs

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

def normalize_field_name_for_mapping(name: str) -> str:
    if not isinstance(name, str): return ""
    base_name = re.sub(r'(_[a-zA-Z])?__c$', '', name)
    return base_name.lower()
# ==============================================================================
# ---  Classe Salesforce API Client (Versão Original Restaurada) ---
# ==============================================================================
class SalesforceClient:
    def __init__(self, config, auth_data):
        self.config = config
        self.access_token = auth_data['access_token']
        self.instance_url = auth_data['instance_url']
        self.session = None
        self.semaphore = asyncio.Semaphore(config.SEMAPHORE_LIMIT)
    async def __aenter__(self):
        headers = {'Authorization': f'Bearer {self.access_token}', 'Content-Type': 'application/json', 'Accept': 'application/json'}
        self.session = aiohttp.ClientSession(base_url=self.instance_url, headers=headers, connector=aiohttp.TCPConnector(ssl=self.config.VERIFY_SSL))
        return self
    async def __aexit__(self, exc_type, exc, tb):
        if self.session and not self.session.closed: await self.session.close()
    async def fetch_api_data(self, relative_url, key_name=None):
        async with self.semaphore:
            for attempt in range(self.config.MAX_RETRIES):
                try:
                    all_records, current_url = [], relative_url
                    is_tooling_api = "/tooling" in current_url
                    while current_url:
                        kwargs = {'ssl': self.config.VERIFY_SSL}
                        if self.config.USE_PROXY: kwargs['proxy'] = self.config.PROXY_URL
                        async with self.session.get(current_url, **kwargs) as response:
                            response.raise_for_status()
                            data = await response.json()
                            if key_name:
                                all_records.extend(data.get(key_name, []))
                                next_page, query_locator = data.get('nextRecordsUrl'), data.get('queryLocator')
                                if next_page: current_url = urljoin(str(self.session._base_url), next_page)
                                elif is_tooling_api and query_locator and not data.get('done', True): current_url = f"/services/data/{self.config.API_VERSION}/tooling/query/{query_locator}"
                                else: current_url = None
                            else: return data
                    return all_records
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    if attempt < self.config.MAX_RETRIES - 1:
                        await asyncio.sleep(self.config.RETRY_DELAY_SECONDS)
                    else:
                        if hasattr(e, 'status') and e.status == 404:
                            return None
                        logging.error(f"❌ Todas as {self.config.MAX_RETRIES} tentativas para {relative_url[:60]} falharam."); raise e
    
    async def fetch_dmo_mappings(self, dmo_api_name):
        endpoint = f"/services/data/{self.config.API_VERSION}/ssot/data-model-object-mappings"
        params = {"dataspace": "default", "dmoDeveloperName": dmo_api_name}
        url = f"{endpoint}?{urlencode(params)}"
        logging.info(f"  --> Chamando API de Mapeamento: ...{url[-100:]}")
        return await self.fetch_api_data(url)
    
    async def execute_query_job(self, query):
        async with self.semaphore:
            for attempt in range(self.config.MAX_RETRIES):
                try:
                    job_url_path = f"/services/data/{self.config.API_VERSION}/jobs/query"
                    payload = {"operation": "query", "query": query, "contentType": "CSV"}
                    proxy = self.config.PROXY_URL if self.config.USE_PROXY else None
                    async with self.session.post(job_url_path, data=json.dumps(payload), proxy=proxy, ssl=self.config.VERIFY_SSL) as res:
                        res.raise_for_status()
                        job_info = await res.json()
                        job_id = job_info.get('id')
                        if not job_id: logging.error(f"❌ JobId não retornado para query: {query[:100]}..."); return []
                    job_status_path = f"{job_url_path}/{job_id}"
                    while True:
                        await asyncio.sleep(5)
                        async with self.session.get(job_status_path, proxy=proxy, ssl=self.config.VERIFY_SSL) as res:
                            res.raise_for_status(); status_info = await res.json()
                            if status_info['state'] == 'JobComplete': break
                            if status_info['state'] in ['Failed', 'Aborted']:
                                logging.error(f"❌ Job {job_id} falhou: {status_info.get('errorMessage')}"); return []
                    results_path = f"{job_status_path}/results"
                    async with self.session.get(results_path, headers={'Accept-Encoding': 'gzip'}, proxy=proxy, ssl=self.config.VERIFY_SSL) as res:
                        res.raise_for_status()
                        content = await res.read()
                        csv_text = (gzip.decompress(content) if res.headers.get('Content-Encoding') == 'gzip' else content).decode('utf-8')
                        lines = csv_text.strip().splitlines()
                        return list(csv.DictReader(lines)) if len(lines) > 1 else []
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    if attempt < self.config.MAX_RETRIES - 1:
                        await asyncio.sleep(self.config.RETRY_DELAY_SECONDS)
                    else:
                        logging.error(f"❌ Todas as {self.config.MAX_RETRIES} tentativas para o job de query '{query[:50]}...' falharam."); raise e
    async def fetch_records_in_bulk(self, object_name, fields, record_ids):
        if not record_ids: return []
        tasks, field_str = [], ", ".join(fields)
        for i in range(0, len(record_ids), self.config.BULK_CHUNK_SIZE):
            chunk = record_ids[i:i + self.config.BULK_CHUNK_SIZE]
            formatted_ids = "','".join(chunk)
            query = f"SELECT {field_str} FROM {object_name} WHERE Id IN ('{formatted_ids}')"
            tasks.append(self.execute_query_job(query))
        results = await tqdm.gather(*tasks, desc=f"Buscando {object_name} (Bulk API)")
        return [record for record_list in results if record_list for record in record_list]
    async def fetch_users_by_id(self, user_ids):
        if not user_ids: return {}
        users = await self.fetch_records_in_bulk('User', ['Id', 'Name'], list(user_ids))
        return {user['Id']: user.get('Name', 'Nome não encontrado') for user in users}

# ==============================================================================
# --- 📊 FUNÇÕES DE ANÁLISE E PROCESSAMENTO ---
# ==============================================================================
def write_csv_report(filename, data, headers):
    if not data:
        logging.info(f"ℹ️ Nenhum dado para gerar o relatório '{filename}'.")
        return
    try:
        with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data)
        logging.info(f"✅ Relatório gerado com sucesso: {filename} ({len(data)} linhas)")
    except (IOError, OSError) as e:
        logging.error(f"❌ Erro ao escrever o arquivo {filename}: {e}")
        
def build_usage_map(data, all_dmo_fields_map, used_field_pairs_from_csv):
    """Constrói um mapa de uso preciso com a chave (DMO, Campo)."""
    usage_map = defaultdict(list)
    for dmo_dev_name, field_api_name in used_field_pairs_from_csv:
        usage_map[(dmo_dev_name, field_api_name)].append(f"Ativação (CSV Externo): {Config.ACTIVATION_FIELDS_CSV}")
    mentioned_fields = set()
    sources = [ (data['segments'], "Segmento", lambda s: f"{s.get('IncludeCriteria', '')} {s.get('ExcludeCriteria', '')}", lambda s: s.get('Name')), (data['activations'], "Ativação", lambda a: a.get('QueryPath', ''), lambda a: a.get('Name')), (data['calculated_insights'], "Calculated Insight", json.dumps, lambda ci: ci.get('displayName')) ]
    for source_list, usage_type, content_extractor, name_extractor in sources:
        for item in source_list:
            content = content_extractor(item)
            if not content: continue
            for match in Config.FIELD_NAME_PATTERN.finditer(html.unescape(str(content))):
                field_name = match.group(1)
                item_name = name_extractor(item) or "Nome Indisponível"
                mentioned_fields.add((field_name, f"{usage_type}: {item_name}"))
    for field_name, context in mentioned_fields:
        if field_name in all_dmo_fields_map:
            for dmo_dev_name in all_dmo_fields_map[field_name]:
                usage_map[(dmo_dev_name, field_name)].append(context)
    return usage_map

async def fetch_mappings_with_fallback(client, dmo_name):
    mappings = await client.fetch_dmo_mappings(dmo_name)
    if not mappings or not mappings.get('objectSourceTargetMaps'):
        normalized_name = normalize_api_name(dmo_name)
        if normalized_name != dmo_name:
            mappings = await client.fetch_dmo_mappings(normalized_name)
    return mappings

def generate_mappings_dump(all_mapping_data_responses, unused_dmos, config: Config):
    """Processa os dados de mapeamento já buscados e gera o arquivo de dump."""
    dump_rows = []
    for dmo_name, mapping_data in zip(unused_dmos, all_mapping_data_responses):
        if not mapping_data:
            logging.info(f"  <-- Resposta para '{dmo_name}' foi VAZIA (None).")
            continue
        if 'objectSourceTargetMaps' not in mapping_data or not mapping_data['objectSourceTargetMaps']:
            logging.info(f"  <-- Resposta para '{dmo_name}' não contém mapeamentos em 'objectSourceTargetMaps'.")
            continue
        logging.info(f"  <-- Resposta VÁLIDA para '{dmo_name}'. Processando {len(mapping_data['objectSourceTargetMaps'])} mapeamento(s) de objeto.")
        for obj_map in mapping_data.get('objectSourceTargetMaps', []):
            target_dmo_name = obj_map.get('targetEntityDeveloperName')
            source_dlo_name = obj_map.get('sourceEntityDeveloperName')
            dmo_mapping_id = obj_map.get('developerName')
            field_mappings = obj_map.get('fieldMappings', [])
            if not field_mappings:
                dump_rows.append({'DMO_NAME': target_dmo_name, 'DLO_NAME': source_dlo_name, 'DMO_MAPPING_ID': dmo_mapping_id, 'FIELD_MAPPING_ID': 'N/A'})
            else:
                for field_map in field_mappings:
                    dump_rows.append({'DMO_NAME': target_dmo_name, 'DLO_NAME': source_dlo_name, 'DMO_MAPPING_ID': dmo_mapping_id, 'FIELD_MAPPING_ID': field_map.get('developerName')})
    
    headers = ['DMO_NAME', 'DLO_NAME', 'DMO_MAPPING_ID', 'FIELD_MAPPING_ID']
    write_csv_report(config.MAPPINGS_DUMP_CSV, dump_rows, headers)

# ==============================================================================
# --- 🚀 ORQUESTRADOR PRINCIPAL ---
# ==============================================================================
async def main():
    config = Config()
    setup_logging(config)  # Configura o logging para arquivo e console
    
    logging.info("🚀 Iniciando auditoria de campos de DMO...")
    auth_data = get_access_token()
    async with SalesforceClient(config, auth_data) as client:
        # ... (Restante do código principal inalterado) ...
        logging.info("--- FASE 1/4: Coletando metadados e objetos... ---")
        tooling_query_fields = "SELECT Id, DeveloperName, MktDataModelObjectId FROM MktDataModelField"
        tasks_to_run = { "dmo_tooling": client.fetch_api_data(f"/services/data/{config.API_VERSION}/tooling/query?{urlencode({'q': 'SELECT Id, DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject'})}", 'records'), "dmo_fields_tooling": client.fetch_api_data(f"/services/data/{config.API_VERSION}/tooling/query?{urlencode({'q': tooling_query_fields})}", 'records'), "dmo_metadata": client.fetch_api_data(f"/services/data/{config.API_VERSION}/ssot/metadata?entityType=DataModelObject", 'metadata'), "segments": client.execute_query_job("SELECT Id, Name, IncludeCriteria, ExcludeCriteria FROM MarketSegment"), "activations": client.execute_query_job("SELECT QueryPath, Name FROM MktSgmntActvtnAudAttribute"), "calculated_insights": client.fetch_api_data(f"/services/data/{config.API_VERSION}/ssot/metadata?entityType=CalculatedInsight", 'metadata'), }
        task_results = await asyncio.gather(*tasks_to_run.values(), return_exceptions=True)
        data = {task_name: res if not isinstance(res, Exception) else [] for task_name, res in zip(tasks_to_run.keys(), task_results)}
        logging.info("✅ Coleta inicial de metadados concluída.")
        dmo_creation_info = {rec['DeveloperName']: rec for rec in data['dmo_tooling']}
        field_id_map = {f"{rec['MktDataModelObjectId']}.{rec['DeveloperName']}": rec['Id'] for rec in data.get('dmo_fields_tooling', [])}
        dmo_creator_ids = {cr_id for d in dmo_creation_info.values() if (cr_id := d.get('CreatedById') or d.get('createdById'))}
        user_id_to_name_map = await client.fetch_users_by_id(dmo_creator_ids)
        
        logging.info("--- FASE 2/4: Construindo mapa de uso preciso (DMO+Campo)... ---")
        all_dmo_fields_map = defaultdict(list)
        all_dmo_fields = defaultdict(lambda: {'fields': {}, 'displayName': ''})
        for dmo in data['dmo_metadata']:
            dmo_api_name = dmo.get('name')
            if dmo_api_name and dmo_api_name.endswith('__dlm') and not any(dmo_api_name.lower().startswith(p) for p in config.DMO_PREFIXES_TO_EXCLUDE):
                all_dmo_fields[dmo_api_name]['displayName'] = dmo.get('displayName', dmo_api_name)
                dmo_dev_name = normalize_api_name(dmo_api_name)
                for field in dmo.get('fields', []):
                    if field_name := field.get('name'):
                        all_dmo_fields[dmo_api_name]['fields'][field_name] = field.get('displayName', field_name)
                        all_dmo_fields_map[field_name].append(dmo_dev_name)
        used_field_pairs_from_csv = read_used_field_pairs_from_csv(config)
        usage_map = build_usage_map(data, all_dmo_fields_map, used_field_pairs_from_csv)
        logging.info(f"✅ Mapa de uso construído com {len(usage_map)} pares (DMO, Campo) únicos em uso.")

        logging.info("--- FASE 3/4: Classificando campos... ---")
        used_results, unused_results = [], []
        for dmo_api_name, dmo_data in all_dmo_fields.items():
            dmo_dev_name = normalize_api_name(dmo_api_name)
            dmo_details = dmo_creation_info.get(dmo_dev_name, {})
            creator_name = user_id_to_name_map.get(dmo_details.get('CreatedById') or dmo_details.get('createdById'), 'Desconhecido')
            for field_api_name, field_display_name in dmo_data['fields'].items():
                if any(field_api_name.startswith(p) for p in config.FIELD_PREFIXES_TO_EXCLUDE) or field_api_name in config.SPECIFIC_FIELDS_TO_EXCLUDE: continue
                composite_key = (dmo_dev_name, field_api_name)
                usages = usage_map.get(composite_key, [])
                is_in_grace_period = False
                created_date = parse_sf_date(dmo_details.get('CreatedDate'))
                if created_date and days_since(created_date) <= config.GRACE_PERIOD_DAYS: is_in_grace_period = True
                dmo_id = dmo_details.get('Id')
                field_name_for_id_lookup = field_api_name.removesuffix('__c')
                deletion_id = field_id_map.get(f"{dmo_id}.{field_name_for_id_lookup}", 'ID não encontrado') if dmo_id else 'ID do DMO não encontrado'
                common_data = {'DMO_DISPLAY_NAME': dmo_data['displayName'], 'DMO_API_NAME': dmo_api_name, 'FIELD_DISPLAY_NAME': field_display_name, 'FIELD_API_NAME': field_api_name, 'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': deletion_id}
                if usages or is_in_grace_period:
                    if is_in_grace_period and not usages: usages.append("N/A (DMO Recém-criado): DMO criado < 90 dias")
                    used_results.append({**common_data, 'USAGE_COUNT': len(usages), 'USAGE_TYPES': ", ".join(sorted(list(set(usages))))})
                else:
                    unused_results.append({**common_data, 'DELETAR': 'NAO', 'REASON': 'Não utilizado e DMO com mais de 90 dias'})
        
        if unused_results:
            logging.info("--- FASE BÔNUS: Buscando Mapeamentos e Gerando Dump Controlado ---")
            unused_dmos = sorted(list({row['DMO_API_NAME'] for row in unused_results}))
            
            mapping_tasks = [fetch_mappings_with_fallback(client, dmo_name) for dmo_name in unused_dmos]
            all_mapping_data = await tqdm.gather(*mapping_tasks, desc="Buscando mapeamentos")
            
            generate_mappings_dump(all_mapping_data, unused_dmos, config)
            
            raw_mapping_by_dmo = dict(zip(unused_dmos, all_mapping_data))
            for row in unused_results:
                dmo_api_name = row['DMO_API_NAME']
                field_api_name = row['FIELD_API_NAME']
                target_key_to_find = normalize_field_name_for_mapping(field_api_name)
                found_mappings = []
                mapping_data = raw_mapping_by_dmo.get(dmo_api_name)
                if mapping_data and 'objectSourceTargetMaps' in mapping_data:
                    for obj_map in mapping_data['objectSourceTargetMaps']:
                        for field_map in obj_map.get('fieldMappings', []):
                            api_target_field = field_map.get('targetFieldDeveloperName')
                            if not api_target_field: continue
                            available_key = normalize_field_name_for_mapping(api_target_field)
                            if target_key_to_find == available_key:
                                found_mappings.append({'OBJECT_MAPPING_ID': obj_map.get('developerName', ''), 'FIELD_MAPPING_ID': field_map.get('developerName', '')})
                if found_mappings:
                    row['OBJECT_MAPPING_ID'] = ", ".join(m['OBJECT_MAPPING_ID'] for m in found_mappings)
                    row['FIELD_MAPPING_ID'] = ", ".join(m['FIELD_MAPPING_ID'] for m in found_mappings)
                else:
                    row['OBJECT_MAPPING_ID'] = 'Não possuí mapeamento'
                    row['FIELD_MAPPING_ID'] = 'Não possuí mapeamento'
            logging.info("✅ IDs de mapeamento adicionados ao relatório.")
        
        logging.info("--- FASE 4/4: Gerando relatórios... ---")
        write_csv_report(config.UNUSED_FIELDS_CSV, unused_results, ['DELETAR', 'DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'REASON', 'CREATED_BY_NAME', 'OBJECT_MAPPING_ID', 'FIELD_MAPPING_ID', 'DELETION_IDENTIFIER'])
        write_csv_report(config.USED_FIELDS_CSV, used_results, ['DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'USAGE_COUNT', 'USAGE_TYPES', 'CREATED_BY_NAME', 'DELETION_IDENTIFIER'])

if __name__ == "__main__":
    start_time = time.time()
    # A configuração do logging agora é a primeira coisa a ser feita
    setup_logging(Config())
    try: asyncio.run(main())
    except Exception as e: logging.critical(f"❌ Ocorreu um erro fatal: {e}", exc_info=True)
    finally: logging.info(f"\n🏁 Auditoria concluída. Tempo total de execução: {time.time() - start_time:.2f} segundos.")