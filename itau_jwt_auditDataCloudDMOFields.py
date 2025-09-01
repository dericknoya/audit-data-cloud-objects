# -*- coding: utf-8 -*-
"""
Este script audita uma instância do Salesforce Data Cloud para identificar 
campos de DMOs (Data Model Objects) utilizados e não utilizados.

Versão: 45.0-stable-final-complete (Restaura ID Técnico para Exclusão)
- FUNCIONALIDADE RESTAURADA: Reintroduzida a lógica para buscar o ID técnico de
  cada campo (MktDataModelField.Id) e adicioná-lo à coluna 'DELETION_IDENTIFIER'
  nos relatórios finais.
- PRECISÃO MANTIDA: A lógica de análise de uso por chave composta (DMO, Campo)
  está mantida.
- ROBUSTEZ: Todas as correções anteriores (versão de API, headers, tratamento
  de erros 404, etc.) estão presentes. Esta é a versão completa.
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
    API_VERSION = "v64.0"
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
    LOG_FILE = 'audit_script_run.log'
    DMO_FIELD_PATTERN = re.compile(r'([\w]+__dlm)\.([\w]+__c)')

# ==============================================================================
# --- 헬 Helpers & Funções Auxiliares ---
# ==============================================================================
def setup_logging(config: Config):
    logger = logging.getLogger()
    if logger.hasHandlers():
        logger.handlers.clear()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler = logging.FileHandler(config.LOG_FILE, mode='w', encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
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
# ---  Classe Salesforce API Client ---
# ==============================================================================
class SalesforceClient:
    def __init__(self, config, auth_data):
        self.config = config
        self.access_token = auth_data['access_token']
        self.instance_url = auth_data['instance_url']
        self.session = None
        self.semaphore = asyncio.Semaphore(config.SEMAPHORE_LIMIT)
    async def __aenter__(self):
        headers = {'Authorization': f'Bearer {self.access_token}', 'Accept': 'application/json'}
        self.session = aiohttp.ClientSession(base_url=self.instance_url, headers=headers, connector=aiohttp.TCPConnector(ssl=self.config.VERIFY_SSL))
        return self
    async def __aexit__(self, exc_type, exc, tb):
        if self.session and not self.session.closed: await self.session.close()
    
    async def fetch_api_data(self, relative_url, key_name=None):
        async with self.semaphore:
            for attempt in range(self.config.MAX_RETRIES):
                try:
                    all_records, current_url = [], relative_url
                    while current_url:
                        kwargs = {'ssl': self.config.VERIFY_SSL}
                        if self.config.USE_PROXY: kwargs['proxy'] = self.config.PROXY_URL
                        async with self.session.get(current_url, **kwargs) as response:
                            response.raise_for_status()
                            data = await response.json()
                            if key_name:
                                all_records.extend(data.get(key_name, []))
                                next_page = data.get('nextRecordsUrl')
                                if next_page:
                                    # Corrige a URL para chamadas de Tooling API paginadas
                                    if "/tooling/query/" in next_page:
                                        current_url = next_page
                                    else:
                                        current_url = urljoin(str(self.session._base_url), next_page)
                                else:
                                    current_url = None
                            else: return data
                    return all_records
                except aiohttp.ClientResponseError as e:
                    if e.status == 404:
                        logging.warning(f"API retornou 404 Not Found para ...{relative_url[-80:]}. Continuando...")
                        return None
                    if attempt < self.config.MAX_RETRIES - 1:
                        logging.warning(f"Erro {e.status} ao buscar dados. Tentando novamente...")
                        await asyncio.sleep(self.config.RETRY_DELAY_SECONDS)
                    else:
                        logging.error(f"❌ Todas as {self.config.MAX_RETRIES} tentativas para {relative_url[:60]} falharam com erro {e.status}."); raise e
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    if attempt < self.config.MAX_RETRIES - 1:
                        await asyncio.sleep(self.config.RETRY_DELAY_SECONDS)
                    else:
                        logging.error(f"❌ Todas as {self.config.MAX_RETRIES} tentativas para {relative_url[:60]} falharam."); raise e

    async def fetch_dmo_mappings(self, dmo_api_name):
        endpoint = f"/services/data/{self.config.API_VERSION}/ssot/data-model-object-mappings"
        params = {"dataspace": "default", "dmoDeveloperName": dmo_api_name}
        url = f"{endpoint}?{urlencode(params)}"
        return await self.fetch_api_data(url)

    async def fetch_users_by_id(self, user_ids):
        if not user_ids: return {}
        # Implementação simples para evitar dependência do Bulk API
        tasks = [self.fetch_api_data(f"/services/data/{self.config.API_VERSION}/sobjects/User/{uid}?fields=Name") for uid in user_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        user_map = {}
        for uid, result in zip(user_ids, results):
            if isinstance(result, Exception):
                user_map[uid] = "Nome não encontrado (erro)"
            else:
                user_map[uid] = result.get("Name", "Nome não encontrado")
        return user_map

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
        
def _find_fields_recursively(node, found_pairs):
    if isinstance(node, dict):
        dmo = node.get("sourceDmoName") or node.get("dmoName") or node.get("objectApiName")
        field = node.get("sourceFieldName") or node.get("fieldName") or node.get("fieldApiName")
        if dmo and field:
            found_pairs.add((normalize_api_name(dmo), field))
        for value in node.values():
            _find_fields_recursively(value, found_pairs)
    elif isinstance(node, list):
        for item in node:
            _find_fields_recursively(item, found_pairs)

def find_used_fields_in_cis(calculated_insights: list) -> set:
    precise_pairs = set()
    for ci in calculated_insights:
        _find_fields_recursively(ci, precise_pairs)
    return precise_pairs

def find_explicit_pairs_in_text(content: str) -> set:
    if not content: return set()
    found_pairs = set()
    try:
        data = json.loads(content)
        _find_fields_recursively(data, found_pairs)
    except (json.JSONDecodeError, TypeError):
        for match in Config.DMO_FIELD_PATTERN.finditer(content):
            dmo_name, field_name = match.group(1), match.group(2)
            dmo_dev_name = normalize_api_name(dmo_name)
            found_pairs.add((dmo_dev_name, field_name))
    return found_pairs

# ==============================================================================
# --- 🚀 ORQUESTRADOR PRINCIPAL ---
# ==============================================================================
async def main():
    config = Config()
    setup_logging(config)
    
    logging.info("🚀 Iniciando auditoria de campos de DMO...")
    auth_data = get_access_token()
    async with SalesforceClient(config, auth_data) as client:
        logging.info("--- FASE 1/4: Coletando metadados e objetos... ---")
        
        # --- LÓGICA RESTAURADA: Query para buscar IDs técnicos dos campos ---
        tooling_query_fields = "SELECT Id, DeveloperName, MktDataModelObjectId FROM MktDataModelField"
        
        tasks_to_run = {
            "dmo_tooling": client.fetch_api_data(f"/services/data/{config.API_VERSION}/tooling/query?{urlencode({'q': 'SELECT Id, DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject'})}", 'records'),
            "dmo_fields_tooling": client.fetch_api_data(f"/services/data/{config.API_VERSION}/tooling/query?{urlencode({'q': tooling_query_fields})}", 'records'),
            "dmo_metadata": client.fetch_api_data(f"/services/data/{config.API_VERSION}/ssot/metadata?entityType=DataModelObject", 'metadata'),
            "calculated_insights": client.fetch_api_data(f"/services/data/{config.API_VERSION}/ssot/metadata?entityType=CalculatedInsight", 'records'),
            "segments": client.fetch_api_data(f"/services/data/{config.API_VERSION}/query?{urlencode({'q': 'SELECT Name, IncludeCriteria, ExcludeCriteria FROM MarketSegment'})}", 'records'),
            "activations": client.fetch_api_data(f"/services/data/{config.API_VERSION}/query?{urlencode({'q': 'SELECT Name, QueryPath FROM MktSgmntActvtnAudAttribute'})}", 'records'),
        }
        task_results = await asyncio.gather(*tasks_to_run.values(), return_exceptions=True)
        data = {task_name: res if not isinstance(res, Exception) else [] for task_name, res in zip(tasks_to_run.keys(), task_results)}
        
        logging.info("✅ Coleta inicial de metadados concluída.")
        dmo_creation_info = {rec['DeveloperName']: rec for rec in data['dmo_tooling']}
        
        # --- LÓGICA RESTAURADA: Criação do mapa de IDs técnicos ---
        field_id_map = {f"{rec['MktDataModelObjectId']}.{rec['DeveloperName']}": rec['Id'] for rec in data.get('dmo_fields_tooling', [])}
        logging.info(f"✅ {len(field_id_map)} IDs técnicos de campos de DMOs foram mapeados.")

        dmo_creator_ids = {cr_id for d in dmo_creation_info.values() if (cr_id := d.get('CreatedById'))}
        user_id_to_name_map = await client.fetch_users_by_id(list(dmo_creator_ids))
        
        logging.info("--- FASE 2/4: Construindo mapa de uso preciso (DMO+Campo)... ---")
        precise_usage_from_csv = read_used_field_pairs_from_csv(config)
        precise_usage_from_cis = find_used_fields_in_cis(data['calculated_insights'])
        
        precise_usage_from_segments = set()
        for seg in data.get('segments', []):
            content = f"{seg.get('IncludeCriteria', '')} {seg.get('ExcludeCriteria', '')}"
            precise_usage_from_segments.update(find_explicit_pairs_in_text(content))

        precise_usage_from_activations = set()
        for act in data['activations']:
            precise_usage_from_activations.update(find_explicit_pairs_in_text(act.get('QueryPath', '')))

        usage_map = defaultdict(list)
        for dmo, field in precise_usage_from_csv: usage_map[(dmo, field)].append(f"Ativação (CSV Externo)")
        for dmo, field in precise_usage_from_cis: usage_map[(dmo, field)].append("Calculated Insight")
        for dmo, field in precise_usage_from_segments: usage_map[(dmo, field)].append("Segmento")
        for dmo, field in precise_usage_from_activations: usage_map[(dmo, field)].append("Ativação")

        logging.info(f"✅ Mapa de uso preciso construído com {len(usage_map)} pares (DMO, Campo) únicos em uso.")

        logging.info("--- FASE 3/4: Classificando campos... ---")
        all_dmo_fields = defaultdict(lambda: {'fields': {}, 'displayName': ''})
        for dmo in data['dmo_metadata']:
            dmo_api_name = dmo.get('name')
            if dmo_api_name and dmo_api_name.endswith('__dlm') and not any(dmo_api_name.lower().startswith(p) for p in config.DMO_PREFIXES_TO_EXCLUDE):
                all_dmo_fields[dmo_api_name]['displayName'] = dmo.get('displayName', dmo_api_name)
                for field in dmo.get('fields', []):
                    if field_name := field.get('name'):
                        all_dmo_fields[dmo_api_name]['fields'][field_name] = field.get('displayName', field_name)

        used_results, unused_results = [], []
        for dmo_api_name, dmo_data in all_dmo_fields.items():
            dmo_dev_name = normalize_api_name(dmo_api_name)
            dmo_details = dmo_creation_info.get(dmo_dev_name, {})
            creator_name = user_id_to_name_map.get(dmo_details.get('CreatedById'), 'Desconhecido')
            for field_api_name, field_display_name in dmo_data['fields'].items():
                if any(field_api_name.startswith(p) for p in config.FIELD_PREFIXES_TO_EXCLUDE) or field_api_name in config.SPECIFIC_FIELDS_TO_EXCLUDE: continue
                
                composite_key = (dmo_dev_name, field_api_name)
                usages = usage_map.get(composite_key, [])
                
                is_in_grace_period = False
                created_date = parse_sf_date(dmo_details.get('CreatedDate'))
                if created_date and days_since(created_date) <= config.GRACE_PERIOD_DAYS: is_in_grace_period = True
                
                # --- LÓGICA RESTAURADA: Busca do ID técnico ---
                dmo_id = dmo_details.get('Id')
                field_name_for_id_lookup = field_api_name.removesuffix('__c')
                deletion_id = field_id_map.get(f"{dmo_id}.{field_name_for_id_lookup}", 'ID não encontrado') if dmo_id else 'ID do DMO não encontrado'
                
                common_data = {'DMO_DISPLAY_NAME': dmo_data['displayName'], 'DMO_API_NAME': dmo_api_name, 'FIELD_DISPLAY_NAME': field_display_name, 'FIELD_API_NAME': field_api_name, 'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': deletion_id}

                if usages or is_in_grace_period:
                    if is_in_grace_period and not usages: usages.append("N/A (DMO Recém-criado)")
                    used_results.append({**common_data, 'USAGE_COUNT': len(usages), 'USAGE_TYPES': ", ".join(sorted(list(set(usages))))})
                else:
                    unused_results.append({**common_data, 'DELETAR': 'NAO', 'REASON': 'Não utilizado'})
        
        if unused_results:
            logging.info("--- FASE BÔNUS: Buscando Mapeamentos para campos não utilizados ---")
            unused_dmos = sorted(list({row['DMO_API_NAME'] for row in unused_results}))
            mapping_tasks = [client.fetch_dmo_mappings(dmo_name) for dmo_name in unused_dmos]
            all_mapping_data = await tqdm.gather(*mapping_tasks, desc="Buscando mapeamentos")
            
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
        # --- LÓGICA RESTAURADA: Coluna 'DELETION_IDENTIFIER' de volta nos headers ---
        header_unused = ['DELETAR', 'DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'REASON', 'CREATED_BY_NAME', 'OBJECT_MAPPING_ID', 'FIELD_MAPPING_ID', 'DELETION_IDENTIFIER']
        write_csv_report(config.UNUSED_FIELDS_CSV, unused_results, header_unused)
        
        header_used = ['DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'USAGE_COUNT', 'USAGE_TYPES', 'CREATED_BY_NAME', 'DELETION_IDENTIFIER']
        write_csv_report(config.USED_FIELDS_CSV, used_results, header_used)

if __name__ == "__main__":
    start_time = time.time()
    setup_logging(Config())
    try: asyncio.run(main())
    except Exception as e: logging.critical(f"❌ Ocorreu um erro fatal: {e}", exc_info=True)
    finally: logging.info(f"\n🏁 Auditoria concluída. Tempo total de execução: {time.time() - start_time:.2f} segundos.")