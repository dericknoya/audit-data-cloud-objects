# -*- coding: utf-8 -*-
"""
Este script audita uma instância do Salesforce Data Cloud para identificar 
campos de DMOs (Data Model Objects) utilizados e não utilizados.

Versão: 32.0-stable-context-aware (Análise de Contexto e Mapeamento Direto)
- ANÁLISE DE USO CONTEXTUAL: O script agora também procura por menções ao NOME DO DMO
  dentro de Segmentos/CIs. Se um DMO é encontrado, todos os seus campos são
  considerados em uso, e a origem é citada no relatório.
- CORREÇÃO DE MAPEAMENTO: A lógica de busca de mapeamentos foi refatorada para
  realizar uma comparação direta e explícita, normalizando ambos os nomes de
  campo (o do DMO e o da API) no momento da verificação, resolvendo a falha
  de correspondência.
- ANÁLISE COMPLETA: O 'Modo Estrito' foi removido para garantir que a análise
  sempre seja abrangente.
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
    FIELD_NAME_PATTERN = re.compile(r'["\'](?:fieldApiName|fieldName|attributeName|developerName)["\']\s*:\s*["\']([^"\']+)["\']')
    
    DEBUG_FOLDER = 'debug_logs'
    DEBUG_USAGE_CSV = 'debug_usage_classification.csv'
    DEBUG_MAPPING_CSV = 'debug_mapping_lookup.csv'
    DEBUG_RAW_MAPPING_FOLDER = 'debug_raw_mappings'

# Configuração do Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ==============================================================================
# --- 헬 Helpers & Funções Auxiliares (sem alterações) ---
# ... (o código das funções auxiliares e da classe SalesforceClient permanece o mesmo) ...
# ==============================================================================
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
                 logging.warning(f"⚠️ Arquivo '{file_path}' encontrado, mas as colunas esperadas '{dmo_col}' e/ou '{field_col}' não existem. Pulando.")
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
def find_fields_in_content(content_string, used_fields_details):
    if not content_string: return
    for match in Config.FIELD_NAME_PATTERN.finditer(html.unescape(str(content_string))):
        used_fields_details[match.group(1)].append(True) # Apenas registra que foi usado

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
        
def classify_fields(all_dmo_fields, dmo_usage_locations, field_usage_locations, used_field_pairs_from_csv: set, dmo_creation_info, user_map, field_id_map, config: Config):
    logging.info("--- FASE 3/4: Classificando campos... ---")
    used_results, unused_results = [], []
    
    for dmo_api_name, data in all_dmo_fields.items():
        dmo_dev_name = normalize_api_name(dmo_api_name)
        dmo_details = dmo_creation_info.get(dmo_dev_name, {})
        creator_id = dmo_details.get('CreatedById') or dmo_details.get('createdById')
        creator_name = user_map.get(creator_id, 'Desconhecido')
        
        # Verifica se o DMO em si foi mencionado em algum lugar
        dmo_level_usages = dmo_usage_locations.get(dmo_dev_name, [])
        
        for field_api_name, field_display_name in data['fields'].items():
            if any(field_api_name.startswith(p) for p in Config.FIELD_PREFIXES_TO_EXCLUDE) or field_api_name in Config.SPECIFIC_FIELDS_TO_EXCLUDE:
                continue
            
            all_usages = []
            
            # 1. Uso a nível de DMO (mais forte)
            if dmo_level_usages:
                all_usages.extend(dmo_level_usages)

            # 2. Uso a nível de campo (buscas de texto)
            field_level_usages = field_usage_locations.get(field_api_name, [])
            if field_level_usages:
                all_usages.extend(field_level_usages)

            # 3. Uso a nível de par (DMO, Campo) do CSV (mais preciso)
            if (dmo_dev_name, field_api_name) in used_field_pairs_from_csv:
                all_usages.append({"usage_type": "Ativação (CSV Externo)", "object_name": config.ACTIVATION_FIELDS_CSV})
            
            # 4. Período de carência
            created_date = parse_sf_date(dmo_details.get('CreatedDate'))
            if created_date and days_since(created_date) <= config.GRACE_PERIOD_DAYS:
                if not all_usages: # Só adiciona se não houver outro uso
                    all_usages.append({"usage_type": "N/A (DMO Recém-criado)", "object_name": "DMO criado < 90 dias"})

            dmo_id = dmo_details.get('Id')
            field_name_for_id_lookup = field_api_name.removesuffix('__c')
            deletion_id = field_id_map.get(f"{dmo_id}.{field_name_for_id_lookup}", 'ID não encontrado') if dmo_id else 'ID do DMO não encontrado'
            common_data = {'DMO_DISPLAY_NAME': data['displayName'], 'DMO_API_NAME': dmo_api_name, 'FIELD_DISPLAY_NAME': field_display_name, 'FIELD_API_NAME': field_api_name, 'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': deletion_id}

            if all_usages:
                usage_types = ", ".join(sorted(list(set(f"{u['usage_type']}: {u['object_name']}" for u in all_usages))))
                used_results.append({**common_data, 'USAGE_COUNT': len(all_usages), 'USAGE_TYPES': usage_types})
            else:
                unused_results.append({**common_data, 'DELETAR': 'NAO', 'REASON': 'Não utilizado e DMO com mais de 90 dias'})
    
    logging.info(f"📊 Classificação concluída: {len(used_results)} campos utilizados, {len(unused_results)} campos não utilizados.")
    return used_results, unused_results

async def fetch_mappings_with_fallback(client, dmo_name):
    mappings = await client.fetch_dmo_mappings(dmo_name)
    if not mappings or not mappings.get('objectSourceTargetMaps'):
        normalized_name = normalize_api_name(dmo_name)
        if normalized_name != dmo_name:
            mappings = await client.fetch_dmo_mappings(normalized_name)
    return mappings

# ==============================================================================
# --- 🚀 ORQUESTRADOR PRINCIPAL ---
# ==============================================================================
async def main():
    logging.info("🚀 Iniciando auditoria de campos de DMO...")
    config = Config()
    
    os.makedirs(config.DEBUG_FOLDER, exist_ok=True)
    raw_mapping_path = os.path.join(config.DEBUG_FOLDER, config.DEBUG_RAW_MAPPING_FOLDER)
    os.makedirs(raw_mapping_path, exist_ok=True)
    
    auth_data = get_access_token()
    async with SalesforceClient(config, auth_data) as client:
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
        
        logging.info("--- FASE 2/4: Analisando o uso dos campos e DMOs... ---")
        used_field_pairs_from_csv = read_used_field_pairs_from_csv(config)
        
        dmo_usage_locations = defaultdict(list)
        field_usage_locations = defaultdict(list)
        
        all_dmo_dev_names = dmo_creation_info.keys()

        # Análise de uso contextual
        for seg in tqdm(data['segments'], desc="Analisando Segmentos"):
            content = f"{seg.get('IncludeCriteria', '')} {seg.get('ExcludeCriteria', '')}"
            for name in all_dmo_dev_names:
                if name in content: dmo_usage_locations[name].append({'usage_type': 'Segmento', 'object_name': seg.get('Name')})
            for match in Config.FIELD_NAME_PATTERN.finditer(content):
                field_usage_locations[match.group(1)].append({'usage_type': 'Segmento', 'object_name': seg.get('Name')})

        for act in tqdm(data['activations'], desc="Analisando Ativações"):
            content = act.get('QueryPath', '')
            for name in all_dmo_dev_names:
                if name in content: dmo_usage_locations[name].append({'usage_type': 'Ativação', 'object_name': act.get('Name')})
            for match in Config.FIELD_NAME_PATTERN.finditer(content):
                field_usage_locations[match.group(1)].append({'usage_type': 'Ativação', 'object_name': act.get('Name')})
        
        for ci in tqdm(data['calculated_insights'], desc="Analisando CIs"):
            content = json.dumps(ci)
            for name in all_dmo_dev_names:
                if name in content: dmo_usage_locations[name].append({'usage_type': 'Calculated Insight', 'object_name': ci.get('displayName')})
            for match in Config.FIELD_NAME_PATTERN.finditer(content):
                field_usage_locations[match.group(1)].append({'usage_type': 'Calculated Insight', 'object_name': ci.get('displayName')})

        all_dmo_fields = defaultdict(lambda: {'fields': {}, 'displayName': ''})
        for dmo in data['dmo_metadata']:
            dmo_name = dmo.get('name')
            if dmo_name and dmo_name.endswith('__dlm') and not any(dmo_name.lower().startswith(p) for p in config.DMO_PREFIXES_TO_EXCLUDE):
                all_dmo_fields[dmo_name]['displayName'] = dmo.get('displayName', dmo_name)
                for field in dmo.get('fields', []):
                    if field_name := field.get('name'): all_dmo_fields[dmo_name]['fields'][field_name] = field.get('displayName', field_name)

        used_field_results, unused_field_results = classify_fields(all_dmo_fields, dmo_usage_locations, field_usage_locations, used_field_pairs_from_csv, dmo_creation_info, user_id_to_name_map, field_id_map, config)

        if unused_field_results:
            logging.info("--- FASE BÔNUS: Buscando e Depurando Mapeamentos ---")
            unused_dmos = sorted(list({row['DMO_API_NAME'] for row in unused_field_results}))
            mapping_tasks = [fetch_mappings_with_fallback(client, dmo_name) for dmo_name in unused_dmos]
            all_mapping_data = await tqdm.gather(*mapping_tasks, desc="Buscando Mapeamentos de DMOs")
            
            # Mapeia DMO API Name para seus dados de mapeamento brutos
            raw_mapping_by_dmo = dict(zip(unused_dmos, all_mapping_data))

            for row in unused_field_results:
                dmo_api_name = row['DMO_API_NAME']
                field_api_name = row['FIELD_API_NAME']
                
                # Chave de busca normalizada para o campo atual
                target_key_to_find = normalize_field_name_for_mapping(field_api_name)
                
                found_mappings = []
                
                # Acessa os dados de mapeamento brutos para este DMO
                mapping_data = raw_mapping_by_dmo.get(dmo_api_name)
                if mapping_data and 'objectSourceTargetMaps' in mapping_data:
                    for obj_map in mapping_data['objectSourceTargetMaps']:
                        for field_map in obj_map.get('fieldMappings', []):
                            api_target_field = field_map.get('targetFieldDeveloperName')
                            if not api_target_field: continue
                            
                            # Normaliza a chave disponível na API para comparação
                            available_key = normalize_field_name_for_mapping(api_target_field)
                            
                            # Comparação direta e explícita
                            if target_key_to_find == available_key:
                                found_mappings.append({
                                    'OBJECT_MAPPING_ID': obj_map.get('developerName', ''),
                                    'FIELD_MAPPING_ID': field_map.get('developerName', '')
                                })
                
                if found_mappings:
                    row['OBJECT_MAPPING_ID'] = ", ".join(m['OBJECT_MAPPING_ID'] for m in found_mappings)
                    row['FIELD_MAPPING_ID'] = ", ".join(m['FIELD_MAPPING_ID'] for m in found_mappings)
                else:
                    row['OBJECT_MAPPING_ID'] = 'Não possuí mapeamento'
                    row['FIELD_MAPPING_ID'] = 'Não possuí mapeamento'
            
            logging.info("✅ IDs de mapeamento adicionados ao relatório.")
        
        logging.info("--- FASE 4/4: Gerando relatórios... ---")
        write_csv_report(config.UNUSED_FIELDS_CSV, unused_field_results, ['DELETAR', 'DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'REASON', 'CREATED_BY_NAME', 'OBJECT_MAPPING_ID', 'FIELD_MAPPING_ID', 'DELETION_IDENTIFIER'])
        write_csv_report(config.USED_FIELDS_CSV, used_field_results, ['DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'USAGE_COUNT', 'USAGE_TYPES', 'CREATED_BY_NAME', 'DELETION_IDENTIFIER'])

if __name__ == "__main__":
    start_time = time.time()
    try: asyncio.run(main())
    except Exception as e: logging.critical(f"❌ Ocorreu um erro fatal: {e}", exc_info=True)
    finally: logging.info(f"\n🏁 Auditoria concluída. Tempo total: {time.time() - start_time:.2f} segundos.")