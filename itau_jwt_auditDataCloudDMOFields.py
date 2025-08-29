# -*- coding: utf-8 -*-
"""
Este script audita uma instância do Salesforce Data Cloud para identificar 
campos de DMOs (Data Model Objects) utilizados e não utilizados.

Versão: 30.3 (Correção de Sintaxe na Query de CustomField)
- BASE: Código baseado na versão estável anterior.
- CORREÇÃO CRÍTICA: Corrigido o erro '400 Bad Request' na query da Tooling API
  que busca os IDs técnicos dos campos. A cláusula 'LIKE' agora tem o valor
  corretamente formatado com aspas simples ('%__dlm%').
- Nenhuma outra lógica funcional foi alterada para garantir a estabilidade.

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
    ACTIVATION_FIELDS_CSV_COLUMN = 'Fieldname' 
    FIELD_NAME_PATTERN = re.compile(r'["\'](?:fieldApiName|fieldName|attributeName|developerName)["\']\s*:\s*["\']([^"\']+)["\']')

# Configuração do Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ==============================================================================
# --- 헬 Helpers & Funções Auxiliares ---
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

def read_activation_fields_from_csv(config):
    used_fields = set()
    file_path = config.ACTIVATION_FIELDS_CSV
    field_column_name = config.ACTIVATION_FIELDS_CSV_COLUMN
    try:
        with open(file_path, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            if field_column_name not in reader.fieldnames:
                 logging.warning(f"⚠️ Arquivo '{file_path}' encontrado, mas a coluna esperada '{field_column_name}' não existe. Pulando análise deste arquivo.")
                 return used_fields
            for row in reader:
                if field_api_name := row.get(field_column_name):
                    used_fields.add(field_api_name.strip())
        logging.info(f"✅ Arquivo '{file_path}' lido. {len(used_fields)} campos únicos encontrados em uso.")
    except FileNotFoundError:
        logging.warning(f"⚠️ Arquivo '{file_path}' não encontrado. A auditoria prosseguirá sem esta fonte de dados.")
    except Exception as e:
        logging.error(f"❌ Erro inesperado ao ler o arquivo '{file_path}': {e}")
    return used_fields

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
                            logging.warning(f"⚠️ Recurso não encontrado (404) para {relative_url[:120]}. Isso é esperado para DMOs sem mapeamento.")
                            return None
                        logging.error(f"❌ Todas as {self.config.MAX_RETRIES} tentativas para {relative_url[:60]} falharam."); raise e
    
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
def find_fields_in_content(content_string, usage_type, object_name, object_api_name, used_fields_details):
    if not content_string: return
    for match in Config.FIELD_NAME_PATTERN.finditer(html.unescape(str(content_string))):
        field_name = match.group(1)
        usage_context = {"usage_type": usage_type, "object_name": object_name, "object_api_name": object_api_name}
        used_fields_details[field_name].append(usage_context)

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
    except IOError as e:
        logging.error(f"❌ Erro ao escrever o arquivo {filename}: {e}")
        
def classify_fields(all_dmo_fields, used_fields_details, dmo_creation_info, user_map, field_id_map):
    logging.info("--- FASE 3/4: Classificando campos... ---")
    used_results, unused_results = [], []
    for dmo_name, dmo_info in dmo_creation_info.items():
        created_date = parse_sf_date(dmo_info.get('CreatedDate'))
        if created_date and days_since(created_date) <= Config.GRACE_PERIOD_DAYS:
            full_dmo_name = f"{dmo_name}__dlm"
            if full_dmo_name in all_dmo_fields:
                for field_api_name in all_dmo_fields[full_dmo_name]['fields']:
                    usage_context = {"usage_type": "N/A (DMO Recém-criado)", "object_name": "DMO criado < 90 dias", "object_api_name": full_dmo_name}
                    if field_api_name not in used_fields_details: used_fields_details[field_api_name] = []
                    if not any(u['usage_type'] == usage_context['usage_type'] for u in used_fields_details[field_api_name]):
                        used_fields_details[field_api_name].append(usage_context)
    for dmo_name, data in all_dmo_fields.items():
        developer_name = normalize_api_name(dmo_name)
        dmo_details = dmo_creation_info.get(developer_name, {})
        creator_id = dmo_details.get('CreatedById') or dmo_details.get('createdById')
        creator_name = user_map.get(creator_id, 'Desconhecido')
        for field_api_name, field_display_name in data['fields'].items():
            if any(field_api_name.startswith(p) for p in Config.FIELD_PREFIXES_TO_EXCLUDE) or field_api_name in Config.SPECIFIC_FIELDS_TO_EXCLUDE:
                continue
            
            full_field_api_name = f"{dmo_name}.{field_api_name}"
            deletion_id = field_id_map.get(full_field_api_name, 'ID não encontrado')

            common_data = {
                'DMO_DISPLAY_NAME': data['displayName'], 'DMO_API_NAME': dmo_name,
                'FIELD_DISPLAY_NAME': field_display_name, 'FIELD_API_NAME': field_api_name,
                'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': deletion_id
            }

            if field_api_name in used_fields_details:
                usages = used_fields_details[field_api_name]
                used_results.append({
                    **common_data,
                    'USAGE_COUNT': len(usages),
                    'USAGE_TYPES': ", ".join(sorted(list(set(u['usage_type'] for u in usages))))
                })
            else:
                unused_results.append({
                    **common_data,
                    'DELETAR': 'NAO',
                    'REASON': 'Não utilizado e DMO com mais de 90 dias'
                })
    logging.info(f"📊 Classificação concluída: {len(used_results)} campos utilizados, {len(unused_results)} campos não utilizados.")
    return used_results, unused_results

# ==============================================================================
# --- 🚀 ORQUESTRADOR PRINCIPAL ---
# ==============================================================================
async def main():
    logging.info("🚀 Iniciando auditoria de campos de DMO...")
    config = Config()
    auth_data = get_access_token()
    async with SalesforceClient(config, auth_data) as client:
        logging.info("--- FASE 1/4: Coletando metadados e objetos... ---")
        
        # <<< INÍCIO DA CORREÇÃO (V30.3) >>>
        tooling_query_fields = "SELECT Id, DeveloperName, TableEnumOrId FROM CustomField WHERE TableEnumOrId LIKE '%__dlm%'"
        # <<< FIM DA CORREÇÃO (V30.3) >>>
        
        tasks_to_run = {
            "dmo_tooling": client.fetch_api_data(f"/services/data/{config.API_VERSION}/tooling/query?{urlencode({'q': 'SELECT DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject'})}", 'records'),
            "custom_fields": client.fetch_api_data(f"/services/data/{config.API_VERSION}/tooling/query?{urlencode({'q': tooling_query_fields})}", 'records'),
            "dmo_metadata": client.fetch_api_data(f"/services/data/{config.API_VERSION}/ssot/metadata?entityType=DataModelObject", 'metadata'),
            "segments": client.execute_query_job("SELECT Id FROM MarketSegment"),
            "activations": client.execute_query_job("SELECT QueryPath, Name, MarketSegmentActivationId FROM MktSgmntActvtnAudAttribute"),
            "calculated_insights": client.fetch_api_data(f"/services/data/{config.API_VERSION}/ssot/metadata?entityType=CalculatedInsight", 'metadata'),
            "contact_points": client.execute_query_job("SELECT Name, ContactPointFilterExpression, ContactPointPath, Id FROM MktSgmntActvtnContactPoint"),
        }
        
        task_results = await asyncio.gather(*tasks_to_run.values(), return_exceptions=True)
        data = {}
        for i, task_name in enumerate(tasks_to_run.keys()):
            result = task_results[i]
            if isinstance(result, Exception):
                logging.error(f"❌ A coleta de '{task_name}' falhou definitivamente: {result}")
                data[task_name] = []
            else: data[task_name] = result
        logging.info("✅ Coleta inicial de metadados concluída (com tratamento de falhas).")
        
        field_id_map = {f"{rec['TableEnumOrId']}.{rec['DeveloperName']}": rec['Id'] for rec in data.get('custom_fields', [])}
        logging.info(f"✅ {len(field_id_map)} IDs técnicos de campos customizados foram mapeados.")

        dmo_creation_info = {rec['DeveloperName']: rec for rec in data['dmo_tooling']}
        segment_ids = [rec['Id'] for rec in data['segments'] if rec.get('Id')]
        
        logging.info(f"Dados processáveis: {len(dmo_creation_info)} DMOs, {len(segment_ids)} Segmentos, {len(data['activations'])} Ativações.")
        
        dmo_creator_ids = set()
        for dmo_details in dmo_creation_info.values():
            if creator_id := (dmo_details.get('CreatedById') or dmo_details.get('createdById')):
                dmo_creator_ids.add(creator_id)
        
        segments_list, user_id_to_name_map = await asyncio.gather(
            client.fetch_records_in_bulk("MarketSegment", ["Id", "Name", "IncludeCriteria", "ExcludeCriteria"], segment_ids),
            client.fetch_users_by_id(dmo_creator_ids)
        )
        
        logging.info(f"✅ Detalhes de {len(segments_list)} segmentos e {len(user_id_to_name_map)} usuários coletados.")

        logging.info("--- FASE 2/4: Analisando o uso dos campos... ---")
        used_fields_details = defaultdict(list)

        fields_from_activation_csv = read_activation_fields_from_csv(config)
        for field_name in tqdm(fields_from_activation_csv, desc="Analisando campos do CSV de Ativações"):
            usage_context = {"usage_type": "Ativação (CSV Externo)", "object_name": config.ACTIVATION_FIELDS_CSV, "object_api_name": "N/A"}
            used_fields_details[field_name].append(usage_context)

        for seg in tqdm(segments_list, desc="Analisando Segmentos"):
            find_fields_in_content(seg.get('IncludeCriteria'), "Segmento", seg.get('Name'), seg.get('Id'), used_fields_details)
            find_fields_in_content(seg.get('ExcludeCriteria'), "Segmento", seg.get('Name'), seg.get('Id'), used_fields_details)
        for attr in tqdm(data['activations'], desc="Analisando Ativações"): find_fields_in_content(attr.get('QueryPath'), "Ativação", attr.get('Name'), attr.get('MarketSegmentActivationId'), used_fields_details)
        for ci in tqdm(data['calculated_insights'], desc="Analisando CIs"): find_fields_in_content(json.dumps(ci), "Calculated Insight", ci.get('displayName'), ci.get('name'), used_fields_details)
        for cp in tqdm(data['contact_points'], desc="Analisando Pontos de Contato"):
            find_fields_in_content(cp.get('ContactPointPath'), "Ponto de Contato", cp.get('Name'), cp.get('Id'), used_fields_details)
            find_fields_in_content(cp.get('ContactPointFilterExpression'), "Ponto de Contato", cp.get('Name'), cp.get('Id'), used_fields_details)

        all_dmo_fields = defaultdict(lambda: {'fields': {}, 'displayName': ''})
        for dmo in data['dmo_metadata']:
            dmo_name = dmo.get('name')
            if dmo_name and dmo_name.endswith('__dlm') and not any(dmo_name.lower().startswith(p) for p in config.DMO_PREFIXES_TO_EXCLUDE):
                all_dmo_fields[dmo_name]['displayName'] = dmo.get('displayName', dmo_name)
                for field in dmo.get('fields', []):
                    if field_name := field.get('name'): all_dmo_fields[dmo_name]['fields'][field_name] = field.get('displayName', field_name)

        used_field_results, unused_field_results = classify_fields(all_dmo_fields, used_fields_details, dmo_creation_info, user_id_to_name_map, field_id_map)

        if unused_field_results:
            logging.info("--- FASE BÔNUS: Buscando IDs de mapeamento para campos não utilizados ---")
            
            unused_dmos = sorted(list({row['DMO_API_NAME'] for row in unused_field_results}))
            
            mapping_tasks = [client.fetch_dmo_mappings(dmo_name) for dmo_name in unused_dmos]
            all_mapping_data = await tqdm.gather(*mapping_tasks, desc="Buscando Mapeamentos de DMOs")

            mappings_lookup = defaultdict(dict)
            for dmo_name, mapping_data in zip(unused_dmos, all_mapping_data):
                if not mapping_data or 'objectSourceTargetMaps' not in mapping_data: continue
                for obj_map in mapping_data['objectSourceTargetMaps']:
                    obj_map_id = obj_map.get('developerName')
                    for field_map in obj_map.get('fieldMappings', []):
                        field_map_id = field_map.get('developerName')
                        target_field = field_map.get('targetFieldDeveloperName')
                        if target_field:
                            mappings_lookup[dmo_name][target_field] = {'OBJECT_MAPPING_ID': obj_map_id, 'FIELD_MAPPING_ID': field_map_id}
            
            for row in unused_field_results:
                mapping_info = mappings_lookup.get(row['DMO_API_NAME'], {}).get(row['FIELD_API_NAME'], {})
                row['OBJECT_MAPPING_ID'] = mapping_info.get('OBJECT_MAPPING_ID', 'Não possuí mapeamento')
                row['FIELD_MAPPING_ID'] = mapping_info.get('FIELD_MAPPING_ID', 'Não possuí mapeamento')
            logging.info("✅ IDs de mapeamento adicionados ao relatório.")

        logging.info("--- FASE 4/4: Gerando relatórios... ---")
        header_unused = ['DELETAR', 'DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'REASON', 'CREATED_BY_NAME', 'OBJECT_MAPPING_ID', 'FIELD_MAPPING_ID', 'DELETION_IDENTIFIER']
        write_csv_report(config.UNUSED_FIELDS_CSV, unused_field_results, header_unused)
        
        header_used = ['DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'USAGE_COUNT', 'USAGE_TYPES', 'CREATED_BY_NAME', 'DELETION_IDENTIFIER']
        write_csv_report(config.USED_FIELDS_CSV, used_field_results, header_used)

if __name__ == "__main__":
    start_time = time.time()
    try: asyncio.run(main())
    except Exception as e: logging.critical(f"❌ Ocorreu um erro fatal e o script foi interrompido: {e}", exc_info=True)
    finally: logging.info(f"\n🏁 Auditoria concluída. Tempo total de execução: {time.time() - start_time:.2f} segundos.")