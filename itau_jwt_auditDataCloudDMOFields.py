# -*- coding: utf-8 -*-
"""
Este script audita uma instância do Salesforce Data Cloud para identificar 
campos de DMOs (Data Model Objects) utilizados e não utilizados.

Versão: 23.0 (Correção de Autenticação em Redes Restritivas)
- CORREÇÃO CRÍTICA: A lógica de autenticação foi revertida para usar a 
  biblioteca 'requests' (síncrona), espelhando o funcionamento do script de
  objetos que opera com sucesso em ambientes com proxies complexos.
- O restante do script permanece 100% assíncrono com 'aiohttp' para garantir
  máxima performance na coleta e processamento de dados.
- MANTÉM: Todos os mecanismos de robustez (retry, semáforo, Bulk API) e 
  funcionalidades (análise de CSV, etc.) das versões anteriores.

================================================================================
REGRAS DE NEGÓCIO PARA CLASSIFICAÇÃO DE CAMPOS
================================================================================

Este script gera dois relatórios para fornecer uma visão completa do uso dos 
campos de DMOs customizados. As regras abaixo definem como um campo é 
classificado em cada relatório.

--------------------------------------------------------------------------------
REGRAS PARA UM CAMPO SER CONSIDERADO "UTILIZADO"
--------------------------------------------------------------------------------
Um campo é listado no relatório 'audit_campos_dmo_utilizados.csv' se UMA OU MAIS 
das seguintes condições for verdadeira:

1.  É encontrado nos critérios de pelo menos um **Segmento**.
2.  É encontrado em qualquer parte da configuração de pelo menos uma **Ativação (via API)**.
3.  É encontrado em qualquer parte da definição de pelo menos um **Calculated Insight**.
4.  É encontrado na definição de um **Ponto de Contato de Ativação**.
5.  Seu DMO pai foi criado **nos últimos 90 dias**.
6.  É encontrado no arquivo de mapeamento manual **ativacoes_campos.csv**.

--------------------------------------------------------------------------------
REGRAS PARA UM CAMPO SER CONSIDERADO "NÃO UTILIZADO"
--------------------------------------------------------------------------------
Um campo é listado no relatório 'audit_campos_dmo_nao_utilizados.csv' SOMENTE 
SE TODAS as seguintes condições forem verdadeiras:

1.  **NÃO é encontrado** em nenhum Segmento, Ativação, Calculated Insight, 
    Ponto de Contato de Ativação ou no CSV de ativações.
2.  Seu DMO pai foi criado **há mais de 90 dias**.
3.  O campo e seu DMO **não são** objetos de sistema do Salesforce (o script 
    ignora nomes com prefixos como 'ssot__', 'unified__', 'aa_', 'aal_', etc.).

================================================================================
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
import requests # <--- ADICIONADO para autenticação robusta
import aiohttp
from dotenv import load_dotenv
from tqdm.asyncio import tqdm

# ==============================================================================
# --- ⚙️ CONFIGURAÇÃO ---
# ==============================================================================
load_dotenv()

class Config:
    # Conexão
    USE_PROXY = os.getenv("USE_PROXY", "True").lower() == "true"
    PROXY_URL = os.getenv("PROXY_URL")
    VERIFY_SSL = os.getenv("VERIFY_SSL", "False").lower() == "true"
    API_VERSION = "v60.0"
    
    # Salesforce JWT
    SF_CLIENT_ID = os.getenv("SF_CLIENT_ID")
    SF_USERNAME = os.getenv("SF_USERNAME")
    SF_AUDIENCE = os.getenv("SF_AUDIENCE")
    SF_LOGIN_URL = os.getenv("SF_LOGIN_URL")
    
    # Performance e Robustez
    SEMAPHORE_LIMIT = 50
    BULK_CHUNK_SIZE = 400
    MAX_RETRIES = 3
    RETRY_DELAY_SECONDS = 5
    
    # Regras de Negócio
    GRACE_PERIOD_DAYS = 90
    DMO_PREFIXES_TO_EXCLUDE = ('ssot', 'unified', 'individual', 'einstein', 'segment_membership', 'aa_', 'aal_')
    FIELD_PREFIXES_TO_EXCLUDE = ('ssot__', 'KQ_')
    SPECIFIC_FIELDS_TO_EXCLUDE = {'DataSource__c', 'DataSourceObject__c', 'InternalOrganization__c'}
    
    # Nomes de Arquivos
    USED_FIELDS_CSV = 'audit_campos_dmo_utilizados.csv'
    UNUSED_FIELDS_CSV = 'audit_campos_dmo_nao_utilizados.csv'
    DEBUG_CSV = 'debug_dados_de_uso.csv'
    ACTIVATION_FIELDS_CSV = 'ativacoes_campos.csv'
    
    # Expressão Regular
    FIELD_NAME_PATTERN = re.compile(r'["\'](?:fieldApiName|fieldName|attributeName|developerName)["\']\s*:\s*["\']([^"\']+)["\']')

# Configuração do Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ==============================================================================
# --- Helpers & Funções Auxiliares ---
# ==============================================================================
def get_access_token():
    """Realiza a autenticação JWT de forma síncrona usando a biblioteca requests."""
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

def read_activation_fields_from_csv(file_path):
    """Lê um arquivo CSV para extrair um conjunto de nomes de API de campos utilizados."""
    used_fields = set()
    try:
        with open(file_path, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            # A coluna com o API name do campo deve se chamar 'FIELD_API_NAME'
            field_column_name = 'FIELD_API_NAME'
            if field_column_name not in reader.fieldnames:
                 logging.warning(f"⚠️ Arquivo '{file_path}' encontrado, mas a coluna esperada '{field_column_name}' não existe. Pulando análise deste arquivo.")
                 return used_fields
            for row in reader:
                if field_api_name := row.get(field_column_name):
                    used_fields.add(field_api_name.strip())
        logging.info(f"✅ Arquivo '{file_path}' lido. {len(used_fields)} campos únicos encontrados em uso.")
    except FileNotFoundError:
        logging.warning(f"⚠️ Arquivo de uso de ativações '{file_path}' não encontrado. A auditoria prosseguirá sem esta fonte de dados.")
    except Exception as e:
        logging.error(f"❌ Erro inesperado ao ler o arquivo '{file_path}': {e}")
    return used_fields

def parse_sf_date(date_str):
    """Converte uma string de data do Salesforce para um objeto datetime ciente do fuso horário."""
    if not date_str: return None
    try:
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return None

def days_since(date_obj):
    """Calcula o número de dias desde uma data até agora."""
    if not date_obj: return None
    return (datetime.now(timezone.utc) - date_obj).days

# ==============================================================================
# --- Salesforce API Client ---
# ==============================================================================
class SalesforceClient:
    """Encapsula as chamadas à API do Salesforce com lógica de retry."""
    def __init__(self, config, auth_data):
        self.config = config
        self.access_token = auth_data['access_token']
        self.instance_url = auth_data['instance_url']
        self.session = None
        self.semaphore = asyncio.Semaphore(config.SEMAPHORE_LIMIT)

    async def __aenter__(self):
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.session = aiohttp.ClientSession(
            base_url=self.instance_url,
            headers=headers,
            connector=aiohttp.TCPConnector(ssl=self.config.VERIFY_SSL)
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session and not self.session.closed:
            await self.session.close()

    async def fetch_api_data(self, relative_url, key_name=None):
        """Busca dados de uma API REST com paginação e retentativas."""
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
                        logging.warning(f" Tentativa {attempt + 1} para {relative_url[:60]} falhou: {e}. Tentando novamente em {self.config.RETRY_DELAY_SECONDS}s...")
                        await asyncio.sleep(self.config.RETRY_DELAY_SECONDS)
                    else:
                        logging.error(f"❌ Todas as {self.config.MAX_RETRIES} tentativas para {relative_url[:60]} falharam."); raise e

    async def execute_query_job(self, query):
        """Executa uma query via Bulk API 2.0 com retentativas."""
        async with self.semaphore:
            for attempt in range(self.config.MAX_RETRIES):
                try:
                    job_url_path = f"/services/data/{self.config.API_VERSION}/jobs/query"
                    payload = {"operation": "query", "query": query, "contentType": "CSV"}
                    proxy = self.config.PROXY_URL if self.config.USE_PROXY else None
                    async with self.session.post(job_url_path, json=payload, proxy=proxy, ssl=self.config.VERIFY_SSL) as res:
                        res.raise_for_status(); job_info = await res.json(); job_id = job_info['id']
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
                        logging.warning(f" Tentativa {attempt + 1} do job de query '{query[:50]}...' falhou: {e}. Tentando novamente em {self.config.RETRY_DELAY_SECONDS}s...")
                        await asyncio.sleep(self.config.RETRY_DELAY_SECONDS)
                    else:
                        logging.error(f"❌ Todas as {self.config.MAX_RETRIES} tentativas para o job de query '{query[:50]}...' falharam."); raise e

    async def fetch_records_in_bulk(self, object_name, fields, record_ids):
        """Busca múltiplos registros em lotes usando a Bulk API."""
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
        """Busca usernames de usuários a partir de seus IDs."""
        if not user_ids: return {}
        users = await self.fetch_records_in_bulk('User', ['Id', 'Username'], list(user_ids))
        return {user['Id']: user.get('Username', 'Nome não encontrado') for user in users}

# ==============================================================================
# --- 📊 FUNÇÕES DE ANÁLISE E PROCESSAMENTO ---
# ==============================================================================
def find_fields_in_content(content_string, usage_type, object_name, object_api_name, used_fields_details, debug_data):
    """Usa regex para encontrar nomes de campos em uma string de conteúdo."""
    if not content_string: return
    debug_data.append({'SOURCE_OBJECT_TYPE': usage_type, 'SOURCE_OBJECT_ID': object_api_name, 'SOURCE_OBJECT_NAME': object_name, 'RAW_CONTENT': content_string})
    for match in Config.FIELD_NAME_PATTERN.finditer(html.unescape(str(content_string))):
        field_name = match.group(1)
        usage_context = {"usage_type": usage_type, "object_name": object_name, "object_api_name": object_api_name}
        used_fields_details[field_name].append(usage_context)

def write_csv_report(filename, data, headers):
    """Escreve uma lista de dicionários em um arquivo CSV."""
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
        
def classify_fields(all_dmo_fields, used_fields_details, dmo_creation_info, user_map):
    """Classifica todos os campos de DMOs em 'utilizados' ou 'não utilizados'."""
    logging.info("--- FASE 3/4: Classificando campos... ---")
    used_results, unused_results = [], []
    
    # Aplica a regra de carência de 90 dias
    for dmo_name, dmo_info in dmo_creation_info.items():
        created_date = parse_sf_date(dmo_info.get('CreatedDate'))
        if created_date and days_since(created_date) <= Config.GRACE_PERIOD_DAYS:
            if dmo_name in all_dmo_fields:
                for field_api_name in all_dmo_fields[dmo_name]['fields']:
                    usage_context = {"usage_type": "N/A (DMO Recém-criado)", "object_name": "DMO criado < 90 dias", "object_api_name": dmo_name}
                    if field_api_name not in used_fields_details: used_fields_details[field_api_name] = []
                    if not any(u['usage_type'] == usage_context['usage_type'] for u in used_fields_details[field_api_name]):
                        used_fields_details[field_api_name].append(usage_context)

    # Itera sobre todos os campos e classifica-os
    for dmo_name, data in all_dmo_fields.items():
        creator_id = dmo_creation_info.get(dmo_name, {}).get('CreatedById') or dmo_creation_info.get(dmo_name, {}).get('createdById')
        creator_name = user_map.get(creator_id, 'Desconhecido')
        
        for field_api_name, field_display_name in data['fields'].items():
            # Regra de exclusão de campos
            if any(field_api_name.startswith(p) for p in Config.FIELD_PREFIXES_TO_EXCLUDE) or field_api_name in Config.SPECIFIC_FIELDS_TO_EXCLUDE:
                continue
            
            if field_api_name in used_fields_details:
                usages = used_fields_details[field_api_name]
                used_results.append({'DMO_DISPLAY_NAME': data['displayName'], 'DMO_API_NAME': dmo_name, 'FIELD_DISPLAY_NAME': field_display_name, 'FIELD_API_NAME': field_api_name, 'USAGE_COUNT': len(usages), 'USAGE_TYPES': ", ".join(sorted(list(set(u['usage_type'] for u in usages)))), 'CREATED_BY_NAME': creator_name})
            else:
                unused_results.append({'DELETAR': 'NAO', 'DMO_DISPLAY_NAME': data['displayName'], 'DMO_API_NAME': dmo_name, 'FIELD_DISPLAY_NAME': field_display_name, 'FIELD_API_NAME': field_api_name, 'REASON': 'Não utilizado e DMO com mais de 90 dias', 'CREATED_BY_NAME': creator_name})
    
    logging.info(f"📊 Classificação concluída: {len(used_results)} campos utilizados, {len(unused_results)} campos não utilizados.")
    return used_results, unused_results

# ==============================================================================
# --- 🚀 ORQUESTRADOR PRINCIPAL ---
# ==============================================================================
async def main():
    """Função principal que orquestra todo o processo de auditoria."""
    logging.info("🚀 Iniciando auditoria de campos de DMO...")
    config = Config()
    
    # Autenticação síncrona primeiro para máxima compatibilidade de rede
    auth_data = get_access_token()
    
    # O cliente assíncrono é inicializado com os dados da autenticação já prontos
    async with SalesforceClient(config, auth_data) as client:
        logging.info("--- FASE 1/4: Coletando metadados e objetos... ---")
        
        tasks_to_run = {
            "dmo_tooling": client.fetch_api_data(f"/services/data/{config.API_VERSION}/tooling/query?{urlencode({'q': 'SELECT DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject'})}", 'records'),
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
        
        dmo_creation_info = {rec['DeveloperName']: rec for rec in data['dmo_tooling']}
        segment_ids = [rec['Id'] for rec in data['segments'] if rec.get('Id')]
        logging.info(f"Dados processáveis: {len(dmo_creation_info)} DMOs, {len(segment_ids)} Segmentos, {len(data['activations'])} Ativações.")
        
        all_creator_ids = set()
        for dmo_details in dmo_creation_info.values():
            if creator_id := (dmo_details.get('CreatedById') or dmo_details.get('createdById')):
                all_creator_ids.add(creator_id)
        
        segments_list, user_id_to_name_map = await asyncio.gather(
            client.fetch_records_in_bulk("MarketSegment", ["Id", "Name", "IncludeCriteria", "ExcludeCriteria"], segment_ids),
            client.fetch_users_by_id(all_creator_ids)
        )
        logging.info(f"✅ Detalhes de {len(segments_list)} segmentos e {len(user_id_to_name_map)} usuários coletados.")

        logging.info("--- FASE 2/4: Analisando o uso dos campos... ---")
        used_fields_details, debug_data = defaultdict(list), []

        fields_from_activation_csv = read_activation_fields_from_csv(config.ACTIVATION_FIELDS_CSV)
        for field_name in tqdm(fields_from_activation_csv, desc="Analisando campos do CSV de Ativações"):
            usage_context = {"usage_type": "Ativação (CSV Externo)", "object_name": config.ACTIVATION_FIELDS_CSV, "object_api_name": "N/A"}
            used_fields_details[field_name].append(usage_context)

        for seg in tqdm(segments_list, desc="Analisando Segmentos"):
            find_fields_in_content(seg.get('IncludeCriteria'), "Segmento", seg.get('Name'), seg.get('Id'), used_fields_details, debug_data)
            find_fields_in_content(seg.get('ExcludeCriteria'), "Segmento", seg.get('Name'), seg.get('Id'), used_fields_details, debug_data)
        for attr in tqdm(data['activations'], desc="Analisando Ativações"): find_fields_in_content(attr.get('QueryPath'), "Ativação", attr.get('Name'), attr.get('MarketSegmentActivationId'), used_fields_details, debug_data)
        for ci in tqdm(data['calculated_insights'], desc="Analisando CIs"): find_fields_in_content(json.dumps(ci), "Calculated Insight", ci.get('displayName'), ci.get('name'), used_fields_details, debug_data)
        for cp in tqdm(data['contact_points'], desc="Analisando Pontos de Contato"):
            find_fields_in_content(cp.get('ContactPointPath'), "Ponto de Contato", cp.get('Name'), cp.get('Id'), used_fields_details, debug_data)
            find_fields_in_content(cp.get('ContactPointFilterExpression'), "Ponto de Contato", cp.get('Name'), cp.get('Id'), used_fields_details, debug_data)

        all_dmo_fields = defaultdict(lambda: {'fields': {}, 'displayName': ''})
        for dmo in data['dmo_metadata']:
            dmo_name = dmo.get('name')
            if dmo_name and dmo_name.endswith('__dlm') and not any(dmo_name.lower().startswith(p) for p in config.DMO_PREFIXES_TO_EXCLUDE):
                all_dmo_fields[dmo_name]['displayName'] = dmo.get('displayName', dmo_name)
                for field in dmo.get('fields', []):
                    if field_name := field.get('name'): all_dmo_fields[dmo_name]['fields'][field_name] = field.get('displayName', field_name)

        used_field_results, unused_field_results = classify_fields(all_dmo_fields, used_fields_details, dmo_creation_info, user_id_to_name_map)

        logging.info("--- FASE 4/4: Gerando relatórios... ---")
        write_csv_report(config.UNUSED_FIELDS_CSV, unused_field_results, ['DELETAR', 'DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'REASON', 'CREATED_BY_NAME'])
        write_csv_report(config.USED_FIELDS_CSV, used_field_results, ['DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'USAGE_COUNT', 'USAGE_TYPES', 'CREATED_BY_NAME'])
        write_csv_report(config.DEBUG_CSV, debug_data, ['SOURCE_OBJECT_TYPE', 'SOURCE_OBJECT_ID', 'SOURCE_OBJECT_NAME', 'RAW_CONTENT'])

if __name__ == "__main__":
    start_time = time.time()
    try: asyncio.run(main())
    except Exception as e: logging.critical(f"❌ Ocorreu um erro fatal e o script foi interrompido: {e}", exc_info=True)
    finally: logging.info(f"\n🏁 Auditoria concluída. Tempo total de execução: {time.time() - start_time:.2f} segundos.")