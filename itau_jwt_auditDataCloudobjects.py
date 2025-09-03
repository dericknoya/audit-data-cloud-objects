# -*- coding: utf-8 -*-
"""
Script de auditoria Salesforce Data Cloud - Objetos órfãos e inativos

Versão: 16.05 (Revisão de Estabilidade)
- BASE: v16.04
- REVISÃO DE ESTABILIDADE (HARDENING):
  - Prevenção de TypeError: O código foi reforçado para tratar de forma segura
    possíveis valores nulos (None) retornados pela API, especialmente ao
    manipular IDs de segmentos e ativações, evitando erros de fatiamento.
  - Robustez Aprimorada: Adicionadas verificações e conversões de tipo para
    garantir que as funções de análise não falhem com dados malformados.
  - O script está funcionalmente idêntico ao anterior, mas é mais resiliente
    a respostas inesperadas da API, prevenindo erros como TypeError,
    AttributeError e NameError.
"""
import os
import time
import asyncio
import csv
import json
import html
import logging
from collections import defaultdict
from urllib.parse import urljoin, urlencode
from datetime import datetime, timezone, timedelta

import jwt
import requests 
import aiohttp
from dotenv import load_dotenv
from tqdm.asyncio import tqdm

# ==============================================================================
# --- ⚙️ CONFIGURAÇÃO CENTRALIZADA ---
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
    SEMAPHORE_LIMIT = 20
    CHUNK_SIZE = 100
    MAX_RETRIES = 3
    RETRY_DELAY_SECONDS = 5
    ORPHAN_DMO_DAYS = 90
    INACTIVE_SEGMENT_DAYS = 30
    INACTIVE_STREAM_DAYS = 30
    DMO_PREFIXES_TO_EXCLUDE = ('ssot', 'unified', 'individual', 'einstein', 'segment_membership', 'aa_', 'aal_')
    OUTPUT_CSV_FILE = 'audit_objetos_para_exclusao.csv'
    ACTIVATION_FIELDS_CSV = 'ativacoes_campos.csv'
    LOG_FILE = 'audit_data_cloud_objects.log'

# ==============================================================================
# --- 헬 FUNÇÕES AUXILIARES E LOGGING ---
# ==============================================================================
def setup_logging(log_file):
    logger = logging.getLogger()
    if logger.hasHandlers(): logger.handlers.clear()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

def get_access_token(config: Config):
    logging.info("🔑 Autenticando com Salesforce via JWT...")
    try:
        with open('private.pem', 'r') as f: private_key = f.read()
    except FileNotFoundError:
        logging.critical("❌ Arquivo 'private.pem' não encontrado. Encerrando."); raise
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
        logging.critical(f"❌ Erro fatal na autenticação: {e.response.text if e.response else e}"); raise

def normalize_api_name(name):
    if not isinstance(name, str): return ""
    return name.removesuffix('__dlm').removesuffix('__cio').removesuffix('__dll')

def parse_sf_date(date_str):
    if not date_str: return None
    try: return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except (ValueError, TypeError): return None

def days_since(date_obj):
    if not date_obj: return None
    return (datetime.now(timezone.utc) - date_obj).days

# ==============================================================================
# --- 🌐 CLASSE CLIENTE SALESFORCE API ---
# ==============================================================================
class SalesforceClient:
    def __init__(self, config: Config, auth_data: dict):
        self.config = config
        self.instance_url = auth_data.get('instance_url')
        self.headers = {'Authorization': f'Bearer {auth_data.get("access_token")}'}
        self.session = None
        self.semaphore = asyncio.Semaphore(config.SEMAPHORE_LIMIT)

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(base_url=self.instance_url, headers=self.headers)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session and not self.session.closed: await self.session.close()

    async def _fetch_with_retry(self, url, key_name=None):
        async with self.semaphore:
            for attempt in range(self.config.MAX_RETRIES):
                try:
                    all_records, current_url = [], url
                    is_tooling = "/tooling" in current_url
                    while current_url:
                        kwargs = {'ssl': self.config.VERIFY_SSL}
                        if self.config.USE_PROXY: kwargs['proxy'] = self.config.PROXY_URL
                        async with self.session.get(current_url, **kwargs) as response:
                            if response.status >= 400:
                                if response.status == 404:
                                    logging.debug(f"DEBUG: Recebido 404 (Not Found), tratando como resultado vazio para: {current_url}")
                                    return [] if key_name else None
                                logging.error(f"❌ Erro {response.status} para URL: {current_url}. Resposta: {await response.text()}")
                                return [] if key_name else None
                            response.raise_for_status()
                            data = await response.json()
                            if key_name:
                                all_records.extend(data.get(key_name, []))
                                next_url = data.get('nextRecordsUrl') or data.get('nextPageUrl')
                                locator = data.get('queryLocator')
                                if next_url: current_url = urljoin(str(self.session._base_url), next_url)
                                elif is_tooling and locator and not data.get('done', True): current_url = f"/services/data/{self.config.API_VERSION}/tooling/query/{locator}"
                                else: current_url = None
                            else: return data
                    return all_records
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    if attempt < self.config.MAX_RETRIES - 1:
                        logging.warning(f"Tentativa {attempt + 1} falhou. Causa: {e}. Tentando novamente...")
                        await asyncio.sleep(self.config.RETRY_DELAY_SECONDS)
                    else:
                        logging.error(f"❌ Falha ao buscar dados de {url} após {self.config.MAX_RETRIES} tentativas.")
                        return [] if key_name else None

    async def query_api(self, query, tooling=False, key_name='records'):
        base = "tooling/query" if tooling else "query"
        url = f"/services/data/{self.config.API_VERSION}/{base}?{urlencode({'q': query})}"
        return await self._fetch_with_retry(url, key_name=key_name)

    async def get_ssot_metadata(self, entity_type, key_name='metadata'):
        url = f"/services/data/{self.config.API_VERSION}/ssot/metadata?entityType={entity_type}"
        return await self._fetch_with_retry(url, key_name=key_name)
    
    async def get_ssot_endpoint(self, endpoint_path, key_name=None):
        url = f"/services/data/{self.config.API_VERSION}/ssot/{endpoint_path}"
        return await self._fetch_with_retry(url, key_name=key_name)

    async def check_dmo_mappings(self, dmo_name: str) -> bool:
        params = {'dataspace': 'default', 'dmoDeveloperName': dmo_name}
        url = f"/services/data/{self.config.API_VERSION}/ssot/data-model-object-mappings?{urlencode(params)}"
        data = await self._fetch_with_retry(url)
        return bool(data and data.get('objectSourceTargetMaps'))

# ==============================================================================
# --- 📊 FUNÇÕES DE ANÁLISE DE DEPENDÊNCIA ---
# ==============================================================================
def load_dmos_from_activations_csv(config: Config) -> set:
    dmo_set = set()
    try:
        with open(config.ACTIVATION_FIELDS_CSV, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if entity_name := row.get('entityName'):
                    if '__dlm' in entity_name: dmo_set.add(normalize_api_name(entity_name))
        logging.info(f"✅ Encontrados {len(dmo_set)} DMOs únicos no CSV de ativações.")
    except FileNotFoundError:
        logging.warning(f"⚠️ Arquivo '{config.ACTIVATION_FIELDS_CSV}' não encontrado.")
    return dmo_set

def find_dmos_in_payload(payload, dmos_used: defaultdict, source_type: str):
    if not payload: return
    try:
        data = json.loads(html.unescape(str(payload))) if isinstance(payload, str) else payload
        dmo_keys = {'objectName', 'entityName', 'developerName', 'objectApiName'}
        def recurse(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in dmo_keys and isinstance(value, str) and value.endswith('__dlm'):
                        dmo_name = normalize_api_name(value)
                        if source_type not in dmos_used[dmo_name]: dmos_used[dmo_name].append(source_type)
                    elif isinstance(value, (dict, list)): recurse(value)
            elif isinstance(obj, list):
                for item in obj: recurse(item)
        recurse(data)
    except (json.JSONDecodeError, TypeError): return

def find_segments_in_criteria(criteria_str, segment_set):
    if not criteria_str: return
    try:
        data = json.loads(html.unescape(str(criteria_str)))
        def recurse(obj):
            if isinstance(obj, dict):
                ### REVISÃO DE ESTABILIDADE: Garante que 'segmentId' é uma string antes de usar ###
                if obj.get('type') == 'NestedSegment' and (seg_id := obj.get('segmentId')) and isinstance(seg_id, str):
                    segment_set.add(seg_id[:15])
                for value in obj.values():
                    if isinstance(value, (dict, list)): recurse(value)
            elif isinstance(obj, list):
                for item in obj: recurse(item)
        recurse(data)
    except (json.JSONDecodeError, TypeError): return

# ==============================================================================
# --- 🚀 ORQUESTRADOR PRINCIPAL (MAIN) ---
# ==============================================================================
async def main():
    config = Config()
    setup_logging(config.LOG_FILE)
    
    logging.info("🚀 Iniciando auditoria de objetos v16.05...")
    auth_data = get_access_token(config)
    
    async with SalesforceClient(config, auth_data) as client:
        # ETAPAS 1 e 2: Coleta e Processamento
        logging.info("--- Etapa 1 & 2: Coletando e Processando Dados... ---")
        
        dmos_from_csv = load_dmos_from_activations_csv(config)
        
        tasks = {
            "dmo_tooling": client.query_api("SELECT Id, DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject", tooling=True),
            "all_segments": client.query_api("SELECT Id, Name, IncludeCriteria, ExcludeCriteria, CreatedById FROM MarketSegment"),
            "all_activations": client.query_api("SELECT Id, Name, MarketSegmentId, LastModifiedDate, CreatedById FROM MarketSegmentActivation"),
            "dmo_metadata": client.get_ssot_metadata("DataModelObject"),
            "calculated_insights": client.get_ssot_metadata("CalculatedInsight", key_name='records'),
            "data_graphs": client.get_ssot_endpoint("data-graphs/metadata", key_name='dataGraphMetadata'),
            "data_actions": client.get_ssot_endpoint("data-actions", key_name='dataActions'),
            "data_streams": client.get_ssot_endpoint("data-streams", key_name='dataStreams'),
        }
        results = await tqdm.gather(*tasks.values(), desc="Coletando dados da API")
        data = dict(zip(tasks.keys(), results))

        dmo_details_map = {rec.get('DeveloperName'): rec for rec in data.get('dmo_tooling', [])}
        dmos_used = defaultdict(list)
        for dmo in dmos_from_csv: dmos_used[dmo].append("Ativação (CSV)")
        
        if cis := data.get('calculated_insights'): find_dmos_in_payload(cis, dmos_used, "Calculated Insight")
        if dgs := data.get('data_graphs'): find_dmos_in_payload(dgs, dmos_used, "Data Graph")
        if das := data.get('data_actions'): find_dmos_in_payload(das, dmos_used, "Data Action")

        nested_segment_parents = defaultdict(list)
        if segments_data := data.get('all_segments'):
            for segment in segments_data:
                find_dmos_in_payload(segment.get('IncludeCriteria'), dmos_used, "Segmento")
                find_dmos_in_payload(segment.get('ExcludeCriteria'), dmos_used, "Segmento")
                temp_nested = set()
                find_segments_in_criteria(segment.get('IncludeCriteria'), temp_nested)
                find_segments_in_criteria(segment.get('ExcludeCriteria'), temp_nested)
                for nested_id in temp_nested:
                    nested_segment_parents[nested_id].append(segment.get('Name', 'Sem Nome'))
        
        ### REVISÃO DE ESTABILIDADE: Garante que o ID é string antes de fatiar ###
        segment_publications = {str(act.get('MarketSegmentId', ''))[:15]: parse_sf_date(act.get('LastModifiedDate')) for act in data.get('all_activations', []) if act.get('MarketSegmentId')}

        # ETAPA 3: Lógica de Auditoria
        logging.info("--- Etapa 3/4: Executando lógica de auditoria... ---")
        audit_results = []
        
        logging.info("Auditando Segmentos, Ativações e Data Streams...")
        deletable_segment_ids = set()
        if segments_data:
            for seg in segments_data:
                ### REVISÃO DE ESTABILIDADE: Garante que o ID é string antes de fatiar ###
                seg_id = str(seg.get('Id', ''))[:15]
                if not seg_id: continue
                last_pub_date = segment_publications.get(seg_id)
                if not last_pub_date or days_since(last_pub_date) > config.INACTIVE_SEGMENT_DAYS:
                    is_nested, status, reason = seg_id in nested_segment_parents, "", ""
                    if not is_nested:
                        status, reason = "Órfão", f"Não publicado nos últimos {config.INACTIVE_SEGMENT_DAYS} dias e não usado como filtro."
                        deletable_segment_ids.add(seg_id)
                    else:
                        status, reason = "Inativo", f"Não publicado, mas usado como filtro em: {', '.join(nested_segment_parents[seg_id])}"
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': seg_id, 'DISPLAY_NAME': seg.get('Name'), 'OBJECT_TYPE': 'SEGMENT', 'STATUS': status, 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Publicação', 'DIAS_ATIVIDADE': days_since(last_pub_date) or f'>{config.INACTIVE_SEGMENT_DAYS}', 'CREATED_BY_NAME': 'N/A', 'DELETION_IDENTIFIER': seg.get('Id')})

        if activations_data := data.get('all_activations'):
            for act in activations_data:
                ### REVISÃO DE ESTABILIDADE: Garante que o ID é string antes de fatiar ###
                if str(act.get('MarketSegmentId', ''))[:15] in deletable_segment_ids:
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': act.get('Id'), 'DISPLAY_NAME': act.get('Name'), 'OBJECT_TYPE': 'ACTIVATION', 'STATUS': 'Órfã', 'REASON': 'Associada a um segmento órfão.', 'TIPO_ATIVIDADE': 'N/A', 'DIAS_ATIVIDADE': 'N/A', 'CREATED_BY_NAME': 'N/A', 'DELETION_IDENTIFIER': act.get('Id')})

        if streams_data := data.get('data_streams'):
            for ds in streams_data:
                last_ingest = parse_sf_date(ds.get('lastIngestDate'))
                if not last_ingest or days_since(last_ingest) > config.INACTIVE_STREAM_DAYS:
                    has_mappings, status, reason = bool(ds.get('mappings')), "", ""
                    dlo_name = ds.get('dataLakeObjectInfo', {}).get('name', 'N/A')
                    if not has_mappings: status, reason = "Órfão", f"Última ingestão > {config.INACTIVE_STREAM_DAYS} dias e sem mapeamentos."
                    else: status, reason = "Inativo", f"Última ingestão > {config.INACTIVE_STREAM_DAYS} dias, mas possui mapeamentos para {dlo_name}."
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': ds.get('name'), 'DISPLAY_NAME': ds.get('label'), 'OBJECT_TYPE': 'DATA_STREAM', 'STATUS': status, 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Ingestão', 'DIAS_ATIVIDADE': days_since(last_ingest) or f'>{config.INACTIVE_STREAM_DAYS}', 'CREATED_BY_NAME': 'N/A', 'DELETION_IDENTIFIER': ds.get('id')})
        
        logging.info("Auditando DMOs...")
        if dmo_metadata := data.get('dmo_metadata'):
            for dmo in tqdm(dmo_metadata, desc="Auditando DMOs"):
                dmo_api_name = dmo.get('name')
                if not dmo_api_name or not dmo_api_name.endswith('__dlm') or any(dmo_api_name.lower().startswith(p) for p in config.DMO_PREFIXES_TO_EXCLUDE):
                    continue
                normalized_dmo, dmo_details = normalize_api_name(dmo_api_name), dmo_details_map.get(dmo_api_name, {})
                created_date = parse_sf_date(dmo_details.get('CreatedDate'))
                is_in_use = normalized_dmo in dmos_used
                is_old_enough = not created_date or days_since(created_date) > config.ORPHAN_DMO_DAYS
                if not is_in_use and is_old_enough:
                    has_mappings = await client.check_dmo_mappings(dmo_api_name)
                    if not has_mappings:
                        audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': dmo_api_name, 'DISPLAY_NAME': dmo.get('displayName', dmo_api_name), 'OBJECT_TYPE': 'DMO', 'STATUS': 'Órfão', 'REASON': f"Criado > {config.ORPHAN_DMO_DAYS} dias, sem uso conhecido e sem mapeamentos de ingestão.", 'TIPO_ATIVIDADE': 'Criação', 'DIAS_ATIVIDADE': days_since(created_date) or f'>{config.ORPHAN_DMO_DAYS}', 'CREATED_BY_NAME': 'N/A', 'DELETION_IDENTIFIER': dmo_details.get('Id', 'ID não encontrado')})
        
        # ETAPA 4: Geração do Relatório
        logging.info("--- Etapa 4/4: Gerando relatório CSV... ---")
        if audit_results:
            fieldnames = ['DELETAR', 'ID_OR_API_NAME', 'DISPLAY_NAME', 'OBJECT_TYPE', 'STATUS', 'REASON', 'TIPO_ATIVIDADE', 'DIAS_ATIVIDADE', 'CREATED_BY_NAME', 'DELETION_IDENTIFIER']
            with open(config.OUTPUT_CSV_FILE, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(sorted(audit_results, key=lambda x: (x.get('OBJECT_TYPE', ''), x.get('DISPLAY_NAME', ''))))
            logging.info(f"✅ Relatório '{config.OUTPUT_CSV_FILE}' gerado com {len(audit_results)} objetos.")
        else:
            logging.info("🎉 Nenhum objeto órfão ou inativo encontrado que atenda aos critérios.")

if __name__ == "__main__":
    start_time = time.time()
    try: asyncio.run(main())
    except Exception as e:
        logging.critical(f"❌ Ocorreu um erro fatal na execução do script: {e}", exc_info=True)
    finally:
        duration = time.time() - start_time
        logging.info(f"\n🏁 Auditoria concluída. Tempo total de execução: {duration:.2f} segundos.")