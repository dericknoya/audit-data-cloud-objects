# -*- coding: utf-8 -*-
"""
Script de auditoria Salesforce Data Cloud - Objetos órfãos e inativos

Versão: 22.02 (Lógica de Fontes Corrigida e API v64.0)
- BASE: v22.01
- CORREÇÃO CRÍTICA (Fonte de Dados para Mapeamentos): A lógica foi reestruturada
  para seguir o padrão correto de uso das APIs:
  1. A lista principal de DMOs para auditoria agora vem do endpoint de metadados
     da SSOT API, que contém o nome de API completo e o nome de exibição.
  2. A consulta à Tooling API (MktDataModelObject) é usada exclusivamente para
     enriquecer os dados com 'CreatedById' e 'CreatedDate'.
  Isso garante que o filtro de DMOs de sistema e as chamadas à API de
  mapeamentos utilizem o identificador correto.
- CORREÇÃO (API Version): A versão da API foi fixada em 'v64.0'.
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
    API_VERSION = "v64.0"
    SF_CLIENT_ID = os.getenv("SF_CLIENT_ID")
    SF_USERNAME = os.getenv("SF_USERNAME")
    SF_AUDIENCE = os.getenv("SF_AUDIENCE")
    SF_LOGIN_URL = os.getenv("SF_LOGIN_URL")
    SEMAPHORE_LIMIT = 5
    MAX_RETRIES = 3
    RETRY_DELAY_SECONDS = 5
    ORPHAN_DMO_DAYS = 90
    INACTIVE_SEGMENT_DAYS = 30
    INACTIVE_STREAM_DAYS = 30
    DMO_PREFIXES_TO_EXCLUDE = ('ssot_', 'unified_', 'individual_', 'einstein_', 'segment_membership_', 'aa_', 'aal_')
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
    
    async def get_ssot_endpoint(self, endpoint_path, key_name=None):
        url = f"/services/data/{self.config.API_VERSION}/ssot/{endpoint_path}"
        return await self._fetch_with_retry(url, key_name=key_name)
    
    async def fetch_dmo_mapping_details(self, dmo_name: str):
        params = {'dataspace': 'default', 'dmoDeveloperName': dmo_name}
        url = f"/services/data/{self.config.API_VERSION}/ssot/data-model-object-mappings?{urlencode(params)}"
        return await self._fetch_with_retry(url)

# ==============================================================================
# --- 📊 FUNÇÕES DE ANÁLISE DE DEPENDÊNCIA ---
# ==============================================================================
def load_dmos_from_activations_csv(config: Config) -> set:
    dmo_set = set()
    try:
        with open(config.ACTIVATION_FIELDS_CSV, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                row_lower = {k.lower(): v for k, v in row.items() if k is not None}
                if entity_name := row_lower.get('entityname'):
                    if '__dlm' in entity_name:
                        dmo_set.add(normalize_api_name(entity_name))
        logging.info(f"✅ Encontrados {len(dmo_set)} DMOs únicos no CSV de ativações.")
    except FileNotFoundError:
        logging.warning(f"⚠️ Arquivo '{config.ACTIVATION_FIELDS_CSV}' não encontrado.")
    except Exception as e:
        logging.error(f"❌ Erro inesperado ao ler o CSV de ativações: {e}")
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
    
    logging.info("🚀 Iniciando auditoria de objetos v22.02...")
    auth_data = get_access_token(config)
    
    async with SalesforceClient(config, auth_data) as client:
        # ETAPA 1: Coleta de Dados Primários
        logging.info("--- Etapa 1/4: Coletando dados primários... ---")
        
        tasks = {
            "dmo_tooling": client.query_api("SELECT Id, DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject", tooling=True),
            "all_segments": client.query_api("SELECT Id, Name, IncludeCriteria, ExcludeCriteria, CreatedById FROM MarketSegment"),
            "all_activations": client.query_api("SELECT Id, Name, MarketSegmentId, LastModifiedDate, CreatedById FROM MarketSegmentActivation"),
            "datastream_sobjects": client.query_api("SELECT Id, Name, CreatedById FROM DataStream"),
            "dmo_metadata": client.get_ssot_endpoint("metadata?entityType=DataModelObject", key_name='metadata'),
            "calculated_insights": client.get_ssot_endpoint("metadata?entityType=CalculatedInsight", key_name='records'),
            "data_graphs": client.get_ssot_endpoint("data-graphs/metadata", key_name='dataGraphMetadata'),
            "data_actions": client.get_ssot_endpoint("data-actions", key_name='dataActions'),
            "data_streams_ssot": client.get_ssot_endpoint("data-streams", key_name='dataStreams'),
        }
        results = await tqdm.gather(*tasks.values(), desc="Coletando dados primários")
        data = dict(zip(tasks.keys(), results))

        # ETAPA 2: Coleta Segura de Mapeamentos e Processamento
        logging.info("--- Etapa 2/4: Processando dados e coletando mapeamentos... ---")

        dmos_to_check_for_mappings = [
            dmo_meta.get('name') for dmo_meta in data.get('dmo_metadata', [])
            if (dmo_api_name := dmo_meta.get('name')) and not any(dmo_api_name.lower().startswith(p) for p in config.DMO_PREFIXES_TO_EXCLUDE)
        ]
        logging.info(f"Identificados {len(dmos_to_check_for_mappings)} DMOs para verificação de mapeamentos.")
        
        mapping_tasks = [client.fetch_dmo_mapping_details(dmo_name) for dmo_name in dmos_to_check_for_mappings]
        all_mappings_results = await tqdm.gather(*mapping_tasks, desc="Coletando mapeamentos de DMOs")

        dlo_to_dmos_map = defaultdict(list)
        dmos_with_mappings = set()
        for payload in all_mappings_results:
            if payload and (mappings := payload.get('objectMappings')):
                for mapping in mappings:
                    source_dlo = mapping.get('sourceObjectName')
                    target_dmo = mapping.get('targetObjectName')
                    if source_dlo and target_dmo:
                        normalized_dlo = normalize_api_name(source_dlo)
                        dlo_to_dmos_map[normalized_dlo].append(target_dmo)
                        dmos_with_mappings.add(target_dmo)
        logging.info(f"Processados {len(dmos_with_mappings)} DMOs com mapeamentos.")

        all_creator_ids = set()
        for key in ["dmo_tooling", "all_segments", "all_activations", "datastream_sobjects"]:
            if data.get(key):
                for item in data[key]:
                    if creator_id := item.get('CreatedById'): all_creator_ids.add(creator_id)
        
        user_id_to_name_map = {}
        if all_creator_ids:
            logging.info(f"Buscando nomes para {len(all_creator_ids)} criadores únicos...")
            user_ids_str = "','".join(list(all_creator_ids))
            user_records = await client.query_api(f"SELECT Id, Name FROM User WHERE Id IN ('{user_ids_str}')")
            if user_records: user_id_to_name_map = {user['Id']: user['Name'] for user in user_records}
        
        dmo_details_map = {rec.get('DeveloperName'): rec for rec in data.get('dmo_tooling', [])}
        datastream_details_map = {rec.get('Name'): rec for rec in data.get('datastream_sobjects', [])}
        dmos_used = defaultdict(list)
        if dmos_from_csv := load_dmos_from_activations_csv(config):
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
        
        segment_publications = {str(act.get('MarketSegmentId', ''))[:15]: parse_sf_date(act.get('LastModifiedDate')) for act in data.get('all_activations', []) if act.get('MarketSegmentId')}

        # ETAPA 3: Lógica de Auditoria (em duas passagens)
        logging.info("--- Etapa 3/4: Executando lógica de auditoria... ---")
        audit_results = []
        
        deletable_segment_ids, deletable_dmo_names = set(), set()
        dmo_audit_buffer = []

        if segments_data:
            for seg in segments_data:
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
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': seg_id, 'DISPLAY_NAME': seg.get('Name'), 'OBJECT_TYPE': 'SEGMENT', 'STATUS': status, 'REASON': reason, 'TIPO_ATIVIDADE': 'Última Publicação', 'DIAS_ATIVIDADE': days_since(last_pub_date) or f'>{config.INACTIVE_SEGMENT_DAYS}', 'CREATED_BY_NAME': user_id_to_name_map.get(seg.get('CreatedById'), 'Desconhecido'), 'DELETION_IDENTIFIER': seg.get('Id')})

        if dmo_metadata_list := data.get('dmo_metadata'):
            for dmo_meta in tqdm(dmo_metadata_list, desc="Auditando DMOs (Passagem 1)"):
                dmo_api_name = dmo_meta.get('name')
                if not dmo_api_name or any(dmo_api_name.lower().startswith(p) for p in config.DMO_PREFIXES_TO_EXCLUDE):
                    continue
                
                dmo_details = dmo_details_map.get(dmo_api_name, {})
                normalized_dmo = normalize_api_name(dmo_api_name)
                is_in_use = normalized_dmo in dmos_used
                created_date = parse_sf_date(dmo_details.get('CreatedDate'))
                is_old_enough = not created_date or days_since(created_date) > config.ORPHAN_DMO_DAYS
                
                if not is_in_use and is_old_enough:
                    has_mappings = dmo_api_name in dmos_with_mappings
                    if not has_mappings:
                        creator_name = user_id_to_name_map.get(dmo_details.get('CreatedById'), 'Desconhecido')
                        dmo_audit_buffer.append({
                            'DELETAR': 'NAO', 'ID_OR_API_NAME': dmo_api_name, 'DISPLAY_NAME': dmo_meta.get('displayName', dmo_api_name),
                            'OBJECT_TYPE': 'DMO', 'STATUS': 'Órfão', 'REASON': f"Criado > {config.ORPHAN_DMO_DAYS} dias, sem uso conhecido e sem mapeamentos de ingestão.", 
                            'TIPO_ATIVIDADE': 'Criação', 'DIAS_ATIVIDADE': days_since(created_date) or f'>{config.ORPHAN_DMO_DAYS}', 
                            'CREATED_BY_NAME': creator_name, 'DELETION_IDENTIFIER': dmo_details.get('Id', 'ID não encontrado')
                        })
                        deletable_dmo_names.add(dmo_api_name)
        
        if activations_data := data.get('all_activations'):
            for act in activations_data:
                if str(act.get('MarketSegmentId', ''))[:15] in deletable_segment_ids:
                    audit_results.append({'DELETAR': 'NAO', 'ID_OR_API_NAME': act.get('Id'), 'DISPLAY_NAME': act.get('Name'), 'OBJECT_TYPE': 'ACTIVATION', 'STATUS': 'Órfã', 'REASON': 'Associada a um segmento órfão.', 'TIPO_ATIVIDADE': 'N/A', 'DIAS_ATIVIDADE': 'N/A', 'CREATED_BY_NAME': user_id_to_name_map.get(act.get('CreatedById'), 'Desconhecido'), 'DELETION_IDENTIFIER': act.get('Id')})

        if streams_data_ssot := data.get('data_streams_ssot'):
            for ds in tqdm(streams_data_ssot, desc="Auditando Data Streams (Passagem 2)"):
                last_ingest = parse_sf_date(ds.get('lastIngestDate'))
                if not last_ingest or days_since(last_ingest) > config.INACTIVE_STREAM_DAYS:
                    ds_details = datastream_details_map.get(ds.get('name'), {})
                    creator_name = user_id_to_name_map.get(ds_details.get('CreatedById'), 'Desconhecido')
                    dlo_name = ds.get('dataLakeObjectInfo', {}).get('name')
                    
                    normalized_dlo_name = normalize_api_name(dlo_name)
                    target_dmos = dlo_to_dmos_map.get(normalized_dlo_name, [])
                    
                    status, reason = "", ""
                    if not target_dmos:
                        status, reason = "Órfão", f"Última ingestão > {config.INACTIVE_STREAM_DAYS} dias e sem mapeamento para um DMO."
                    else:
                        active_target_dmos = [dmo for dmo in target_dmos if dmo not in deletable_dmo_names]
                        if not active_target_dmos:
                            status, reason = "Órfão", f"Mapeado apenas para DMO(s) órfão(s): {', '.join(target_dmos)}."
                        else:
                            status, reason = "Inativo", f"Última ingestão > {config.INACTIVE_STREAM_DAYS} dias, mas está mapeado para o(s) DMO(s) ativo(s): {', '.join(active_target_dmos)}."
                    
                    audit_results.append({
                        'DELETAR': 'NAO', 'ID_OR_API_NAME': ds.get('name'), 'DISPLAY_NAME': ds.get('label'), 
                        'OBJECT_TYPE': 'DATA_STREAM', 'STATUS': status, 'REASON': reason, 
                        'TIPO_ATIVIDADE': 'Última Ingestão', 'DIAS_ATIVIDADE': days_since(last_ingest) or f'>{config.INACTIVE_STREAM_DAYS}', 
                        'CREATED_BY_NAME': creator_name, 
                        'DELETION_IDENTIFIER': dlo_name or ds.get('name')
                    })
        
        audit_results.extend(dmo_audit_buffer)
        
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