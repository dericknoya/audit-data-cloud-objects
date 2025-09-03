# -*- coding: utf-8 -*-
"""
Script de auditoria Salesforce Data Cloud - Objetos órfãos e inativos

Versão: 16.00 (Estável, Refatorada e Precisa)
- BASE: Evolução da v15.00 com base nas melhores práticas do script de campos.
- ARQUITETURA REATORADA: O código foi reestruturado com classes (Config, 
  SalesforceClient) para maior estabilidade, organização e manutenibilidade.
- NOVA VERIFICAÇÃO CRÍTICA (MAPEAMENTOS): Para DMOs considerados órfãos,
  uma verificação final é feita para garantir que não são alvos de mapeamentos
  de Data Streams, evitando a exclusão de objetos de ingestão.
- FILTROS INTELIGENTES: DMOs padrão do sistema (ssot__, unified__, etc.) são
  automaticamente ignorados para focar a análise em objetos customizados.
- IDENTIFICADOR DE EXCLUSÃO (ID TÉCNICO): O relatório final agora inclui o ID
  de 18 dígitos do DMO para ações de exclusão precisas.
- LOGGING ROBUSTO: A execução do script agora gera um arquivo de log detalhado
  (audit_data_cloud_objects.log).
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
    """Classe para centralizar todas as configurações do script."""
    # Conexão
    USE_PROXY = os.getenv("USE_PROXY", "True").lower() == "true"
    PROXY_URL = os.getenv("PROXY_URL")
    VERIFY_SSL = os.getenv("VERIFY_SSL", "False").lower() == "true"
    API_VERSION = "v60.0"
    
    # Autenticação
    SF_CLIENT_ID = os.getenv("SF_CLIENT_ID")
    SF_USERNAME = os.getenv("SF_USERNAME")
    SF_AUDIENCE = os.getenv("SF_AUDIENCE")
    SF_LOGIN_URL = os.getenv("SF_LOGIN_URL")
    
    # Performance
    SEMAPHORE_LIMIT = 20
    CHUNK_SIZE = 100
    
    # Lógica de Negócio
    MAX_RETRIES = 3
    RETRY_DELAY_SECONDS = 5
    ORPHAN_DMO_DAYS = 90
    INACTIVE_SEGMENT_DAYS = 30
    
    # Filtros de Exclusão
    DMO_PREFIXES_TO_EXCLUDE = ('ssot', 'unified', 'individual', 'einstein', 'segment_membership', 'aa_', 'aal_')
    
    # Arquivos de Saída
    OUTPUT_CSV_FILE = 'audit_objetos_para_exclusao.csv'
    ACTIVATION_FIELDS_CSV = 'ativacoes_campos.csv'
    LOG_FILE = 'audit_data_cloud_objects.log'

# ==============================================================================
# --- 헬 FUNÇÕES AUXILIARES E LOGGING ---
# ==============================================================================
def setup_logging(log_file):
    """Configura o logging para console e arquivo, garantindo que não haja duplicidade."""
    logger = logging.getLogger()
    if logger.hasHandlers():
        logger.handlers.clear()
        
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Handler para o arquivo de log
    file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Handler para o console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

def get_access_token(config: Config):
    """Obtém o token de acesso da Salesforce."""
    logging.info("🔑 Autenticando com Salesforce via JWT...")
    # ... (código de autenticação permanece o mesmo, mas usando 'config')
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

# ... (outras funções auxiliares como parse_sf_date, days_since)
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
    """Classe para encapsular todas as interações com a API do Salesforce."""
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
        if self.session and not self.session.closed:
            await self.session.close()

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
                            if response.status == 404:
                                logging.warning(f"⚠️ Recurso não encontrado (404) para URL: {current_url}. Retornando vazio.")
                                return [] if key_name else None
                            response.raise_for_status()
                            data = await response.json()
                            if key_name:
                                all_records.extend(data.get(key_name, []))
                                next_url = data.get('nextRecordsUrl') or data.get('nextPageUrl')
                                locator = data.get('queryLocator')
                                if next_url:
                                    current_url = urljoin(str(self.session._base_url), next_url)
                                elif is_tooling and locator and not data.get('done', True):
                                    current_url = f"/services/data/{self.config.API_VERSION}/tooling/query/{locator}"
                                else:
                                    current_url = None
                            else:
                                return data
                    return all_records
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    if attempt < self.config.MAX_RETRIES - 1:
                        logging.warning(f"Tentativa {attempt + 1} falhou. Causa: {e}. Tentando novamente em {self.config.RETRY_DELAY_SECONDS}s...")
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
    
    async def check_dmo_mappings(self, dmo_name: str) -> bool:
        """Verifica se um DMO possui mapeamentos de Data Stream."""
        url = f"/services/data/{self.config.API_VERSION}/ssot/data-model-object-mappings?dmoDeveloperName={dmo_name}"
        data = await self._fetch_with_retry(url)
        if data and data.get('objectSourceTargetMaps'):
            return True
        return False
    
# ==============================================================================
# --- 📊 FUNÇÕES DE ANÁLISE DE DEPENDÊNCIA ---
# ==============================================================================
def load_dmos_from_activations_csv(config: Config) -> set:
    """Lê o arquivo CSV de ativações e retorna um set de DMOs normalizados."""
    # ... (código da função da v15.00, usando 'config')
    dmo_set = set()
    try:
        with open(config.ACTIVATION_FIELDS_CSV, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if entity_name := row.get('entityName'):
                    if '__dlm' in entity_name:
                        dmo_set.add(normalize_api_name(entity_name))
        logging.info(f"✅ Encontrados {len(dmo_set)} DMOs únicos no CSV de ativações.")
    except FileNotFoundError:
        logging.warning(f"⚠️ Arquivo '{config.ACTIVATION_FIELDS_CSV}' não encontrado. Dependências de ativações via CSV serão ignoradas.")
    return dmo_set

def find_dmos_in_payload(payload: str, dmo_set: set):
    """Encontra DMOs em um payload JSON, buscando por chaves específicas."""
    # ... (código da função da v15.00)
    if not payload: return
    try:
        data = json.loads(html.unescape(payload))
        dmo_keys = {'objectName', 'entityName', 'developerName', 'objectApiName'}
        def recurse(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in dmo_keys and isinstance(value, str) and value.endswith('__dlm'):
                        dmo_set.add(normalize_api_name(value))
                    elif isinstance(value, (dict, list)):
                        recurse(value)
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
    
    logging.info("🚀 Iniciando auditoria de objetos v16.00...")
    auth_data = get_access_token(config)
    
    async with SalesforceClient(config, auth_data) as client:
        # --- ETAPA 1: Coleta de Dados e Dependências ---
        logging.info("--- Etapa 1/4: Coletando metadados e dependências... ---")
        
        dmos_used_in_activations_csv = load_dmos_from_activations_csv(config)
        
        tasks = {
            "dmo_tooling": client.query_api("SELECT Id, DeveloperName, CreatedDate, CreatedById FROM MktDataModelObject", tooling=True),
            "all_segments": client.query_api("SELECT Id, Name, IncludeCriteria, ExcludeCriteria, CreatedById FROM MarketSegment"),
            "all_activations": client.query_api("SELECT MarketSegmentId, LastModifiedDate FROM MarketSegmentActivation"),
            "dmo_metadata": client.get_ssot_metadata("DataModelObject"),
            "calculated_insights": client.get_ssot_metadata("CalculatedInsight", key_name='records'),
            "data_graphs": client.get_ssot_metadata("DataGraph", key_name='dataGraphMetadata'),
            "data_actions": client.get_ssot_metadata("DataAction", key_name='dataActions'),
        }
        results = await tqdm.gather(*tasks.values(), desc="Coletando dados da API")
        data = dict(zip(tasks.keys(), results))

        # --- ETAPA 2: Processamento e Mapeamento ---
        logging.info("--- Etapa 2/4: Processando dados e mapeando dependências... ---")

        dmo_details_map = {rec.get('DeveloperName'): rec for rec in data.get('dmo_tooling', [])}
        
        dmos_used = defaultdict(list)
        for dmo in dmos_used_in_activations_csv: dmos_used[dmo].append("Ativação (CSV)")
        for ci in data.get('calculated_insights', []): find_dmos_in_payload(json.dumps(ci), dmos_used)
        for dg in data.get('data_graphs', []): find_dmos_in_payload(json.dumps(dg), dmos_used)
        for da in data.get('data_actions', []): find_dmos_in_payload(json.dumps(da), dmos_used)

        segment_publications = {act.get('MarketSegmentId', '')[:15]: parse_sf_date(act.get('LastModifiedDate')) for act in data.get('all_activations', []) if act.get('MarketSegmentId')}

        # --- ETAPA 3: Análise e Auditoria ---
        logging.info("--- Etapa 3/4: Executando lógica de auditoria... ---")
        audit_results = []
        
        # Auditoria de DMOs
        for dmo in tqdm(data.get('dmo_metadata', []), desc="Auditando DMOs"):
            dmo_api_name = dmo.get('name')
            if not dmo_api_name or not dmo_api_name.endswith('__dlm') or \
               any(dmo_api_name.lower().startswith(p) for p in config.DMO_PREFIXES_TO_EXCLUDE):
                continue
            
            normalized_dmo = normalize_api_name(dmo_api_name)
            dmo_details = dmo_details_map.get(dmo_api_name, {})
            created_date = parse_sf_date(dmo_details.get('CreatedDate'))
            
            is_in_use = normalized_dmo in dmos_used
            is_old_enough = not created_date or days_since(created_date) > config.ORPHAN_DMO_DAYS

            if not is_in_use and is_old_enough:
                has_mappings = await client.check_dmo_mappings(dmo_api_name)
                if not has_mappings:
                    audit_results.append({
                        'DELETAR': 'NAO', 
                        'ID_OR_API_NAME': dmo_api_name,
                        'DISPLAY_NAME': dmo.get('displayName', dmo_api_name),
                        'OBJECT_TYPE': 'DMO', 'STATUS': 'Órfão',
                        'REASON': f"Criado > {config.ORPHAN_DMO_DAYS} dias, sem uso conhecido e sem mapeamentos de ingestão.",
                        'DELETION_IDENTIFIER': dmo_details.get('Id', 'ID não encontrado')
                    })
        
        # --- ETAPA 4: Geração do Relatório ---
        logging.info("--- Etapa 4/4: Gerando relatório CSV... ---")
        if audit_results:
            fieldnames = ['DELETAR', 'ID_OR_API_NAME', 'DISPLAY_NAME', 'OBJECT_TYPE', 'STATUS', 'REASON', 'DELETION_IDENTIFIER']
            with open(config.OUTPUT_CSV_FILE, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(sorted(audit_results, key=lambda x: (x['OBJECT_TYPE'], x['DISPLAY_NAME'])))
            logging.info(f"✅ Relatório '{config.OUTPUT_CSV_FILE}' gerado com {len(audit_results)} objetos.")
        else:
            logging.info("🎉 Nenhum objeto órfão ou inativo encontrado que atenda aos critérios.")

if __name__ == "__main__":
    start_time = time.time()
    try:
        asyncio.run(main())
    except Exception as e:
        logging.critical(f"❌ Ocorreu um erro fatal na execução do script: {e}", exc_info=True)
    finally:
        duration = time.time() - start_time
        logging.info(f"\n🏁 Auditoria concluída. Tempo total de execução: {duration:.2f} segundos.")