# -*- coding: utf-8 -*-
"""
Script para extrair mapeamentos de DMOs (Data Model Objects) do Salesforce Data Cloud.

Este script executa as seguintes ações:
1. Autentica-se na organização Salesforce usando JWT.
2. Obtém a lista de todos os DMOs disponíveis via API.
3. Para cada DMO, busca seus mapeamentos de ingestão (DLO -> DMO).
4. Gera um arquivo CSV ('dmo_mappings.csv') com os detalhes de cada mapeamento encontrado.
"""
import os
import time
import asyncio
import csv
import logging
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
    """Classe de configuração para centralizar os parâmetros do script."""
    # Configurações de Conexão
    USE_PROXY = os.getenv("USE_PROXY", "False").lower() == "true"
    PROXY_URL = os.getenv("PROXY_URL")
    VERIFY_SSL = os.getenv("VERIFY_SSL", "True").lower() == "true"
    
    # Credenciais e Endpoints Salesforce
    API_VERSION = "v60.0" # Mantenha a versão mais recente compatível
    SF_CLIENT_ID = os.getenv("SF_CLIENT_ID")
    SF_USERNAME = os.getenv("SF_USERNAME")
    SF_AUDIENCE = os.getenv("SF_AUDIENCE")
    SF_LOGIN_URL = os.getenv("SF_LOGIN_URL")
    
    # Configurações de Execução
    SEMAPHORE_LIMIT = 10 # Limite de chamadas concorrentes à API
    MAX_RETRIES = 3
    RETRY_DELAY_SECONDS = 5
    
    # Arquivos de Saída
    OUTPUT_CSV_FILE = 'dmo_mappings.csv'
    LOG_FILE = 'mapping_extractor.log'

# ==============================================================================
# --- 헬 FUNÇÕES AUXILIARES E LOGGING ---
# ==============================================================================
def setup_logging(log_file):
    """Configura o sistema de logging para arquivo e console."""
    logger = logging.getLogger()
    if logger.hasHandlers(): logger.handlers.clear()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Handler para arquivo
    file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Handler para console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

def get_access_token(config: Config):
    """Obtém o token de acesso da Salesforce usando o fluxo JWT Bearer."""
    logging.info("🔑 Autenticando com Salesforce via JWT...")
    try:
        with open('private.pem', 'r', encoding='utf-8') as f:
            private_key = f.read()
    except FileNotFoundError:
        logging.critical("❌ Arquivo 'private.pem' não encontrado. Encerrando.")
        raise

    payload = {
        'iss': config.SF_CLIENT_ID,
        'sub': config.SF_USERNAME,
        'aud': config.SF_AUDIENCE,
        'exp': int(time.time()) + 300
    }
    assertion = jwt.encode(payload, private_key, algorithm='RS256')
    params = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion': assertion
    }
    
    token_url = urljoin(config.SF_LOGIN_URL, "/services/oauth2/token")
    proxies = {'http': config.PROXY_URL, 'https': config.PROXY_URL} if config.USE_PROXY and config.PROXY_URL else None
    
    try:
        res = requests.post(token_url, data=params, proxies=proxies, verify=config.VERIFY_SSL, timeout=30)
        res.raise_for_status()
        logging.info("✅ Autenticação bem-sucedida.")
        return res.json()
    except requests.exceptions.RequestException as e:
        logging.critical(f"❌ Erro fatal na autenticação: {e.response.text if e.response else e}")
        raise

# ==============================================================================
# --- 🌐 CLASSE CLIENTE SALESFORCE API ---
# ==============================================================================
class SalesforceClient:
    """Cliente assíncrono para interagir com as APIs da Salesforce."""
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
        """Método genérico para buscar dados de um endpoint com retentativas e paginação."""
        async with self.semaphore:
            for attempt in range(self.config.MAX_RETRIES):
                try:
                    all_records, current_url = [], url
                    while current_url:
                        kwargs = {'ssl': self.config.VERIFY_SSL}
                        if self.config.USE_PROXY:
                            kwargs['proxy'] = self.config.PROXY_URL
                        
                        async with self.session.get(current_url, **kwargs) as response:
                            if response.status >= 400:
                                if response.status == 404:
                                    logging.warning(f"⚠️  Recebido 404 (Not Found), tratando como resultado vazio para: {current_url}")
                                    return [] if key_name else None
                                error_text = await response.text()
                                logging.error(f"❌ Erro {response.status} para URL: {current_url}. Resposta: {error_text}")
                                response.raise_for_status()

                            data = await response.json()
                            if key_name:
                                all_records.extend(data.get(key_name, []))
                                next_url = data.get('nextRecordsUrl') or data.get('nextPageUrl')
                                current_url = urljoin(str(self.session._base_url), next_url) if next_url else None
                            else:
                                return data # Retorna o payload completo se não houver uma chave específica
                    return all_records
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    if attempt < self.config.MAX_RETRIES - 1:
                        logging.warning(f"Tentativa {attempt + 1} falhou para {url}. Causa: {e}. Tentando novamente...")
                        await asyncio.sleep(self.config.RETRY_DELAY_SECONDS)
                    else:
                        logging.error(f"❌ Falha ao buscar dados de {url} após {self.config.MAX_RETRIES} tentativas.")
                        return [] if key_name else None

    async def get_ssot_endpoint(self, endpoint_path, key_name=None):
        """Busca dados de um endpoint SSOT genérico."""
        url = f"/services/data/{self.config.API_VERSION}/ssot/{endpoint_path}"
        return await self._fetch_with_retry(url, key_name=key_name)

    async def fetch_dmo_mapping_details(self, dmo_api_name: str):
        """Busca os detalhes de mapeamento para um DMO específico."""
        params = {'dataspace': 'default', 'dmoDeveloperName': dmo_api_name}
        url_path = f"/services/data/{self.config.API_VERSION}/ssot/data-model-object-mappings?{urlencode(params)}"
        return await self._fetch_with_retry(url_path)

# ==============================================================================
# --- 🚀 ORQUESTRADOR PRINCIPAL (MAIN) ---
# ==============================================================================
async def main():
    """Função principal que orquestra a extração e geração do CSV."""
    config = Config()
    setup_logging(config.LOG_FILE)
    
    logging.info("🚀 Iniciando extrator de mapeamentos de DMOs...")
    
    try:
        auth_data = get_access_token(config)
    except Exception:
        logging.critical("Falha na autenticação. O script não pode continuar.")
        return

    async with SalesforceClient(config, auth_data) as client:
        
        # --- ETAPA 1: Buscar a lista de todos os DMOs ---
        logging.info("--- Etapa 1/3: Buscando a lista de DMOs... ---")
        dmo_metadata = await client.get_ssot_endpoint("metadata?entityType=DataModelObject", key_name='metadata')
        
        if not dmo_metadata:
            logging.error("Nenhum metadado de DMO foi encontrado ou houve um erro na busca. Encerrando.")
            return
            
        dmo_names = sorted([dmo.get('name') for dmo in dmo_metadata if dmo.get('name')])
        logging.info(f"✅ Encontrados {len(dmo_names)} DMOs para verificar.")

        # --- ETAPA 2: Buscar os mapeamentos para cada DMO ---
        logging.info("--- Etapa 2/3: Coletando os mapeamentos de cada DMO... ---")
        mapping_tasks = [client.fetch_dmo_mapping_details(name) for name in dmo_names]
        all_mappings_results = await tqdm.gather(*mapping_tasks, desc="Coletando mapeamentos")

        # --- ETAPA 3: Processar os resultados e gerar o CSV ---
        logging.info("--- Etapa 3/3: Processando resultados e gerando o arquivo CSV... ---")
        csv_data = []
        
        # Itera sobre os nomes e os resultados correspondentes
        for dmo_name, payload in zip(dmo_names, all_mappings_results):
            if not payload or 'objectSourceTargetMaps' not in payload:
                continue # Pula DMOs sem mapeamentos ou com resposta de erro
            
            mappings = payload.get('objectSourceTargetMaps', [])
            for mapping in mappings:
                csv_data.append({
                    'DMO_API_NAME': dmo_name,
                    'DLO_SOURCE': mapping.get('sourceEntityDeveloperName'),
                    'OBJECT_MAP_NAME': mapping.get('developerName')
                })

        if not csv_data:
            logging.warning("⚠️ Nenhum mapeamento foi encontrado para os DMOs verificados.")
            return

        # Escreve o arquivo CSV
        try:
            fieldnames = ['DMO_API_NAME', 'DLO_SOURCE', 'OBJECT_MAP_NAME']
            with open(config.OUTPUT_CSV_FILE, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(csv_data)
            logging.info(f"✅ Relatório '{config.OUTPUT_CSV_FILE}' gerado com sucesso, contendo {len(csv_data)} registros de mapeamento.")
        except IOError as e:
            logging.error(f"❌ Erro ao escrever o arquivo CSV: {e}")


if __name__ == "__main__":
    start_time = time.time()
    try:
        asyncio.run(main())
    except Exception as e:
        logging.critical(f"❌ Ocorreu um erro fatal na execução do script: {e}", exc_info=True)
    finally:
        duration = time.time() - start_time
        logging.info(f"\n🏁 Execução concluída. Tempo total: {duration:.2f} segundos.")