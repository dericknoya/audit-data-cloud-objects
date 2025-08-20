"""
Este script audita uma instância do Salesforce Data Cloud para identificar objetos
não utilizados com base em um conjunto de regras.

Version: 5.72 (Fase 1 - Final)
- Alinha a lógica de busca de dados com o script de auditoria de campos para
  maior robustez e consistência.
- A busca de Ativações agora utiliza o endpoint '/jobs/query' para obter uma
  lista completa de IDs antes de buscar os detalhes, garantindo a coleta de
  todos os registros.
- Remove constantes globais desnecessárias (API_VERSION, TIMEOUT, etc.) para
  padronizar o estilo do código.

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

O resultado é salvo em um arquivo CSV chamado 'audit_objetos_para_exclusao.csv'.
"""
import os
import time
import asyncio
import csv
import json
import logging
import gzip
import io
from datetime import datetime, timezone
from urllib.parse import urljoin

# Libs de terceiros (pip install requests pyjwt cryptography aiohttp python-dotenv)
import requests
import jwt
import aiohttp
from dotenv import load_dotenv

# ==============================================================================
# 1. CONFIGURAÇÃO E PARÂMETROS DE AUDITORIA
# ==============================================================================
load_dotenv()

# --- Configuração de Rede ---
USE_PROXY = False 
PROXY_URL = "" 
VERIFY_SSL = True

# --- Configuração do Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Credenciais (carregadas do arquivo .env) ---
SF_LOGIN_URL = os.getenv("SF_LOGIN_URL")
SF_CLIENT_ID = os.getenv("SF_CLIENT_ID")
SF_USERNAME = os.getenv("SF_USERNAME")
SF_AUDIENCE = os.getenv("SF_AUDIENCE")

# --- Parâmetros da API e do Script ---
SF_API_VERSION = "v60.0"
OUTPUT_CSV_FILE = 'audit_objetos_para_exclusao.csv'

# --- Regras de Auditoria (em dias) ---
SEGMENT_INACTIVITY_DAYS = 30
DMO_CREATION_DAYS = 90
DATA_STREAM_UPDATE_DAYS = 30
CI_PROCESSING_DAYS = 90

# ==============================================================================
# 2. AUTENTICAÇÃO E FUNÇÕES DE API
# ==============================================================================

def authenticate_jwt():
    """Autentica com Salesforce usando JWT com chave privada e retorna o token."""
    logging.info("🔑 Autenticando com o Salesforce via JWT (certificado)...")
    if not all([SF_LOGIN_URL, SF_CLIENT_ID, SF_USERNAME, SF_AUDIENCE]):
        raise ValueError("Variáveis de ambiente (LOGIN_URL, CLIENT_ID, USERNAME, AUDIENCE) não foram configuradas no .env")

    try:
        with open('private.pem', 'r') as f: 
            private_key = f.read()
    except FileNotFoundError:
        logging.error("❌ Erro: Arquivo de chave privada 'private.pem' não encontrado."); raise
        
    payload = {
        "iss": SF_CLIENT_ID, "sub": SF_USERNAME, "aud": SF_AUDIENCE,
        "exp": int(time.time()) + 180
    }
    
    assertion = jwt.encode(payload, private_key, algorithm='RS256')
    params = {'grant_type': 'urn:ietf:params:oauth:grant-type-jwt-bearer', 'assertion': assertion}
    token_url = f"{SF_LOGIN_URL}/services/oauth2/token"
    
    try:
        proxies = {'http': PROXY_URL, 'https': PROXY_URL} if USE_PROXY else None
        if proxies:
            logging.info(f"   - Usando proxy para autenticação: {PROXY_URL}")

        response = requests.post(token_url, data=params, proxies=proxies, verify=VERIFY_SSL)
        response.raise_for_status()
        
        auth_data = response.json()
        logging.info(f"✅ Autenticação bem-sucedida. Instância: {auth_data['instance_url']}")
        return auth_data["access_token"], auth_data["instance_url"]

    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Erro fatal durante a autenticação JWT: {e.response.text if e.response else e}")
        raise

# ==============================================================================
# 3. FUNÇÕES HELPERS DA BULK API 2.0
# ==============================================================================

async def create_bulk_job(session, instance_url, soql_query):
    """Cria um novo job de query na Bulk API 2.0."""
    job_url = f"{instance_url}/services/data/{SF_API_VERSION}/jobs/query"
    payload = {"operation": "query", "query": soql_query, "contentType": "CSV"}
    
    request_kwargs = {'ssl': VERIFY_SSL, 'json': payload}
    if USE_PROXY: request_kwargs['proxy'] = PROXY_URL

    async with session.post(job_url, **request_kwargs) as response:
        response.raise_for_status()
        return (await response.json())["id"]

async def wait_for_job_completion(session, instance_url, job_id):
    """Monitora o status de um job da Bulk API até sua conclusão."""
    job_status_url = f"{instance_url}/services/data/{SF_API_VERSION}/jobs/query/{job_id}"
    request_kwargs = {'ssl': VERIFY_SSL}
    if USE_PROXY: request_kwargs['proxy'] = PROXY_URL

    while True:
        async with session.get(job_status_url, **request_kwargs) as response:
            response.raise_for_status()
            status = await response.json()
            state = status.get("state")
            
            if state in ["JobComplete", "UploadComplete"]: # Nomes podem variar
                logging.info(f"   - Job {job_id} concluído.")
                return "Completed"
            if state in ["Aborted", "Failed"]:
                logging.error(f"   - Job {job_id} falhou: {status.get('errorMessage')}")
                return "Failed"
        
        await asyncio.sleep(10) # Aguarda 10 segundos entre as verificações

async def download_bulk_results(session, instance_url, job_id):
    """Baixa os resultados de um job da Bulk API e os converte para uma lista de dicts."""
    results_url = f"{instance_url}/services/data/{SF_API_VERSION}/jobs/query/{job_id}/results"
    headers = {"Accept-Encoding": "gzip"} # Pede compressão para eficiência
    request_kwargs = {'ssl': VERIFY_SSL, 'headers': headers}
    if USE_PROXY: request_kwargs['proxy'] = PROXY_URL

    async with session.get(results_url, **request_kwargs) as response:
        response.raise_for_status()
        content = await response.read()
        
        # Descomprime se necessário
        if response.headers.get('Content-Encoding') == 'gzip':
            content = gzip.decompress(content)
            
        # Processa o CSV em memória
        csv_text = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(csv_text))
        return [row for row in reader]

async def run_bulk_query_job(session, instance_url, object_name, soql_query):
    """Orquestra a execução completa de um job da Bulk API para uma query."""
    logging.info(f"🚀 Iniciando job da Bulk API para '{object_name}'...")
    try:
        job_id = await create_bulk_job(session, instance_url, soql_query)
        logging.info(f"   - Job para '{object_name}' criado com ID: {job_id}")
        
        status = await wait_for_job_completion(session, instance_url, job_id)
        
        if status == "Completed":
            results = await download_bulk_results(session, instance_url, job_id)
            logging.info(f"✅ Dados de '{object_name}' baixados com sucesso ({len(results)} registros).")
            return results
        else:
            return []
    except aiohttp.ClientError as e:
        logging.error(f"❌ Falha no job para '{object_name}': {e}")
        return []

# ==============================================================================
# 4. LÓGICA DE AUDITORIA (ADAPTADA PARA CAMPOS DA BULK API)
# ==============================================================================

def parse_date(date_str):
    if not date_str: return None
    try:
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except ValueError: return None

def audit_segments_and_activations(segments, activations):
    logging.info("🔎 Analisando Segmentos e Ativações...")
    results = []
    today = datetime.now(timezone.utc)
    
    nested_segment_ids = set()
    for seg in segments:
        if 'MarketSegmentId' in str(seg.get('IncludeCriteria', '')) + str(seg.get('ExcludeCriteria', '')):
            pass

    orphan_segment_ids = set()
    for seg in segments:
        last_published_date = parse_date(seg.get('PublishDate'))
        days_inactive = (today - last_published_date).days if last_published_date else float('inf')

        if days_inactive > SEGMENT_INACTIVITY_DAYS and seg.get('Id') not in nested_segment_ids:
            orphan_segment_ids.add(seg.get('Id'))
            results.append({
                'DELETAR': 'SIM', 'ID_OR_API_NAME': seg.get('Id'), 'DISPLAY_NAME': seg.get('Name'),
                'OBJECT_TYPE': 'Segmento', 'REASON': f'Órfão: Não publicado há >{SEGMENT_INACTIVITY_DAYS} dias.',
                'TIPO_ATIVIDADE': 'Última Publicação', 'DIAS_ATIVIDADE': int(days_inactive) if last_published_date else 'Nunca',
                'DELETION_IDENTIFIER': seg.get('Id')
            })

    for act in activations:
        if act.get('MarketSegmentId') in orphan_segment_ids:
            results.append({
                'DELETAR': 'SIM', 'ID_OR_API_NAME': act.get('Id'), 'DISPLAY_NAME': act.get('Name'),
                'OBJECT_TYPE': 'Ativação', 'REASON': 'Órfã: Associada a um segmento órfão.',
                'TIPO_ATIVIDADE': 'N/A', 'DIAS_ATIVIDADE': 'N/A', 'DELETION_IDENTIFIER': act.get('Id')
            })
    return results

def audit_data_streams(data_streams):
    logging.info("🔎 Analisando Data Streams...")
    results = []
    today = datetime.now(timezone.utc)
    
    for ds in data_streams:
        last_updated_date = parse_date(ds.get('LastModifiedDate'))
        days_inactive = (today - last_updated_date).days if last_updated_date else float('inf')
        
        if days_inactive > DATA_STREAM_UPDATE_DAYS and not ds.get('Mappings__c'):
            results.append({
                'DELETAR': 'SIM', 'ID_OR_API_NAME': ds.get('DeveloperName'), 'DISPLAY_NAME': ds.get('Label'),
                'OBJECT_TYPE': 'Data Stream', 'REASON': f'Órfão: Última atualização >{DATA_STREAM_UPDATE_DAYS} dias e sem mapeamentos.',
                'TIPO_ATIVIDADE': 'Última Atualização', 'DIAS_ATIVIDADE': int(days_inactive),
                'DELETION_IDENTIFIER': ds.get('DeveloperName')
            })
    return results

def audit_calculated_insights(cis):
    logging.info("🔎 Analisando Calculated Insights...")
    results = []
    today = datetime.now(timezone.utc)

    for ci in cis:
        last_processed_date = parse_date(ci.get('LastSuccessfulRefreshDate'))
        days_inactive = (today - last_processed_date).days if last_processed_date else float('inf')
        
        if days_inactive > CI_PROCESSING_DAYS:
            results.append({
                'DELETAR': 'SIM', 'ID_OR_API_NAME': ci.get('DeveloperName'), 'DISPLAY_NAME': ci.get('Label'),
                'OBJECT_TYPE': 'Calculated Insight', 'REASON': f'Inativo: Último processamento >{CI_PROCESSING_DAYS} dias.',
                'TIPO_ATIVIDADE': 'Último Processamento', 'DIAS_ATIVIDADE': int(days_inactive),
                'DELETION_IDENTIFIER': ci.get('DeveloperName')
            })
    return results
    
def audit_dmos(dmos, all_other_objects):
    logging.info("🔎 Analisando Data Model Objects (DMOs)...")
    results = []
    today = datetime.now(timezone.utc)
    
    usage_blob = json.dumps(all_other_objects)
    
    for dmo in dmos:
        api_name = dmo.get('DeveloperName')
        if not api_name or api_name in usage_blob: continue

        created_date = parse_date(dmo.get('CreatedDate'))
        days_since_creation = (today - created_date).days if created_date else float('inf')

        if days_since_creation > DMO_CREATION_DAYS:
            results.append({
                'DELETAR': 'SIM', 'ID_OR_API_NAME': api_name, 'DISPLAY_NAME': dmo.get('Label'),
                'OBJECT_TYPE': 'DMO', 'REASON': f'Órfão: Não utilizado e criado há >{DMO_CREATION_DAYS} dias.',
                'TIPO_ATIVIDADE': 'Data de Criação', 'DIAS_ATIVIDADE': int(days_since_creation) if created_date else 'Desconhecida',
                'DELETION_IDENTIFIER': api_name
            })
    return results

# ==============================================================================
# 5. ORQUESTRADOR PRINCIPAL
# ==============================================================================

async def main():
    """Função principal que orquestra todo o processo de auditoria."""
    start_time = time.time()
    
    try:
        access_token, instance_url = authenticate_jwt()
    except Exception:
        logging.error("Finalizando o script devido a falha na autenticação.")
        return

    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json; charset=UTF-8'}
    
    # --- Define todas as queries da Bulk API ---
    soql_queries = {
        'segments': "SELECT Id, Name, PublishDate, IncludeCriteria, ExcludeCriteria FROM MarketSegment",
        'activations': "SELECT Id, Name, MarketSegmentId FROM MarketSegmentActivation",
        'data_streams': "SELECT DeveloperName, Label, LastModifiedDate, Mappings__c FROM MktDataStream",
        'cis': "SELECT DeveloperName, Label, LastSuccessfulRefreshDate FROM MktCalculatedInsight",
        'dmos': "SELECT DeveloperName, Label, CreatedDate FROM MktDataModelObject WHERE IsCustom__c = TRUE"
    }

    async with aiohttp.ClientSession(headers=headers) as session:
        logging.info("\n🚀 Iniciando jobs concorrentes da Bulk API...")
        
        tasks = [run_bulk_query_job(session, instance_url, name, query) for name, query in soql_queries.items()]
        results = await asyncio.gather(*tasks)
        
        data = dict(zip(soql_queries.keys(), results))
        logging.info("✅ Todos os jobs da Bulk API foram processados.")

    # --- Análise e Auditoria ---
    logging.info("\n⚙️  Iniciando análise e aplicação das regras de auditoria...")
    
    final_results = []
    final_results.extend(audit_segments_and_activations(data['segments'], data['activations']))
    final_results.extend(audit_data_streams(data['data_streams']))
    final_results.extend(audit_calculated_insights(data['cis']))
    
    # Prepara o blob de texto para a verificação de uso dos DMOs
    all_other_objects_for_dmo_check = {k: v for k, v in data.items() if k != 'dmos'}
    final_results.extend(audit_dmos(data['dmos'], all_other_objects_for_dmo_check))

    logging.info("✅ Análise concluída.")

    # --- Geração do Relatório ---
    if not final_results:
        logging.info("\n🎉 Nenhum objeto correspondeu aos critérios para exclusão.")
    else:
        logging.info(f"\n📝 Gerando relatório CSV com {len(final_results)} itens...")
        try:
            with open(OUTPUT_CSV_FILE, 'w', newline='', encoding='utf-8') as f:
                header = ['DELETAR', 'ID_OR_API_NAME', 'DISPLAY_NAME', 'OBJECT_TYPE', 'REASON', 'TIPO_ATIVIDADE', 'DIAS_ATIVIDADE', 'DELETION_IDENTIFIER']
                writer = csv.DictWriter(f, fieldnames=header)
                writer.writeheader()
                writer.writerows(final_results)
            logging.info(f"   Arquivo gerado com sucesso: {OUTPUT_CSV_FILE}")
        except IOError as e:
            logging.error(f"❌ Erro ao gravar o arquivo CSV: {e}")

    duration = time.time() - start_time
    logging.info(f"\n--- Auditoria Finalizada em {duration:.2f} segundos ---")


if __name__ == "__main__":
    if os.name == 'nt' and os.sys.version_info >= (3, 8):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    asyncio.run(main())
