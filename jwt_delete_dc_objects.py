"""
Este script realiza uma exclusão em massa de objetos do Data Cloud com base em um
arquivo CSV aprovado manualmente.

Version: 2.4 (Proxy Support)
- Adicionado suporte completo a proxy para todas as chamadas de rede (autenticação
  e requisições de exclusão), alinhando o comportamento com os scripts de auditoria.
- A variável PROXY_URL agora é lida do arquivo .env para centralizar a configuração.

AVISO: ESTE SCRIPT REALIZA AÇÕES DE EXCLUSÃO IRREVERSÍVEIS.
USE COM CUIDADO E APENAS APÓS REVISAR CUIDADOSAMENTE O ARQUIVO CSV.
"""
import os
import csv
import asyncio
import time
from urllib.parse import urlencode, urljoin
import sys
import logging
from collections import defaultdict

import jwt
import requests
import aiohttp
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# --- Configuration ---
API_VERSION = "v60.0"
CONCURRENCY_LIMIT = 10
CSV_FILE_PATH = 'audit_objetos_para_exclusao.csv'

# Configuração de Proxy lida do .env
USE_PROXY = True
PROXY_URL = os.getenv("PROXY_URL")
VERIFY_SSL = False

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Authentication ---
def get_access_token():
    """Authenticates with Salesforce using the JWT Bearer Flow."""
    logging.info("🔑 Authenticating with Salesforce using JWT Bearer Flow...")
    
    sf_client_id = os.getenv("SF_CLIENT_ID")
    sf_username = os.getenv("SF_USERNAME")
    sf_audience = os.getenv("SF_AUDIENCE")
    sf_login_url = os.getenv("SF_LOGIN_URL")

    if not all([sf_client_id, sf_username, sf_audience, sf_login_url]):
        raise ValueError("Uma ou mais variáveis de ambiente de autenticação estão faltando.")

    if USE_PROXY and not PROXY_URL:
        logging.warning("⚠️ USE_PROXY está como True, mas a variável PROXY_URL não foi encontrada no .env. Continuando sem proxy.")

    try:
        with open('private.pem', 'r') as f:
            private_key = f.read()
    except FileNotFoundError:
        logging.error("❌ 'private.pem' file not found.")
        raise

    payload = {
        'iss': sf_client_id, 'sub': sf_username, 'aud': sf_audience,
        'exp': int(time.time()) + 300
    }
    assertion = jwt.encode(payload, private_key, algorithm='RS256')
    params = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': assertion}
    token_url = f"{sf_login_url}/services/oauth2/token"

    try:
        # Adicionado suporte a proxy e verificação de SSL
        proxies = {'http': PROXY_URL, 'https': PROXY_URL} if USE_PROXY and PROXY_URL else None
        res = requests.post(token_url, data=params, proxies=proxies, verify=VERIFY_SSL)
        res.raise_for_status()
        logging.info("✅ Authentication successful.")
        return res.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Salesforce authentication error: {e.response.text if e.response else e}")
        raise

# --- Helper Functions ---
def read_and_prepare_csv(file_path='audit_objetos_para_exclusao.csv'):
    """Reads the audit CSV and filters for objects marked for deletion."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            if 'DELETAR' not in reader.fieldnames:
                logging.error(f"❌ A coluna 'DELETAR' não foi encontrada no arquivo '{file_path}'.")
                return None
            
            to_delete = [row for row in reader if str(row.get('DELETAR')).strip().upper() == 'SIM']
            
            if not to_delete:
                logging.info("ℹ️ Nenhum objeto marcado com 'SIM' na coluna 'DELETAR'. Nenhuma ação será executada.")
                return None
            return to_delete
    except FileNotFoundError:
        logging.error(f"❌ O arquivo '{file_path}' não foi encontrado.")
        return None

def confirm_deletion(objects_to_delete):
    """Displays a detailed summary table and asks for final user confirmation."""
    print("\n--- RESUMO DA EXCLUSÃO ---")
    print("O script irá deletar permanentemente os seguintes objetos:")
    if not objects_to_delete: return False

    # Simple table print for brevity
    for item in objects_to_delete:
        print(f"  - TIPO: {item.get('OBJECT_TYPE', 'N/A')}, NOME: {item.get('DISPLAY_NAME', 'N/A')}, ID/API_NAME: {item.get('ID_OR_API_NAME', 'N/A')}")

    print("\n---------------------------------")
    print(f"Total de objetos a serem deletados: {len(objects_to_delete)}")
    print("\n⚠️  ATENÇÃO: ESTA AÇÃO É IRREVERSÍVEL! ⚠️")
    confirmation = input("Para confirmar a exclusão, digite 'CONFIRMAR' e pressione Enter: ")
    return confirmation.strip().upper() == 'CONFIRMAR'

def normalize_api_name(name):
    if not isinstance(name, str): return ""
    return name.removesuffix('__dlm').removesuffix('__cio')

async def get_tooling_ids(session, semaphore, base_url, object_api_name, developer_names):
    if not developer_names: return {}
    
    formatted_names = ",".join([f"'{name}'" for name in developer_names])
    soql_query = f"SELECT Id, DeveloperName FROM {object_api_name} WHERE DeveloperName IN ({formatted_names})"
    
    params = {'q': soql_query}
    url = f"{base_url}/services/data/{API_VERSION}/tooling/query?{urlencode(params)}"
    
    try:
        async with semaphore:
            kwargs = {'ssl': VERIFY_SSL}
            if USE_PROXY and PROXY_URL: kwargs['proxy'] = PROXY_URL
            async with session.get(url, **kwargs) as response:
                response.raise_for_status()
                data = await response.json()
                return {record['DeveloperName']: record['Id'] for record in data.get('records', [])}
    except aiohttp.ClientError as e:
        logging.error(f"❌ Erro ao buscar IDs para {object_api_name}: {e}")
        return {}

async def delete_record(session, semaphore, url, item, results_list):
    display_name = item.get('DISPLAY_NAME')
    api_name = item.get('ID_OR_API_NAME')
    try:
        async with semaphore:
            kwargs = {'ssl': VERIFY_SSL}
            if USE_PROXY and PROXY_URL: kwargs['proxy'] = PROXY_URL
            async with session.delete(url, **kwargs) as response:
                response_text = await response.text()
                if response.status in [200, 204]:
                    results_list.append({'status': '✅ Sucesso', 'name': display_name, 'message': f"Objeto '{api_name}' deletado."})
                else:
                    results_list.append({'status': '❌ Falha', 'name': display_name, 'message': f"Erro ao deletar '{api_name}' (Status: {response.status}): {response_text}"})
    except aiohttp.ClientError as e:
        results_list.append({'status': '❌ Falha', 'name': display_name, 'message': f"Erro de conexão ao deletar '{api_name}': {e}"})

# --- Main Deletion Logic ---
async def main():
    objects_to_delete = read_and_prepare_csv(CSV_FILE_PATH)
    if not objects_to_delete: return

    if not confirm_deletion(objects_to_delete):
        logging.warning("🚫 Exclusão cancelada pelo usuário.")
        return

    auth_data = get_access_token()
    access_token, instance_url = auth_data['access_token'], auth_data['instance_url']
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    deletion_tasks, results = [], []

    async with aiohttp.ClientSession(headers=headers) as session:
        logging.info("\n🔥 Iniciando processo de exclusão...")

        grouped_objects = defaultdict(list)
        for item in objects_to_delete:
            grouped_objects[item.get('OBJECT_TYPE')].append(item)
        
        delete_order = ['ACTIVATION', 'SEGMENT', 'DATA_STREAM', 'DMO', 'CALCULATED_INSIGHT']
        
        for object_type in delete_order:
            if object_type not in grouped_objects: continue

            items_to_process = grouped_objects[object_type]
            logging.info(f"Processando {len(items_to_process)} objetos do tipo: {object_type}")

            if object_type == 'ACTIVATION':
                for item in items_to_process:
                    url = f"{instance_url}/services/data/{API_VERSION}/ssot/activations/{item['DELETION_IDENTIFIER']}"
                    deletion_tasks.append(delete_record(session, semaphore, url, item, results))

            elif object_type == 'SEGMENT':
                for item in items_to_process:
                    url = f"{instance_url}/services/data/{API_VERSION}/ssot/segments/{item['DELETION_IDENTIFIER']}"
                    deletion_tasks.append(delete_record(session, semaphore, url, item, results))

            elif object_type == 'DATA_STREAM':
                for item in items_to_process:
                    url = f"{instance_url}/services/data/{API_VERSION}/ssot/data-streams/{item['DELETION_IDENTIFIER']}?shouldDeleteDataLakeObject=true"
                    deletion_tasks.append(delete_record(session, semaphore, url, item, results))

            elif object_type == 'CALCULATED_INSIGHT':
                for item in items_to_process:
                    url = f"{instance_url}/services/data/{API_VERSION}/ssot/calculated-insights/{item['DELETION_IDENTIFIER']}"
                    deletion_tasks.append(delete_record(session, semaphore, url, item, results))
            
            elif object_type == 'DMO':
                dmo_names_to_delete = [item['DELETION_IDENTIFIER'] for item in items_to_process]
                
                dmo_ids = await get_tooling_ids(session, semaphore, instance_url, 'MktDataModelObject', dmo_names_to_delete)
                
                for item in items_to_process:
                    original_name = item['DELETION_IDENTIFIER']
                    if original_name in dmo_ids:
                        dmo_id = dmo_ids[original_name]
                        url = f"{instance_url}/services/data/{API_VERSION}/tooling/sobjects/MktDataModelObject/{dmo_id}"
                        deletion_tasks.append(delete_record(session, semaphore, url, item, results))
                    else:
                        results.append({'status': '❌ Falha', 'name': item['DISPLAY_NAME'], 'message': f"Não foi possível encontrar o ID para o DMO '{original_name}'."})
            
        await asyncio.gather(*deletion_tasks)

    # --- Relatório Final ---
    print("\n--- RELATÓRIO FINAL DA EXCLUSÃO ---")
    success_count = sum(1 for r in results if r['status'] == '✅ Sucesso')
    failure_count = len(results) - success_count
    for result in results: print(f"{result['status']} - {result['name']}: {result['message']}")
    print("\n--- RESUMO ---")
    print(f"Total de objetos deletados com sucesso: {success_count}")
    print(f"Total de falhas na exclusão: {failure_count}")


if __name__ == "__main__":
    start_time = time.time()
    try:
        asyncio.run(main())
    except Exception as e:
        logging.error(f"Um erro inesperado ocorreu: {e}", exc_info=True)
    finally:
        end_time = time.time()
        duration = end_time - start_time
        logging.info(f"\nTempo total de execução: {duration:.2f} segundos")