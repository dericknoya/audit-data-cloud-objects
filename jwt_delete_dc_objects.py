"""
Este script realiza uma exclusão em massa de objetos do Data Cloud com base em um
arquivo CSV aprovado manualmente.

Version: 3.0 (Correção na Deleção de DMOs)
- CORREÇÃO CRÍTICA: Altera o endpoint de exclusão de DMOs para usar a API SSOT
  ('/ssot/data-model-objects/{DeveloperName}') em vez da Tooling API, com base
  em testes e descobertas. Isso simplifica o script, remove a necessidade de
  buscar o ID do objeto e corrige a falha de exclusão original.
- LIMPEZA DE CÓDIGO: A função 'get_tooling_ids' e importações relacionadas foram
  removidas por não serem mais necessárias.
- MANTÉM: Ajuste de leitura do CSV com 'utf-8-sig' e log detalhado da API.

AVISO: ESTE SCRIPT REALIZA AÇÕES DE EXCLUSÃO IRREVERSÍVEIS.
USE COM CUIDADO E APENAS APÓS REVISAR CUIDADOSAMENTE O ARQUIVO CSV.
"""
import os
import csv
import asyncio
import time
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
    try:
        # Usando 'utf-8-sig' para ignorar o BOM (Byte Order Mark) do Excel.
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            # Remove espaços em branco dos nomes das colunas para maior robustez
            reader.fieldnames = [header.strip() for header in reader.fieldnames]

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
    print("\n--- RESUMO DA EXCLUSÃO ---")
    print("O script irá deletar permanentemente os seguintes objetos:")
    if not objects_to_delete: return False
    for item in objects_to_delete:
        print(f"  - TIPO: {item.get('OBJECT_TYPE', 'N/A')}, NOME: {item.get('DISPLAY_NAME', 'N/A')}, ID/API_NAME: {item.get('DELETION_IDENTIFIER', 'N/A')}")
    print("\n---------------------------------")
    print(f"Total de objetos a serem deletados: {len(objects_to_delete)}")
    print("\n⚠️  ATENÇÃO: ESTA AÇÃO É IRREVERSÍVEL! ⚠️")
    confirmation = input("Para confirmar a exclusão, digite 'CONFIRMAR' e pressione Enter: ")
    return confirmation.strip().upper() == 'CONFIRMAR'

async def delete_record(session, semaphore, url, item, results_list):
    display_name = item.get('DISPLAY_NAME')
    api_name = item.get('DELETION_IDENTIFIER')
    try:
        async with semaphore:
            kwargs = {'ssl': VERIFY_SSL}
            if USE_PROXY and PROXY_URL: kwargs['proxy'] = PROXY_URL
            async with session.delete(url, **kwargs) as response:
                response_text = await response.text()
                # Logando a resposta completa da API para depuração
                logging.info(f"Resposta da API para '{api_name}': Status={response.status}, Corpo={response_text}")
                
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
            # Normaliza o tipo de objeto lido do CSV para corresponder à chave
            items_to_process = grouped_objects.get(object_type) or grouped_objects.get(object_type.replace('_', ' '))
            if not items_to_process:
                continue

            logging.info(f"Processando {len(items_to_process)} objetos do tipo: {object_type}")
            
            base_ssot_url = f"{instance_url}/services/data/{API_VERSION}/ssot"

            if object_type == 'ACTIVATION':
                for item in items_to_process:
                    identifier = item['DELETION_IDENTIFIER']
                    url = f"{base_ssot_url}/activations/{identifier}"
                    deletion_tasks.append(delete_record(session, semaphore, url, item, results))

            elif object_type == 'SEGMENT':
                for item in items_to_process:
                    identifier = item['DELETION_IDENTIFIER']
                    url = f"{base_ssot_url}/segments/{identifier}"
                    deletion_tasks.append(delete_record(session, semaphore, url, item, results))

            elif object_type == 'DATA_STREAM':
                for item in items_to_process:
                    identifier = item['DELETION_IDENTIFIER']
                    url = f"{base_ssot_url}/data-streams/{identifier}?shouldDeleteDataLakeObject=true"
                    deletion_tasks.append(delete_record(session, semaphore, url, item, results))

            elif object_type == 'CALCULATED_INSIGHT':
                for item in items_to_process:
                    identifier = item['DELETION_IDENTIFIER']
                    url = f"{base_ssot_url}/calculated-insights/{identifier}"
                    deletion_tasks.append(delete_record(session, semaphore, url, item, results))
            
            # --- AJUSTE CRÍTICO AQUI ---
            elif object_type == 'DMO':
                for item in items_to_process:
                    # Usa o DeveloperName diretamente no endpoint correto da API SSOT
                    identifier = item['DELETION_IDENTIFIER']
                    url = f"{base_ssot_url}/data-model-objects/{identifier}"
                    deletion_tasks.append(delete_record(session, semaphore, url, item, results))
            
        await asyncio.gather(*deletion_tasks)

    # --- Relatório Final ---
    print("\n--- RELATÓRIO FINAL DA EXCLUSÃO ---")
    success_count = sum(1 for r in results if r['status'] == '✅ Sucesso')
    failure_count = len(results) - success_count
    # Ordena os resultados para mostrar falhas primeiro
    results.sort(key=lambda x: x['status'], reverse=True) 
    for result in results: 
        print(f"{result['status']} - {result['name']}: {result['message']}")
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