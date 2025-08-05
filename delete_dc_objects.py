"""
Este script realiza uma exclusão em massa de objetos do Data Cloud com base em um
arquivo CSV aprovado manualmente.


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

import requests
import aiohttp
from dotenv import load_dotenv

# --- Configuration ---
API_VERSION = "v64.0"
CONCURRENCY_LIMIT = 10  # Limite de chamadas de API simultâneas para evitar rate limiting
CSV_FILE_PATH = 'audit_objetos_para_exclusao.csv'

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Authentication ---
def get_access_token():
    """Authenticates with Salesforce using the Username-Password Flow."""
    logging.info("🔑 Authenticating with Salesforce using Username-Password Flow...")
    load_dotenv()

    sf_client_id = os.getenv("SF_CLIENT_ID")
    sf_client_secret = os.getenv("SF_CLIENT_SECRET")
    sf_username = os.getenv("SF_USERNAME")
    sf_password = os.getenv("SF_PASSWORD")
    sf_security_token = os.getenv("SF_SECURITY_TOKEN", "") # Opcional se o IP for confiável
    sf_login_url = os.getenv("SF_LOGIN_URL")

    if not all([sf_client_id, sf_client_secret, sf_username, sf_password, sf_login_url]):
        raise ValueError("Variáveis de ambiente necessárias para o fluxo Username-Password estão faltando (.env).")

    params = {
        'grant_type': 'password',
        'client_id': sf_client_id,
        'client_secret': sf_client_secret,
        'username': sf_username,
        'password': f"{sf_password}{sf_security_token}"
    }
    token_url = f"{sf_login_url}/services/oauth2/token"

    try:
        res = requests.post(token_url, data=params)
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
                logging.error("   Por favor, adicione a coluna e marque os objetos com 'SIM' para excluí-los.")
                return None
            
            to_delete = []
            for row in reader:
                delete_flag = row.get('DELETAR')
                if isinstance(delete_flag, str) and delete_flag.strip().upper() == 'SIM':
                    to_delete.append(row)
            
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
    
    if not objects_to_delete:
        return False

    col_widths = { 'ID_OR_API_NAME': len('ID_OR_API_NAME'), 'DISPLAY_NAME': len('DISPLAY_NAME'), 'OBJECT_TYPE': len('OBJECT_TYPE') }
    for item in objects_to_delete:
        col_widths['ID_OR_API_NAME'] = max(col_widths['ID_OR_API_NAME'], len(item.get('ID_OR_API_NAME', '')))
        col_widths['DISPLAY_NAME'] = max(col_widths['DISPLAY_NAME'], len(item.get('DISPLAY_NAME', '')))
        col_widths['OBJECT_TYPE'] = max(col_widths['OBJECT_TYPE'], len(item.get('OBJECT_TYPE', '')))

    header_format = (f"{{:<{col_widths['ID_OR_API_NAME']}}} | "
                     f"{{:<{col_widths['DISPLAY_NAME']}}} | "
                     f"{{:<{col_widths['OBJECT_TYPE']}}}")
    
    print("\n" + header_format.format("ID_OR_API_NAME", "DISPLAY_NAME", "OBJECT_TYPE"))
    print("-" * (col_widths['ID_OR_API_NAME'] + col_widths['DISPLAY_NAME'] + col_widths['OBJECT_TYPE'] + 6))

    for item in objects_to_delete:
        print(header_format.format(item.get('ID_OR_API_NAME', ''), item.get('DISPLAY_NAME', ''), item.get('OBJECT_TYPE', '')))

    print("\n---------------------------------")
    print(f"Total de objetos a serem deletados: {len(objects_to_delete)}")
    print("\n⚠️  ATENÇÃO: ESTA AÇÃO É IRREVERSÍVEL! ⚠️")
    confirmation = input("Para confirmar a exclusão, digite 'CONFIRMAR' e pressione Enter: ")
    
    return confirmation.strip().upper() == 'CONFIRMAR'

def normalize_api_name(name):
    """Removes common suffixes from API names for consistent matching."""
    if not isinstance(name, str): return ""
    return name.removesuffix('__dlm').removesuffix('__cio')

async def get_tooling_ids(session, semaphore, base_url, object_api_name, developer_names):
    """Fetches IDs from the Tooling API for a list of developer names."""
    if not developer_names: return {}
    
    formatted_names = ",".join([f"'{name}'" for name in developer_names])
    soql_query = f"SELECT Id, DeveloperName FROM {object_api_name} WHERE DeveloperName IN ({formatted_names})"
    
    params = {'q': soql_query}
    url = f"{base_url}/services/data/{API_VERSION}/tooling/query?{urlencode(params)}"
    
    try:
        async with semaphore:
            async with session.get(url) as response:
                response.raise_for_status()
                data = await response.json()
                return {record['DeveloperName']: record['Id'] for record in data.get('records', [])}
    except aiohttp.ClientError as e:
        logging.error(f"❌ Erro ao buscar IDs para {object_api_name}: {e}")
        return {}

async def delete_record(session, semaphore, url, item, results_list):
    """Performs a single DELETE request and records the result."""
    display_name = item.get('DISPLAY_NAME')
    api_name = item.get('ID_OR_API_NAME')
    try:
        async with semaphore:
            async with session.delete(url) as response:
                response_text = await response.text()
                if response.status in [200, 204]:
                    results_list.append({'status': '✅ Sucesso', 'name': display_name, 'message': f"Objeto '{api_name}' deletado."})
                else:
                    results_list.append({'status': '❌ Falha', 'name': display_name, 'message': f"Erro ao deletar '{api_name}' (Status: {response.status}): {response_text}"})
    except aiohttp.ClientError as e:
        results_list.append({'status': '❌ Falha', 'name': display_name, 'message': f"Erro de conexão ao deletar '{api_name}': {e}"})

# --- Main Deletion Logic ---
async def main():
    """Main function to run the deletion process."""
    objects_to_delete = read_and_prepare_csv(CSV_FILE_PATH)
    if not objects_to_delete: return

    if not confirm_deletion(objects_to_delete):
        logging.warning("🚫 Exclusão cancelada pelo usuário.")
        return

    auth_data = get_access_token()
    access_token, instance_url = auth_data['access_token'], auth_data['instance_url']
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    deletion_tasks = []
    results = []

    async with aiohttp.ClientSession(headers=headers) as session:
        logging.info("\n🔥 Iniciando processo de exclusão...")

        grouped_objects = {}
        for item in objects_to_delete:
            obj_type = item.get('OBJECT_TYPE')
            if obj_type not in grouped_objects: grouped_objects[obj_type] = []
            grouped_objects[obj_type].append(item)
        
        # Prioritize deletions: Activations first, then Segments, then others
        delete_order = ['ACTIVATION', 'SEGMENT', 'DATA STREAM', 'DATA MODEL', 'CALCULATED INSIGHT']
        
        for object_type_to_delete in delete_order:
            if object_type_to_delete not in grouped_objects:
                continue

            if object_type_to_delete == 'ACTIVATION':
                for item in grouped_objects['ACTIVATION']:
                    identifier = item['DELETION_IDENTIFIER']
                    url = f"{instance_url}/services/data/{API_VERSION}/ssot/activations/{identifier}"
                    deletion_tasks.append(delete_record(session, semaphore, url, item, results))

            elif object_type_to_delete == 'SEGMENT':
                for item in grouped_objects['SEGMENT']:
                    identifier = item['DELETION_IDENTIFIER']
                    url = f"{instance_url}/services/data/{API_VERSION}/ssot/segments/{identifier}"
                    deletion_tasks.append(delete_record(session, semaphore, url, item, results))

            elif object_type_to_delete == 'DATA STREAM':
                for item in grouped_objects['DATA STREAM']:
                    identifier = item['DELETION_IDENTIFIER']
                    url = f"{instance_url}/services/data/{API_VERSION}/ssot/data-streams/{identifier}?shouldDeleteDataLakeObject=true"
                    deletion_tasks.append(delete_record(session, semaphore, url, item, results))

            elif object_type_to_delete == 'CALCULATED INSIGHT':
                for item in grouped_objects['CALCULATED INSIGHT']:
                    identifier = item['DELETION_IDENTIFIER']
                    url = f"{instance_url}/services/data/{API_VERSION}/ssot/calculated-insights/{identifier}"
                    deletion_tasks.append(delete_record(session, semaphore, url, item, results))
            
            elif object_type_to_delete == 'DATA MODEL':
                dmo_names_with_suffix = [item['DELETION_IDENTIFIER'] for item in grouped_objects['DATA MODEL']]
                normalized_dmo_names = [normalize_api_name(name) for name in dmo_names_with_suffix]
                
                logging.info(f"Querying for DMO IDs with normalized names: {normalized_dmo_names}")
                dmo_ids = await get_tooling_ids(session, semaphore, instance_url, 'MktDataModelObject', normalized_dmo_names)
                logging.info(f"Received DMO IDs from Tooling API: {dmo_ids}")
                
                for item in grouped_objects['DATA MODEL']:
                    original_name = item['DELETION_IDENTIFIER']
                    normalized_name = normalize_api_name(original_name)
                    
                    logging.info(f"Checking for normalized name '{normalized_name}' in received IDs...")
                    if normalized_name in dmo_ids:
                        dmo_id = dmo_ids[normalized_name]
                        url = f"{instance_url}/services/data/{API_VERSION}/tooling/sobjects/MktDataModelObject/{dmo_id}"
                        deletion_tasks.append(delete_record(session, semaphore, url, item, results))
                    else:
                        results.append({'status': '❌ Falha', 'name': item['DISPLAY_NAME'], 'message': f"Não foi possível encontrar o ID para o DMO '{original_name}'."})
            
        await asyncio.gather(*deletion_tasks)

    # --- Relatório Final ---
    print("\n--- RELATÓRIO FINAL DA EXCLUSÃO ---")
    success_count = sum(1 for r in results if r['status'] == '✅ Sucesso')
    failure_count = len(results) - success_count

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
        logging.error(f"Um erro inesperado ocorreu durante o processo de exclusão: {e}", exc_info=True)
    finally:
        end_time = time.time()
        duration = end_time - start_time
        logging.info(f"\nTempo total de execução: {duration:.2f} segundos")
