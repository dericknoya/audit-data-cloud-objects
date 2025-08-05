# -*- coding: utf-8 -*-
"""
Este script realiza a exclusão em massa de campos de DMOs (Data Model Objects)
baseado em um arquivo CSV de auditoria.



Metodologia:
- Utiliza o fluxo de autenticação OAuth 2.0 Username-Password.
- Lê um arquivo CSV (padrão: 'audit_campos_dmo_nao_utilizados.csv').
- Filtra as linhas onde a coluna 'DELETAR' está marcada como 'SIM'.
- Para cada campo a ser excluído, faz uma consulta SOQL individual e específica na 
  Tooling API para obter seu ID, aumentando a confiabilidade.
- Pede uma confirmação explícita ao usuário antes de iniciar a exclusão.
- Realiza as chamadas de exclusão de forma assíncrona.

!! ATENÇÃO !!
!! ESTE SCRIPT É DESTRUTIVO E DELETA METADADOS PERMANENTEMENTE. !!
!! USE COM EXTREMO CUIDADO E FAÇA BACKUPS QUANDO APLICÁVEL. !!
"""
import os
import time
import asyncio
import csv
import argparse
from urllib.parse import urlencode

import requests
import aiohttp
from dotenv import load_dotenv

# --- Função de Autenticação ---

def get_access_token():
    """Autentica com o Salesforce usando o fluxo Username-Password."""
    print("🔑 Autenticando com o Salesforce via Usuário e Senha...")
    load_dotenv()
    
    sf_client_id = os.getenv("SF_CLIENT_ID")
    sf_client_secret = os.getenv("SF_CLIENT_SECRET")
    sf_username = os.getenv("SF_USERNAME")
    sf_password = os.getenv("SF_PASSWORD")
    sf_security_token = os.getenv("SF_SECURITY_TOKEN")
    sf_login_url = os.getenv("SF_LOGIN_URL")

    if not all([sf_client_id, sf_client_secret, sf_username, sf_password, sf_security_token, sf_login_url]):
        raise ValueError("Uma ou mais variáveis de ambiente para o fluxo de senha estão faltando.")

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
        print("✅ Autenticação bem-sucedida.")
        return res.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro na autenticação com Salesforce: {e.response.text if e.response else e}")
        raise

# --- Funções da API ---

async def fetch_tooling_api_query(session, base_url, soql_query):
    """Busca dados da Tooling API usando uma consulta SOQL."""
    params = {'q': soql_query}
    url = f"{base_url}/services/data/v64.0/tooling/query?{urlencode(params)}"
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            data = await response.json()
            return data.get('records', [])
    except aiohttp.ClientError as e:
        print(f"❌ Erro ao consultar a Tooling API {url}: {e}")
        return []

async def delete_dmo_field(session, instance_url, field_id, field_name_for_log):
    """Deleta um único campo de DMO usando seu ID técnico."""
    delete_url = f"{instance_url}/services/data/v64.0/tooling/sobjects/MktDataModelField/{field_id}"
    
    try:
        async with session.delete(delete_url) as response:
            if response.status == 204: # 204 No Content é o sucesso para DELETE
                print(f"✅ Campo deletado com sucesso: {field_name_for_log}")
                return field_name_for_log, True, "Deletado com Sucesso"
            else:
                error_text = await response.text()
                print(f"❌ Falha ao deletar o campo {field_name_for_log}: {response.status} - {error_text}")
                return field_name_for_log, False, f"Erro {response.status}: {error_text}"
    except aiohttp.ClientError as e:
        print(f"❌ Erro de conexão ao deletar o campo {field_name_for_log}: {e}")
        return field_name_for_log, False, f"Erro de conexão: {e}"

# --- Lógica Principal de Deleção ---

async def mass_delete_fields(file_path):
    """Orquestra o processo de leitura, confirmação e exclusão de campos."""
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            all_rows = list(reader)
    except FileNotFoundError:
        print(f"❌ Erro: O arquivo de auditoria '{file_path}' não foi encontrado.")
        return

    fields_to_delete = [
        row for row in all_rows if row.get('DELETAR', 'NAO').upper() == 'SIM'
    ]

    if not fields_to_delete:
        print("🙂 Nenhum campo marcado com 'SIM' na coluna 'DELETAR'. Nenhuma ação a ser feita.")
        return

    print("="*60)
    print("⚠️ ATENÇÃO: Os seguintes campos estão marcados para DELEÇÃO PERMANENTE:")
    print("="*60)
    for row in fields_to_delete:
        print(f"- DMO: {row['DMO_DISPLAY_NAME']} | Campo: {row['FIELD_DISPLAY_NAME']} ({row['FIELD_API_NAME']})")
    
    print("\n" + "!"*60)
    print("Esta ação é IRREVERSÍVEL. Uma vez deletados, os campos não podem ser recuperados.")
    confirm = input("👉 Para confirmar a exclusão, digite 'CONFIRMAR' e pressione Enter: ")
    if confirm != 'CONFIRMAR':
        print("\n🚫 Exclusão cancelada pelo usuário.")
        return
    print("\n✅ Confirmação recebida. Iniciando processo de exclusão...")

    auth_data = get_access_token()
    access_token = auth_data['access_token']
    instance_url = auth_data['instance_url']
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}

    async with aiohttp.ClientSession(headers=headers) as session:
        delete_tasks = []
        print("\n🔎 Buscando IDs técnicos e preparando para exclusão (um por um)...")
        
        for row in fields_to_delete:
            dmo_api_name = row['DMO_API_NAME']
            field_api_name = row['FIELD_API_NAME']
            
            soql = f"SELECT Id FROM MktDataModelField WHERE DeveloperName = '{field_api_name}' AND MktDataModelObject.DeveloperName = '{dmo_api_name}'"
            field_records = await fetch_tooling_api_query(session, instance_url, soql)
            
            field_log_name = f"{row['DMO_DISPLAY_NAME']}.{row['FIELD_DISPLAY_NAME']}"

            if field_records and len(field_records) > 0:
                field_id = field_records[0]['Id']
                print(f"   - ID encontrado para {field_log_name}: {field_id}")
                delete_tasks.append(delete_dmo_field(session, instance_url, field_id, field_log_name))
            else:
                print(f"⚠️ Aviso: Não foi possível encontrar um ID para o campo {field_log_name}. Ele será ignorado.")

        if not delete_tasks:
            print("\nNenhum campo pôde ser processado para exclusão após a busca de IDs.")
            return
        
        results = await asyncio.gather(*delete_tasks)
    
        # Apresentar o resumo
        success_count = sum(1 for _, success, _ in results if success)
        failure_count = len(results) - success_count
        
        print("\n" + "="*60)
        print("✅ PROCESSO DE EXCLUSÃO FINALIZADO")
        print("="*60)
        print(f"Sucessos: {success_count}")
        print(f"Falhas: {failure_count}")

        if failure_count > 0:
            print("\nDetalhes das falhas:")
            for field, success, reason in results:
                if not success:
                    print(f"- Campo: {field} | Motivo: {reason}")
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deleta em massa campos de DMOs baseados em um arquivo CSV.")
    parser.add_argument(
        '--file', 
        default='audit_campos_dmo_nao_utilizados.csv', 
        help="Caminho para o arquivo CSV de auditoria (padrão: 'audit_campos_dmo_nao_utilizados.csv')"
    )
    args = parser.parse_args()

    start_time = time.time()
    try:
        asyncio.run(mass_delete_fields(args.file))
    except Exception as e:
        print(f"Ocorreu um erro inesperado durante o processo de exclusão: {e}")
    finally:
        end_time = time.time()
        duration = end_time - start_time
        print(f"\nTempo total de execução: {duration:.2f} segundos")