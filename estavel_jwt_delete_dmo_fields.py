# -*- coding: utf-8 -*-
"""
Este script realiza a exclusão em massa de campos de DMOs (Data Model Objects)
baseado em um arquivo CSV de auditoria.

Versão: 1.5 - Deleção em Massa (Autenticação JWT)

Metodologia:
- Utiliza o fluxo de autenticação JWT Bearer Flow (com certificado).
- Lê um arquivo CSV (padrão: 'audit_campos_dmo_nao_utilizados.csv').
- Filtra as linhas onde a coluna 'DELETAR' está marcada como 'SIM'.
- Para cada campo a ser excluído, faz uma consulta SOQL individual e específica na 
  Tooling API para obter seu ID, aumentando a confiabilidade.
- Pede uma confirmação explícita ao usuário antes de iniciar a exclusão.
- Realiza as chamadas de exclusão de forma assíncrona.
- Suporta um modo de simulação ('--dry-run') para verificar a operação sem deletar.

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

import jwt
import requests
import aiohttp
from dotenv import load_dotenv

# --- MUDANÇA: Autenticação revertida para JWT Bearer Flow ---

def get_access_token():
    """Autentica com o Salesforce usando o fluxo JWT Bearer Flow."""
    print("🔑 Autenticando com o Salesforce via JWT (certificado)...")
    load_dotenv()
    
    sf_client_id = os.getenv("SF_CLIENT_ID")
    sf_username = os.getenv("SF_USERNAME")
    sf_audience = os.getenv("SF_AUDIENCE")
    sf_login_url = os.getenv("SF_LOGIN_URL")

    if not all([sf_client_id, sf_username, sf_audience, sf_login_url]):
        raise ValueError("Uma ou mais variáveis de ambiente para o fluxo JWT estão faltando.")
    
    try:
        with open('private.pem', 'r') as f: 
            private_key = f.read()
    except FileNotFoundError:
        print("❌ Erro: Arquivo 'private.pem' não encontrado."); raise
        
    payload = {'iss': sf_client_id, 'sub': sf_username, 'aud': sf_audience, 'exp': int(time.time()) + 300}
    assertion = jwt.encode(payload, private_key, algorithm='RS256')
    params = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': assertion}
    token_url = f"{sf_login_url}/services/oauth2/token"
    
    try:
        res = requests.post(token_url, data=params)
        res.raise_for_status()
        print("✅ Autenticação bem-sucedida.")
        return res.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro na autenticação com Salesforce: {e.response.text if e.response else e}"); raise


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

async def delete_dmo_field(session, instance_url, field_id, field_name_for_log, dry_run=False):
    """Deleta um único campo de DMO usando seu ID técnico."""
    delete_url = f"{instance_url}/services/data/v64.0/tooling/sobjects/MktDataModelField/{field_id}"
    
    if dry_run:
        print(f"🐫 [SIMULAÇÃO] Deletaria o campo: {field_name_for_log} (ID: {field_id})")
        return field_name_for_log, True, "Modo de Simulação (Dry Run)"

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

async def mass_delete_fields(file_path, dry_run):
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
    
    if dry_run:
        print("\n🐫 EXECUTANDO EM MODO DE SIMULAÇÃO (DRY RUN). NENHUM CAMPO SERÁ DELETADO.")
    else:
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
                delete_tasks.append(delete_dmo_field(session, instance_url, field_id, field_log_name, dry_run))
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
    
        if dry_run:
            print("\n🐫 Simulação (Dry Run) concluída. Nenhum dado foi alterado.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deleta em massa campos de DMOs baseados em um arquivo CSV.")
    parser.add_argument(
        '--file', 
        default='audit_campos_dmo_nao_utilizados.csv', 
        help="Caminho para o arquivo CSV de auditoria (padrão: 'audit_campos_dmo_nao_utilizados.csv')"
    )
    parser.add_argument(
        '--dry-run', 
        action='store_true', 
        help="Executa o script em modo de simulação, sem deletar nenhum campo."
    )
    args = parser.parse_args()

    start_time = time.time()
    try:
        asyncio.run(mass_delete_fields(args.file, args.dry_run))
    except Exception as e:
        print(f"Ocorreu um erro inesperado durante o processo de exclusão: {e}")
    finally:
        end_time = time.time()
        duration = end_time - start_time
        print(f"\nTempo total de execução: {duration:.2f} segundos")