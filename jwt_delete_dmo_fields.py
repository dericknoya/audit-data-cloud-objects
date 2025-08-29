# -*- coding: utf-8 -*-
"""
Este script realiza a exclusão em massa de campos de DMOs (Data Model Objects)
baseado em um arquivo CSV de auditoria.

Versão: 2.1 - Correção de leitura de CSV (BOM) e ajuste na variável de proxy.

Metodologia:
- Utiliza o fluxo de autenticação JWT Bearer Flow (com certificado).
- Suporta o uso de proxy através da variável de ambiente 'PROXY_URL'.
- Lê um arquivo CSV (padrão: 'audit_campos_dmo_nao_utilizados.csv') usando a codificação 'utf-8-sig'
  para evitar problemas com BOM (Byte Order Mark).
- Filtra as linhas onde a coluna 'DELETAR' está marcada como 'SIM'.
- Para cada campo a ser excluído:
  - Verifica se existe um mapeamento associado nas colunas 'OBJECT_MAPPING_ID' e 'FIELD_MAPPING_ID'.
  - Se um mapeamento existir, realiza uma chamada DELETE para removê-lo primeiro.
  - Se a remoção do mapeamento for bem-sucedida (ou se não houver mapeamento),
    faz uma consulta SOQL na Tooling API para obter o ID técnico do campo.
  - Realiza a chamada DELETE para excluir o campo.
- Pede uma confirmação explícita ao usuário antes de iniciar a exclusão.
- Realiza todas as chamadas de API (mapeamento e campo) de forma assíncrona.
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

# --- Configuração de Autenticação e Proxy ---

def get_access_token():
    """Autentica com o Salesforce usando o fluxo JWT Bearer Flow."""
    print("🔑 Autenticando com o Salesforce via JWT (certificado)...")
    load_dotenv()
    
    sf_client_id = os.getenv("SF_CLIENT_ID")
    sf_username = os.getenv("SF_USERNAME")
    sf_audience = os.getenv("SF_AUDIENCE")
    sf_login_url = os.getenv("SF_LOGIN_URL")

    # AJUSTE: Suporte a Proxy via variável de ambiente PROXY_URL
    proxy_url = os.getenv("PROXY_URL")
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    
    if proxies:
        print(f"🌍 Usando proxy para autenticação: {proxy_url}")

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
        res = requests.post(token_url, data=params, proxies=proxies)
        res.raise_for_status()
        print("✅ Autenticação bem-sucedida.")
        return res.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro na autenticação com Salesforce: {e.response.text if e.response else e}"); raise


# --- Funções da API ---

async def delete_field_mapping(session, instance_url, obj_mapping_id, field_mapping_id, field_name_for_log, dry_run=False):
    """Deleta o mapeamento de um campo de DMO."""
    delete_url = (f"{instance_url}/services/data/v64.0/ssot/data-model-object-mappings/"
                  f"{obj_mapping_id}/field-mappings/{field_mapping_id}")

    if dry_run:
        print(f"🐫 [SIMULAÇÃO] Removeria o mapeamento do campo: {field_name_for_log}")
        return True, "Modo de Simulação (Dry Run)"
    
    try:
        async with session.delete(delete_url) as response:
            if response.status == 204:
                print(f"✅ Mapeamento do campo '{field_name_for_log}' removido com sucesso.")
                return True, "Mapeamento Removido"
            else:
                error_text = await response.text()
                print(f"❌ Falha ao remover mapeamento de {field_name_for_log}: {response.status} - {error_text}")
                return False, f"Erro ao remover mapeamento {response.status}: {error_text}"
    except aiohttp.ClientError as e:
        print(f"❌ Erro de conexão ao remover mapeamento de {field_name_for_log}: {e}")
        return False, f"Erro de conexão: {e}"

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
        return True, "Modo de Simulação (Dry Run)"

    try:
        async with session.delete(delete_url) as response:
            if response.status == 204: # 204 No Content é o sucesso para DELETE
                print(f"✅ Campo deletado com sucesso: {field_name_for_log}")
                return True, "Deletado com Sucesso"
            else:
                error_text = await response.text()
                print(f"❌ Falha ao deletar o campo {field_name_for_log}: {response.status} - {error_text}")
                return False, f"Erro {response.status}: {error_text}"
    except aiohttp.ClientError as e:
        print(f"❌ Erro de conexão ao deletar o campo {field_name_for_log}: {e}")
        return False, f"Erro de conexão: {e}"

# --- Lógica de Orquestração ---

async def process_single_field_deletion(session, instance_url, row_data, dry_run):
    """
    Processa a exclusão de um único campo, incluindo a remoção do mapeamento, se houver.
    Retorna uma tupla (nome_do_campo, sucesso, mensagem).
    """
    field_log_name = f"{row_data['DMO_DISPLAY_NAME']}.{row_data['FIELD_DISPLAY_NAME']}"
    obj_mapping_id = row_data.get("OBJECT_MAPPING_ID")
    field_mapping_id = row_data.get("FIELD_MAPPING_ID")

    # Etapa 1: Remover mapeamento, se existir
    has_mapping = obj_mapping_id and obj_mapping_id != "Não possui mapeamento"
    if has_mapping:
        print(f"   - Campo '{field_log_name}' possui mapeamento. Removendo primeiro...")
        map_success, map_reason = await delete_field_mapping(
            session, instance_url, obj_mapping_id, field_mapping_id, field_log_name, dry_run
        )
        if not map_success:
            return field_log_name, False, f"Falha na remoção do mapeamento: {map_reason}"
    
    # Etapa 2: Obter o ID técnico do campo
    dmo_api_name = row_data['DMO_API_NAME']
    field_api_name = row_data['FIELD_API_NAME']
    
    soql = f"SELECT Id FROM MktDataModelField WHERE DeveloperName = '{field_api_name}' AND MktDataModelObject.DeveloperName = '{dmo_api_name}'"
    field_records = await fetch_tooling_api_query(session, instance_url, soql)
    
    if not field_records or len(field_records) == 0:
        msg = "Não foi possível encontrar um ID técnico para o campo. Pode já ter sido deletado."
        print(f"⚠️  Aviso: {msg} ({field_log_name})")
        return field_log_name, False, msg

    field_id = field_records[0]['Id']
    print(f"   - ID técnico encontrado para {field_log_name}: {field_id}")
    
    # Etapa 3: Deletar o campo
    delete_success, delete_reason = await delete_dmo_field(
        session, instance_url, field_id, field_log_name, dry_run
    )
    return field_log_name, delete_success, delete_reason


async def mass_delete_fields(file_path, dry_run):
    """Orquestra o processo de leitura, confirmação e exclusão de campos."""
    
    try:
        # AJUSTE: Mudar a codificação para 'utf-8-sig' para lidar com o BOM (Byte Order Mark)
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            # Validar cabeçalhos necessários
            required_cols = ['DELETAR', 'DMO_DISPLAY_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 
                             'DMO_API_NAME', 'OBJECT_MAPPING_ID', 'FIELD_MAPPING_ID']
            if not all(col in reader.fieldnames for col in required_cols):
                missing = [col for col in required_cols if col not in reader.fieldnames]
                print(f"❌ Erro: O arquivo CSV '{file_path}' não contém as colunas necessárias: {', '.join(missing)}")
                return
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
        has_map_str = " (COM MAPEAMENTO)" if row.get("OBJECT_MAPPING_ID") != "Não possui mapeamento" else ""
        print(f"- DMO: {row['DMO_DISPLAY_NAME']} | Campo: {row['FIELD_DISPLAY_NAME']}{has_map_str}")
    
    if dry_run:
        print("\n🐫 EXECUTANDO EM MODO DE SIMULAÇÃO (DRY RUN). NENHUM METADADO SERÁ ALTERADO.")
    else:
        print("\n" + "!"*60)
        print("Esta ação é IRREVERSÍVEL. Uma vez deletados, os metadados não podem ser recuperados.")
        confirm = input("👉 Para confirmar a exclusão, digite 'CONFIRMAR' e pressione Enter: ")
        if confirm != 'CONFIRMAR':
            print("\n🚫 Exclusão cancelada pelo usuário.")
            return
        print("\n✅ Confirmação recebida. Iniciando processo de exclusão...")

    auth_data = get_access_token()
    access_token = auth_data['access_token']
    instance_url = auth_data['instance_url']
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    
    # AJUSTE: Configuração de proxy via variável de ambiente PROXY_URL
    proxy_url = os.getenv("PROXY_URL")
    if proxy_url:
        print(f"🌍 Usando proxy para chamadas de API: {proxy_url}")

    async with aiohttp.ClientSession(headers=headers, proxy=proxy_url) as session:
        tasks = []
        print("\n🔎 Iniciando processamento dos campos para exclusão...")
        for row in fields_to_delete:
            tasks.append(process_single_field_deletion(session, instance_url, row, dry_run))

        if not tasks:
            print("\nNenhum campo pôde ser processado para exclusão.")
            return
        
        results = await asyncio.gather(*tasks)
    
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
        help="Executa o script em modo de simulação, sem deletar nenhum metadado."
    )
    args = parser.parse_args()

    start_time = time.time()
    try:
        asyncio.run(mass_delete_fields(args.file, args.dry_run))
    except Exception as e:
        print(f"\n❌ Ocorreu um erro inesperado e fatal durante a execução: {e}")
    finally:
        end_time = time.time()
        duration = end_time - start_time
        print(f"\nTempo total de execução: {duration:.2f} segundos")