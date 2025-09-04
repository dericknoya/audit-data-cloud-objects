# -*- coding: utf-8 -*-
"""
Este script realiza a exclusão em massa de campos de DMOs (Data Model Objects)
baseado em um arquivo CSV de auditoria.

Versão: 3.1 - Adiciona verificação pós-exclusão para erros 500.

Metodologia:
- Utiliza o fluxo de autenticação JWT Bearer Flow (com certificado).
- Suporta o uso de proxy através da variável de ambiente 'PROXY_URL'.
- Lê um arquivo CSV e o ID técnico de deleção da coluna 'DELETION_IDENTIFIER'.
- Para cada campo a ser excluído:
  - Remove o mapeamento associado, se houver.
  - Tenta deletar o campo usando seu ID técnico.
  - MELHORIA: Se a API retornar um erro 500 (Internal Server Error), o script
    faz uma pausa e executa uma consulta de verificação para confirmar se o campo
    foi realmente deletado. Se a verificação mostrar que o campo não existe mais,
    a operação é marcada como SUCESSO.
- Pede uma confirmação explícita ao usuário antes de iniciar a exclusão.
- Suporta um modo de simulação ('--dry-run').

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

# NOVA FUNÇÃO DE VERIFICAÇÃO
async def verify_field_deletion(session, instance_url, field_id):
    """Verifica se um campo ainda existe consultando seu ID via Tooling API."""
    soql_query = f"SELECT Id FROM MktDataModelField WHERE Id = '{field_id}'"
    params = {'q': soql_query}
    url = f"{instance_url}/services/data/v64.0/tooling/query?{urlencode(params)}"
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            data = await response.json()
            # Se a lista de 'records' estiver vazia, o campo foi deletado com sucesso.
            return not data.get('records')
    except aiohttp.ClientError as e:
        print(f"❌ Erro durante a verificação da exclusão: {e}")
        # Por segurança, se a verificação falhar, assumimos que a exclusão falhou.
        return False

async def delete_dmo_field(session, instance_url, field_id, field_name_for_log, dry_run=False):
    """Deleta um único campo de DMO, com lógica de verificação para erro 500."""
    delete_url = f"{instance_url}/services/data/v64.0/tooling/sobjects/MktDataModelField/{field_id}"
    
    if dry_run:
        print(f"🐫 [SIMULAÇÃO] Deletaria o campo: {field_name_for_log} (ID: {field_id})")
        return True, "Modo de Simulação (Dry Run)"

    try:
        async with session.delete(delete_url) as response:
            # Captura o texto do erro no início para usar depois, se necessário
            error_text = await response.text()

            if response.status == 204: # 204 No Content é o sucesso para DELETE
                print(f"✅ Campo deletado com sucesso: {field_name_for_log}")
                return True, "Deletado com Sucesso"
            
            # LÓGICA DE VERIFICAÇÃO PARA ERRO 500
            elif response.status == 500:
                print(f"⚠️  Recebido erro 500 para o campo '{field_name_for_log}'. Tentando verificar o status da exclusão...")
                await asyncio.sleep(3) # Pausa estratégica para dar tempo à plataforma
                
                is_truly_deleted = await verify_field_deletion(session, instance_url, field_id)
                
                if is_truly_deleted:
                    print(f"✅ Verificação confirmou que o campo '{field_name_for_log}' foi deletado com sucesso.")
                    return True, "Deletado com Sucesso (Após verificação do erro 500)"
                else:
                    print(f"❌ Verificação mostrou que o campo '{field_name_for_log}' ainda existe. A exclusão falhou.")
                    return False, f"Erro 500 e verificação confirmou falha: {error_text}"
            
            else: # Trata outros erros (400, 403, 404, etc.)
                print(f"❌ Falha ao deletar o campo {field_name_for_log}: {response.status} - {error_text}")
                return False, f"Erro {response.status}: {error_text}"
                
    except aiohttp.ClientError as e:
        print(f"❌ Erro de conexão ao deletar o campo {field_name_for_log}: {e}")
        return False, f"Erro de conexão: {e}"

# --- Lógica de Orquestração --- (sem alterações daqui para baixo)

async def process_single_field_deletion(session, instance_url, row_data, dry_run):
    """
    Processa a exclusão de um único campo, lendo o ID diretamente do CSV.
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
    
    # Etapa 2: Ler o ID técnico diretamente da coluna do CSV
    field_id = row_data.get('DELETION_IDENTIFIER')
    if not field_id or len(field_id) < 15: # Validação básica do ID
        msg = f"Coluna 'DELETION_IDENTIFIER' está vazia ou contém um ID inválido ('{field_id}')."
        print(f"❌ Erro: {msg} ({field_log_name})")
        return field_log_name, False, msg
    
    print(f"   - ID técnico lido do arquivo para {field_log_name}: {field_id}")
    
    # Etapa 3: Deletar o campo (agora com a lógica de verificação embutida)
    delete_success, delete_reason = await delete_dmo_field(
        session, instance_url, field_id, field_log_name, dry_run
    )
    return field_log_name, delete_success, delete_reason


async def mass_delete_fields(file_path, dry_run):
    """Orquestra o processo de leitura, confirmação e exclusão de campos."""
    
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            required_cols = ['DELETAR', 'DMO_DISPLAY_NAME', 'FIELD_DISPLAY_NAME', 
                             'OBJECT_MAPPING_ID', 'FIELD_MAPPING_ID', 'DELETION_IDENTIFIER']
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