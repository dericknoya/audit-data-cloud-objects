# -*- coding: utf-8 -*-
"""
Este script audita uma instância do Salesforce Data Cloud para identificar 
campos de DMOs (Data Model Objects) não utilizados.

Versão: 6.6 - Autenticação por Usuário e Senha

Metodologia:
- Utiliza o fluxo de autenticação OAuth 2.0 Username-Password.
- Um campo "não utilizado" é aquele que não é encontrado em Segmentos, Ativações ou CIs.

"""
import os
import time
import asyncio
import csv
import json
import html
from collections import defaultdict
from urllib.parse import urljoin

# A biblioteca 'jwt' e 'cryptography' não são mais necessárias para este fluxo
import requests
import aiohttp
from dotenv import load_dotenv

# --- MUDANÇA: Nova Função de Autenticação ---

def get_access_token():
    """Autentica com o Salesforce usando o fluxo Username-Password."""
    print("🔑 Autenticando com o Salesforce via Usuário e Senha...")
    load_dotenv()
    
    # Carrega as credenciais do arquivo .env
    sf_client_id = os.getenv("SF_CLIENT_ID")
    sf_client_secret = os.getenv("SF_CLIENT_SECRET")
    sf_username = os.getenv("SF_USERNAME")
    sf_password = os.getenv("SF_PASSWORD")
    sf_security_token = os.getenv("SF_SECURITY_TOKEN")
    sf_login_url = os.getenv("SF_LOGIN_URL")

    if not all([sf_client_id, sf_client_secret, sf_username, sf_password, sf_security_token, sf_login_url]):
        raise ValueError("Uma ou mais variáveis de ambiente para o fluxo de senha estão faltando.")

    # Constrói o corpo da requisição (payload)
    params = {
        'grant_type': 'password',
        'client_id': sf_client_id,
        'client_secret': sf_client_secret,
        'username': sf_username,
        'password': f"{sf_password}{sf_security_token}"  # Concatena a senha e o token
    }
    
    token_url = f"{sf_login_url}/services/oauth2/token"

    try:
        res = requests.post(token_url, data=params)
        res.raise_for_status() # Lança um erro para status HTTP 4xx/5xx
        print("✅ Autenticação bem-sucedida.")
        return res.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro na autenticação com Salesforce: {e.response.text if e.response else e}")
        # Uma causa comum de erro é "invalid_grant". Verifique se a senha, token e IPs permitidos estão corretos.
        raise

# --- API Fetching ---

async def fetch_api_data(session, instance_url, relative_url, key_name=None):
    all_records = []
    current_url = urljoin(instance_url, relative_url)
    try:
        while current_url:
            async with session.get(current_url) as response:
                response.raise_for_status(); data = await response.json()
                if key_name:
                    all_records.extend(data.get(key_name, []))
                    next_page_url = data.get('nextPageUrl')
                    if next_page_url and not next_page_url.startswith('http'):
                        next_page_url = urljoin(instance_url, next_page_url)
                else: 
                    return data
                if current_url == next_page_url: break
                current_url = next_page_url
        return all_records
    except aiohttp.ClientError as e:
        print(f"❌ Erro ao buscar {current_url}: {e}"); return [] if key_name else {}

# --- Helper Functions ---

def _recursive_find_fields(obj, used_fields_set):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == 'fieldApiName' and isinstance(value, str):
                used_fields_set.add(value)
            # Para CIs e Ativações, a chave pode ser 'name'
            elif key == 'name' and 'type' in obj and isinstance(value, str):
                 used_fields_set.add(value)
            elif isinstance(value, (dict, list)):
                _recursive_find_fields(value, used_fields_set)
    elif isinstance(obj, list):
        for item in obj:
            _recursive_find_fields(item, used_fields_set)

def parse_segment_criteria(criteria_str, used_fields_set):
    if not criteria_str: return
    try:
        decoded_str = html.unescape(criteria_str)
        data = json.loads(decoded_str)
        _recursive_find_fields(data, used_fields_set)
    except (json.JSONDecodeError, TypeError):
        print(f"⚠️ Aviso: Falha ao processar critério de segmento: {criteria_str[:100]}...")


# --- Main Audit Logic ---

async def audit_dmo_fields():
    auth_data = get_access_token()
    access_token = auth_data['access_token']
    instance_url = auth_data['instance_url']
    print('🚀 Iniciando auditoria de campos de DMO não utilizados...')
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}

    async with aiohttp.ClientSession(headers=headers) as session:
        print("--- Etapa 1: Coletando metadados e listas de objetos ---")
        base_tasks = [
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=DataModelObject", 'metadata'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/segments", 'segments'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/activations", 'activations'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=CalculatedInsight", 'metadata'),
        ]
        dmo_metadata_list, segments_list, activations_summary, calculated_insights = await asyncio.gather(*base_tasks)
        
        print("\n--- Etapa 2: Coletando detalhes das Ativações ---")
        activation_detail_tasks = [fetch_api_data(session, instance_url, f"/services/data/v64.0/ssot/activations/{act.get('id')}") for act in activations_summary if act.get('id')]
        print(f"🔎 Buscando detalhes para {len(activation_detail_tasks)} ativações...")
        detailed_activations = await asyncio.gather(*activation_detail_tasks)

    print("\n📊 Dados coletados. Analisando o uso dos campos...")
    
    all_dmo_data = defaultdict(lambda: {'fields': {}, 'displayName': ''})
    
    dmo_prefixes_to_exclude = (
        'ssot', 'unified', 'individual', 'einstein', 
        'segment_membership', 'aa_', 'aal_'
    )

    for dmo in dmo_metadata_list:
        if (dmo_name := dmo.get('name')) and dmo_name.endswith('__dlm'):
            dmo_name_lower = dmo_name.lower()
            if any(dmo_name_lower.startswith(prefix) for prefix in dmo_prefixes_to_exclude):
                continue

            all_dmo_data[dmo_name]['displayName'] = dmo.get('displayName', dmo_name)
            for field in dmo.get('fields', []):
                if field_name := field.get('name'):
                    all_dmo_data[dmo_name]['fields'][field_name] = field.get('displayName', field_name)
    
    total_fields = sum(len(data['fields']) for data in all_dmo_data.values())
    print(f"🗺️ Mapeados {total_fields} campos em {len(all_dmo_data)} DMOs customizados (após filtragem).")

    used_fields = set()

    # Análise de Segmentos
    for seg in segments_list:
        if criteria := seg.get('includeCriteria'): parse_segment_criteria(criteria, used_fields)
        if criteria := seg.get('excludeCriteria'): parse_segment_criteria(criteria, used_fields)
    print(f"🔍 Identificados {len(used_fields)} campos únicos em Segmentos.")

    # Análise de Ativações
    initial_count = len(used_fields)
    for act in detailed_activations:
        _recursive_find_fields(act, used_fields)
    print(f"🔍 Identificados {len(used_fields) - initial_count} campos adicionais em Ativações.")

    # Análise de CIs
    initial_count = len(used_fields)
    for ci in calculated_insights:
        _recursive_find_fields(ci.get('ciObject', ci), used_fields)
        for rel in ci.get('relationships', []):
            if rel.get('fromEntity'): used_fields.add(rel['fromEntity'])
    print(f"🔍 Identificados {len(used_fields) - initial_count} campos/objetos adicionais em Calculated Insights.")
    print(f"Total de campos únicos em uso: {len(used_fields)}")

    # Comparação e Resultados
    unused_field_results = []
    
    field_prefixes_to_exclude = ('ssot__', 'KQ_')
    specific_fields_to_exclude = {'DataSource__c', 'DataSourceObject__c', 'InternalOrganization__c'}

    if not all_dmo_data:
         print("\n⚠️ Nenhum DMO customizado (e não-sistema) foi encontrado para auditar.")
         return

    for dmo_name, data in all_dmo_data.items():
        if dmo_name in used_fields: continue
        for field_api_name, field_display_name in data['fields'].items():
            if field_api_name not in used_fields:
                if not field_api_name.startswith(field_prefixes_to_exclude) and \
                   field_api_name not in specific_fields_to_exclude:
                    unused_field_results.append({
                        'DELETAR': 'NAO',
                        'DMO_DISPLAY_NAME': data['displayName'],
                        'DMO_API_NAME': dmo_name,
                        'FIELD_DISPLAY_NAME': field_display_name,
                        'FIELD_API_NAME': field_api_name, 
                        'REASON': 'Não utilizado em Segmentos, Ativações ou CIs'
                    })
    
    # Geração do CSV
    if not unused_field_results:
        print("\n🎉 Nenhum campo órfão (não-sistema) encontrado. Todos os campos customizados estão em uso!")
    else:
        csv_file_path = 'audit_campos_dmo_nao_utilizados.csv'
        header = ['DELETAR', 'DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'REASON']
        try:
            with open(csv_file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=header)
                writer.writeheader()
                writer.writerows(unused_field_results)
            print(f"\n✅ Auditoria finalizada. {len(unused_field_results)} campos não utilizados (e não-sistema) encontrados.")
            print(f"   Arquivo CSV gerado: {csv_file_path}")
        except IOError as e:
            print(f"❌ Erro ao gravar o arquivo CSV: {e}")

if __name__ == "__main__":
    start_time = time.time()
    try:
        if os.name == 'nt':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(audit_dmo_fields())
    except Exception as e:
        print(f"Ocorreu um erro inesperado durante o processo de auditoria: {e}")
    finally:
        end_time = time.time()
        duration = end_time - start_time
        print(f"\nTempo total de execução: {duration:.2f} segundos")