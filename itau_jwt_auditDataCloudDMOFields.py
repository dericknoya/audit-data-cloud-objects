"""
Este script audita uma instância do Salesforce Data Cloud para identificar 
campos de DMOs (Data Model Objects) não utilizados.

Versão: 8.5

Metodologia:
- Utiliza o fluxo de autenticação JWT Bearer Flow (com certificado).
- Um campo "não utilizado" é aquele que não é encontrado em Segmentos, Ativações ou CIs.
- Audita o uso de campos analisando os critérios de Segmentos ('includeCriteria'/'excludeCriteria').
- Audita o uso de campos buscando os metadados detalhados de cada Ativação.
- Audita o uso de campos e DMOs dentro de Calculated Insights.
- O relatório final inclui os Nomes de Exibição do DMO e do Campo para melhor legibilidade.
- Exclui campos e DMOs de sistema/gerados automaticamente da análise.
- Adiciona uma coluna 'DELETAR' como a primeira coluna, com o valor padrão 'NAO'.
""""""
Este script audita uma instância do Salesforce Data Cloud para identificar 
campos de DMOs (Data Model Objects) não utilizados.

Versão: 8.9

Metodologia:
- Utiliza o fluxo de autenticação JWT Bearer Flow (com certificado).
- Um campo "não utilizado" é aquele que não é encontrado em Segmentos, Ativações ou CIs.
- Audita o uso de campos analisando os critérios de Segmentos ('includeCriteria'/'excludeCriteria').
- Audita o uso de campos buscando os metadados detalhados de cada Ativação.
- Audita o uso de campos e DMOs dentro de Calculated Insights.
- O relatório final inclui os Nomes de Exibição do DMO e do Campo para melhor legibilidade.
- Exclui campos e DMOs de sistema/gerados automaticamente da análise.
- Adiciona uma coluna 'DELETAR' como a primeira coluna, com o valor padrão 'NAO'.

https://itauengajamentoworkflow--sfdcenv.sandbox.my.salesforce.com/setup/emailverif?oid=00DHZ000005wWsf&k=Cj4KNQoPMDBESFowMDAwMDV3V3NmEg8wMkc1ZTAwMDAwMEhNUFUaDzAwNWJKMDAwMDBJQmtRTiAFGPGOgNWKMxIQZqX2F3TNj7c4bbTCL2SZ-RoMM8BzPljZ_74BH9AGIoMB7oqUKlTi_Qn0JX0eJxJSJ5aeGDLS78yeKTEWlimW0A87boj7UFM545RQg5MTN3PisrZNyHjCAsHlsYIB5T6oq2q3yB0utbQ36lOBtLo2MudV0mql5UZ5lvyDqalAyVdI_ahUi5a4Pocl_edt6l3lGdtjQX2WzwZxrvw6TrQm3-VLQSc%3D

"""
import os
import time
import asyncio
import csv
import json
import html
import logging
from collections import defaultdict
from urllib.parse import urljoin, urlencode

import jwt
import requests
import aiohttp
from dotenv import load_dotenv

# --- Configuração de Rede ---
USE_PROXY = True
PROXY_URL = "http://usuario:senha@proxy.suaempresa.com:porta" # Substitua pelo seu proxy
VERIFY_SSL = False

# --- Configuração do Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Autenticação ---
def get_access_token():
    logging.info("🔑 Autenticando com o Salesforce via JWT (certificado)...")
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
        logging.error("❌ Erro: Arquivo 'private.pem' não encontrado."); raise
        
    payload = {'iss': sf_client_id, 'sub': sf_username, 'aud': sf_audience, 'exp': int(time.time()) + 300}
    assertion = jwt.encode(payload, private_key, algorithm='RS256')
    params = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': assertion}
    token_url = f"{sf_login_url}/services/oauth2/token"
    
    try:
        res = requests.post(token_url, data=params, verify=VERIFY_SSL)
        res.raise_for_status()
        logging.info("✅ Autenticação bem-sucedida.")
        return res.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Erro na autenticação com Salesforce: {e.response.text if e.response else e}"); raise


# --- API Fetching ---
async def fetch_api_data(session, instance_url, relative_url, key_name=None):
    all_records = []
    current_url = urljoin(instance_url, relative_url)
    try:
        while current_url:
            kwargs = {'ssl': VERIFY_SSL}
            if USE_PROXY:
                kwargs['proxy'] = PROXY_URL

            async with session.get(current_url, **kwargs) as response:
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
        logging.error(f"❌ Erro ao buscar {current_url}: {e}"); return [] if key_name else {}

# --- Helper Functions ---
def _recursive_find_fields_generic(obj, used_fields_set):
    if isinstance(obj, dict):
        if 'name' in obj and 'type' in obj and isinstance(obj['name'], str):
            used_fields_set.add(obj['name'])
        
        for value in obj.values():
            _recursive_find_fields_generic(value, used_fields_set)

    elif isinstance(obj, list):
        for item in obj:
            _recursive_find_fields_generic(item, used_fields_set)


# --- Main Audit Logic ---
async def audit_dmo_fields():
    auth_data = get_access_token()
    access_token = auth_data['access_token']
    instance_url = auth_data['instance_url']
    logging.info('🚀 Iniciando auditoria de campos de DMO não utilizados...')
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}

    async with aiohttp.ClientSession(headers=headers) as session:
        logging.info("--- Etapa 1: Coletando metadados e listas de objetos ---")
        
        # **MUDANÇA CRÍTICA**: Usa uma única chamada com o parâmetro 'filters'
        logging.info(f"🔎 Buscando todos os segmentos via: /services/data/v64.0/ssot/segments?filters = SegmentStatus in Active")

        base_tasks = [
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/segments?filters = SegmentStatus in Active", 'segments'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=DataModelObject", 'metadata'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/activations", 'activations'),
            fetch_api_data(session, instance_url, "/services/data/v64.0/ssot/metadata?entityType=CalculatedInsight", 'metadata'),
        ]
        
        segments_list, dmo_metadata_list, activations_summary, calculated_insights = await asyncio.gather(*base_tasks)
        logging.info(f"✅ Total de {len(segments_list)} segmentos encontrados.")
        
        logging.info("\n--- Etapa 2: Coletando detalhes das Ativações ---")
        activation_detail_tasks = [fetch_api_data(session, instance_url, f"/services/data/v64.0/ssot/activations/{act.get('id')}") for act in activations_summary if act.get('id')]
        logging.info(f"🔎 Buscando detalhes para {len(activation_detail_tasks)} ativações...")
        detailed_activations = await asyncio.gather(*activation_detail_tasks)

    logging.info("\n📊 Dados coletados. Analisando o uso dos campos...")
    
    all_dmo_data = defaultdict(lambda: {'fields': {}, 'displayName': ''})
    dmo_prefixes_to_exclude = ('ssot', 'unified', 'individual', 'einstein', 'segment_membership', 'aa_', 'aal_')

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
    logging.info(f"🗺️ Mapeados {total_fields} campos em {len(all_dmo_data)} DMOs customizados (após filtragem).")

    used_fields = set()
    
    logging.info("🔍 Analisando uso de campos em Segmentos com busca de texto direta...")
    all_segment_criteria_text = ""
    for seg in segments_list:
        if criteria := seg.get('includeCriteria'): all_segment_criteria_text += html.unescape(criteria)
        if criteria := seg.get('excludeCriteria'): all_segment_criteria_text += html.unescape(criteria)
        if criteria := seg.get('filterDefinition'): all_segment_criteria_text += html.unescape(criteria)

    for dmo_name, data in all_dmo_data.items():
        for field_api_name in data['fields'].keys():
            if f'"{field_api_name}"' in all_segment_criteria_text:
                used_fields.add(field_api_name)
    logging.info(f"🔍 Identificados {len(used_fields)} campos únicos em Segmentos.")

    initial_count = len(used_fields)
    for act in detailed_activations:
        _recursive_find_fields_generic(act, used_fields)
    logging.info(f"🔍 Identificados {len(used_fields) - initial_count} campos adicionais em Ativações.")

    initial_count = len(used_fields)
    for ci in calculated_insights:
        _recursive_find_fields_generic(ci.get('ciObject', ci), used_fields)
        for rel in ci.get('relationships', []):
            if rel.get('fromEntity'): used_fields.add(rel['fromEntity'])
    logging.info(f"🔍 Identificados {len(used_fields) - initial_count} campos/objetos adicionais em Calculated Insights.")
    logging.info(f"Total de campos e objetos únicos em uso: {len(used_fields)}")

    unused_field_results = []
    field_prefixes_to_exclude = ('ssot__', 'KQ_')
    specific_fields_to_exclude = {'DataSource__c', 'DataSourceObject__c', 'InternalOrganization__c'}

    if not all_dmo_data:
         logging.warning("\n⚠️ Nenhum DMO customizado (e não-sistema) foi encontrado para auditar.")
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
    
    if not unused_field_results:
        logging.info("\n🎉 Nenhum campo órfão (não-sistema) encontrado. Todos os campos customizados estão em uso!")
    else:
        csv_file_path = 'audit_campos_dmo_nao_utilizados.csv'
        header = ['DELETAR', 'DMO_DISPLAY_NAME', 'DMO_API_NAME', 'FIELD_DISPLAY_NAME', 'FIELD_API_NAME', 'REASON']
        try:
            with open(csv_file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=header)
                writer.writeheader()
                writer.writerows(unused_field_results)
            logging.info(f"\n✅ Auditoria finalizada. {len(unused_field_results)} campos não utilizados (e não-sistema) encontrados.")
            logging.info(f"   Arquivo CSV gerado: {csv_file_path}")
        except IOError as e:
            logging.error(f"❌ Erro ao gravar o arquivo CSV: {e}")

if __name__ == "__main__":
    start_time = time.time()
    try:
        if os.name == 'nt':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(audit_dmo_fields())
    except Exception as e:
        logging.error(f"Um erro inesperado durante o processo de auditoria: {e}", exc_info=True)
    finally:
        end_time = time.time()
        duration = end_time - start_time
        logging.info(f"\nTempo total de execução: {duration:.2f} segundos")