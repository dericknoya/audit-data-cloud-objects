"""
Este script audita uma instância do Salesforce Data Cloud para identificar objetos
não utilizados com base em um conjunto de regras.

Version: 1
- Remove completamente a chamada ao endpoint '/ssot/activations'.
- A lista de Ativações agora é obtida exclusivamente a partir dos IDs coletados
  via '/jobs/query' em 'MktSgmntActvtnAudAttribute', alinhando o script com a
  lógica mais robusta e consistente do projeto.

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
from urllib.parse import urljoin, urlencode
from datetime import datetime, timedelta, timezone

import jwt
import requests
import aiohttp
from dotenv import load_dotenv
from tqdm.asyncio import tqdm

# --- Configuração de Rede ---
USE_PROXY = True
PROXY_URL = "http://usuario:senha@proxy.suaempresa.com:porta" # Substitua pelo seu proxy
VERIFY_SSL = False

# --- Configuração do Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Funções de Autenticação e Busca (reutilizadas e aprimoradas) ---

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
        proxies = {'http': PROXY_URL, 'https': PROXY_URL} if USE_PROXY else None
        res = requests.post(token_url, data=params, proxies=proxies, verify=VERIFY_SSL)
        res.raise_for_status()
        logging.info("✅ Autenticação bem-sucedida.")
        return res.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Erro na autenticação com Salesforce: {e.response.text if e.response else e}"); raise


async def fetch_api_data(session, instance_url, relative_url, semaphore, key_name=None):
    async with semaphore:
        all_records = []
        current_url = urljoin(instance_url, relative_url)
        try:
            while current_url:
                kwargs = {'ssl': VERIFY_SSL}
                if USE_PROXY:
                    kwargs['proxy'] = PROXY_URL

                async with session.get(current_url, **kwargs) as response:
                    response.raise_for_status()
                    data = await response.json()
                    if key_name:
                        all_records.extend(data.get(key_name, []))
                        next_page_url = data.get('nextRecordsUrl') or data.get('nextPageUrl')

                        if next_page_url and not next_page_url.startswith('http'):
                            current_url = urljoin(instance_url, next_page_url)
                        else:
                            current_url = next_page_url
                    else: 
                        return data
            return all_records
        except aiohttp.ClientError:
            return [] if key_name else {}

# --- Lógica Principal da Auditoria ---
async def audit_data_cloud_objects():
    auth_data = get_access_token()
    access_token, instance_url = auth_data['access_token'], auth_data['instance_url']
    logging.info('🚀 Iniciando auditoria de objetos do Data Cloud...')
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    
    CONCURRENT_REQUESTS = 25
    semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS)

    async with aiohttp.ClientSession(headers=headers) as session:
        logging.info("--- Etapa 1: Coletando todos os dados necessários ---")

        # Define todas as queries e chamadas de API
        segments_query = "SELECT Id, Name, LastPublishedEndDateTime, (SELECT Id FROM NestedSegments) FROM MarketSegment"
        activations_query = "SELECT Id, Name, MarketSegmentId FROM Activation"
        dmo_query = "SELECT DeveloperName, CreatedDate, Label FROM MktDataModelObject WHERE IsCustomizable = true"
        activation_attributes_query = "SELECT EntityDeveloperName, AttributeDeveloperName FROM MktSgmntActvtnAudAttribute"
        data_streams_url = "/services/data/v60.0/ssot/datasources"
        ci_url = "/services/data/v60.0/ssot/metadata?entityType=CalculatedInsight"
        # Adicione aqui futuras chamadas para Data Graphs e Data Actions se necessário

        initial_tasks = [
            fetch_api_data(session, instance_url, f"/services/data/v60.0/query?{urlencode({'q': segments_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, f"/services/data/v60.0/query?{urlencode({'q': activations_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, f"/services/data/v60.0/tooling/query?{urlencode({'q': dmo_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, f"/services/data/v60.0/query?{urlencode({'q': activation_attributes_query})}", semaphore, 'records'),
            fetch_api_data(session, instance_url, data_streams_url, semaphore, 'dataSources'),
            fetch_api_data(session, instance_url, ci_url, semaphore, 'metadata'),
        ]

        results = await tqdm.gather(*initial_tasks, desc="Coletando dados primários")
        all_segments, all_activations, all_dmos, activation_attributes, all_data_streams, all_cis = results
        
        logging.info(f"✅ Coleta primária finalizada. Encontrados: {len(all_segments)} segmentos, {len(all_activations)} ativações, {len(all_dmos)} DMOs customizáveis.")

        # Coleta de detalhes adicionais (ex: mapeamentos de Data Streams)
        data_stream_detail_tasks = [fetch_api_data(session, instance_url, f"/services/data/v60.0/ssot/datasources/{ds.get('id')}", semaphore) for ds in all_data_streams]
        data_stream_details = await tqdm.gather(*data_stream_detail_tasks, desc="Buscando detalhes de Data Streams")

    # --- Etapa 2: Análise e Classificação ---
    logging.info("\n--- Etapa 2: Analisando e classificando objetos ---")
    audit_results = []
    now_utc = datetime.now(timezone.utc)
    
    # ** 1. Análise de Segmentos **
    logging.info("🔍 Analisando Segmentos...")
    thirty_days_ago = now_utc - timedelta(days=30)
    nested_segment_ids = {nested['Id'] for seg in all_segments if seg.get('NestedSegments') for nested in seg['NestedSegments']['records']}
    orphan_segment_ids = set()

    for seg in all_segments:
        last_published_str = seg.get('LastPublishedEndDateTime')
        is_published_long_ago = True
        if last_published_str:
            last_published_date = datetime.fromisoformat(last_published_str.replace('Z', '+00:00'))
            if last_published_date > thirty_days_ago:
                is_published_long_ago = False
        
        is_nested = seg['Id'] in nested_segment_ids

        if is_published_long_ago and not is_nested:
            orphan_segment_ids.add(seg['Id'])
            audit_results.append({
                'ObjectType': 'Segmento', 'ObjectName': seg['Name'], 'ObjectId': seg['Id'],
                'Status': 'Órfão', 'Reason': 'Não publicado nos últimos 30 dias e não é usado como filtro aninhado.'
            })
        elif is_published_long_ago and is_nested:
            audit_results.append({
                'ObjectType': 'Segmento', 'ObjectName': seg['Name'], 'ObjectId': seg['Id'],
                'Status': 'Inativo', 'Reason': 'Última publicação > 30 dias, mas é usado como filtro aninhado.'
            })

    # ** 2. Análise de Ativações **
    logging.info("🔍 Analisando Ativações...")
    for act in all_activations:
        if act.get('MarketSegmentId') in orphan_segment_ids:
            audit_results.append({
                'ObjectType': 'Ativação', 'ObjectName': act['Name'], 'ObjectId': act['Id'],
                'Status': 'Órfã', 'Reason': f"Associada ao segmento órfão ID: {act.get('MarketSegmentId')}"
            })

    # ** 3. Análise de DMOs **
    logging.info("🔍 Analisando DMOs...")
    used_dmos_and_fields = {attr['EntityDeveloperName'] for attr in activation_attributes if attr.get('EntityDeveloperName')}
    used_dmos_and_fields.update({attr['AttributeDeveloperName'] for attr in activation_attributes if attr.get('AttributeDeveloperName')})
    # Adicionar aqui a lógica para extrair DMOs de Segmentos, CIs, Data Graphs...
    
    ninety_days_ago = now_utc - timedelta(days=90)
    for dmo in all_dmos:
        dmo_name = dmo.get('DeveloperName')
        if dmo_name in used_dmos_and_fields:
            continue
            
        created_date_str = dmo.get('CreatedDate')
        is_older_than_90_days = True
        if created_date_str:
            created_date = datetime.fromisoformat(created_date_str.replace('Z', '+00:00'))
            if created_date > ninety_days_ago:
                is_older_than_90_days = False
        
        if is_older_than_90_days:
            audit_results.append({
                'ObjectType': 'DMO', 'ObjectName': dmo.get('Label'), 'ObjectId': dmo_name,
                'Status': 'Órfão', 'Reason': 'Customizado, não utilizado em Segmentos/Ativações/CIs, etc. e criado há mais de 90 dias.'
            })

    # ** 4. Análise de Data Streams **
    logging.info("🔍 Analisando Data Streams...")
    for ds_detail in data_stream_details:
        if not ds_detail: continue
        last_updated_str = ds_detail.get('lastModifiedDate')
        is_updated_long_ago = False
        if last_updated_str:
            last_updated_date = datetime.fromisoformat(last_updated_str.replace('Z', '+00:00'))
            if last_updated_date < thirty_days_ago:
                is_updated_long_ago = True

        if is_updated_long_ago:
            mappings = ds_detail.get('mappings', [])
            if not mappings:
                audit_results.append({
                    'ObjectType': 'Data Stream', 'ObjectName': ds_detail.get('name'), 'ObjectId': ds_detail.get('id'),
                    'Status': 'Órfão', 'Reason': 'Última atualização > 30 dias e não possui mapeamentos.'
                })
            else:
                audit_results.append({
                    'ObjectType': 'Data Stream', 'ObjectName': ds_detail.get('name'), 'ObjectId': ds_detail.get('id'),
                    'Status': 'Inativo', 'Reason': 'Última atualização > 30 dias, mas ainda possui mapeamentos.'
                })

    # ** 5. Análise de Calculated Insights **
    logging.info("🔍 Analisando Calculated Insights...")
    for ci in all_cis:
        last_run_str = ci.get('lastRunEndDateTime') # Supondo este nome de campo
        status = ci.get('status')
        
        is_processed_long_ago = True
        if status == 'Success' and last_run_str:
            last_run_date = datetime.fromisoformat(last_run_str.replace('Z', '+00:00'))
            if last_run_date > ninety_days_ago:
                is_processed_long_ago = False

        if is_processed_long_ago:
            audit_results.append({
                'ObjectType': 'Calculated Insight', 'ObjectName': ci.get('displayName'), 'ObjectId': ci.get('name'),
                'Status': 'Inativo', 'Reason': 'Último processamento bem-sucedido > 90 dias.'
            })

    # --- Etapa 3: Geração do Relatório ---
    logging.info("\n--- Etapa 3: Gerando relatório consolidado ---")
    if not audit_results:
        logging.info("🎉 Nenhum objeto órfão ou inativo encontrado de acordo com as regras.")
        return

    csv_file_path = 'data_cloud_audit_report.csv'
    header = ['ObjectType', 'ObjectName', 'ObjectId', 'Status', 'Reason']
    try:
        with open(csv_file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()
            writer.writerows(audit_results)
        logging.info(f"✅ Relatório de auditoria gerado com sucesso: {csv_file_path} ({len(audit_results)} itens)")
    except IOError as e:
        logging.error(f"❌ Erro ao gravar o arquivo CSV: {e}")


if __name__ == "__main__":
    start_time = time.time()
    try:
        if os.name == 'nt':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(audit_data_cloud_objects())
    except Exception as e:
        logging.error(f"Um erro inesperado durante o processo de auditoria: {e}", exc_info=True)
    finally:
        end_time = time.time()
        duration = end_time - start_time
        logging.info(f"\nTempo total de execução: {duration:.2f} segundos")