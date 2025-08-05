# Scripts de Auditoria e Exclusão para Salesforce Data Cloud

Este projeto contém um conjunto de scripts Python para ajudar na manutenção e limpeza de uma instância do Salesforce Data Cloud. O processo é dividido em duas fases principais:

1.  **Auditoria de Objetos:** Identifica objetos de alto nível (Segmentos, Data Streams, etc.) que estão potencialmente órfãos ou inativos.
2.  **Auditoria de Campos:** Após a limpeza dos objetos, este script analisa os Data Model Objects (DMOs) restantes para identificar campos específicos que não estão sendo utilizados.

Para cada fase, há um script de **auditoria (somente leitura)** que gera um relatório em CSV e um script de **exclusão (destrutivo)** que age com base no relatório revisado.

O objetivo é fornecer um fluxo de trabalho seguro: primeiro, auditar e revisar; depois, executar a exclusão de forma controlada.

---

## Funcionalidades

-   **Autenticação Segura:** Utiliza o fluxo JWT Bearer para se conectar à Salesforce, sem a necessidade de armazenar senhas.
-   **Análise Abrangente:** Os scripts de auditoria verificam:
    -   **Objetos de Alto Nível:** Segmentos, Ativações, DMOs, Data Streams e Calculated Insights.
    -   **Campos de DMOs:** Identifica campos individuais dentro dos DMOs que não estão em uso.
-   **Regras Claras:** Aplica um conjunto de regras lógicas para determinar se um objeto ou campo está órfão ou inativo.
-   **Fluxo de Trabalho em Duas Etapas:** Garante que nenhuma exclusão seja feita sem revisão e aprovação manual nos arquivos CSV gerados.
-   **Performance:** Utiliza chamadas de API assíncronas para acelerar a coleta e a exclusão de dados.

---

## Pré-requisitos

1.  **Python 3.7+** instalado em sua máquina.
2.  **Bibliotecas Python:** Instale as dependências necessárias com o seguinte comando:
    ```bash
    pip install requests aiohttp python-dotenv pyjwt cryptography
    ```
3.  **Salesforce Connected App:**
    -   Uma [Connected App](https://help.salesforce.com/s/articleView?id=sf.connected_app_create.htm&type=5) configurada em sua organização Salesforce.
    -   A autenticação JWT Bearer deve estar habilitada.
    -   O usuário da API (associado ao `SF_USERNAME`) deve ser pré-autorizado na Connected App.
    -   Os escopos de OAuth `cdp_query_api`, `cdp_management_api` e `sf__cdp_delete` devem ser concedidos.

---

## Configuração

1.  **Chave Privada (`private.pem`):**
    -   Gere um par de chaves pública e privada usando OpenSSL.
    -   Faça o upload do certificado público (`.crt`) para a sua Connected App.
    -   Coloque o arquivo da chave privada, renomeado para `private.pem`, no mesmo diretório dos scripts.

2.  **Arquivo de Ambiente (`.env`):**
    -   Crie um arquivo chamado `.env` no mesmo diretório dos scripts.
    -   Adicione as seguintes variáveis de ambiente ao arquivo, substituindo pelos valores da sua organização e Connected App:
    ```env
    # --- Salesforce Connected App Details ---
    SF_CLIENT_ID="SEU_CONSUMER_KEY_DA_CONNECTED_APP"
    SF_USERNAME="SEU_NOME_DE_USUARIO_DA_API"
    
    # --- Salesforce Environment URLs ---
    # Use [https://login.salesforce.com](https://login.salesforce.com) para produção
    # Use [https://test.salesforce.com](https://test.salesforce.com) para sandboxes
    SF_AUDIENCE="[https://login.salesforce.com](https://login.salesforce.com)"
    SF_LOGIN_URL="[https://login.salesforce.com](https://login.salesforce.com)"
    ```

---

## Como Executar o Processo Completo

O processo foi projetado para ser executado em fases distintas para garantir a segurança.

### Fase 1: Auditoria e Exclusão de Objetos (Segmentos, Data Streams, etc.)

Primeiro, execute o script de auditoria de objetos para gerar o relatório.

```bash
python auditDataCloudobjects.py
```

-   Isso criará o arquivo `audit_objetos_para_exclusao.csv`.
-   **Abra este arquivo CSV** e revise cada linha. Para cada objeto que você deseja excluir, altere o valor na coluna `DELETAR` de `NAO` para `SIM`.

**AVISO:** A exclusão de objetos é **irreversível**.

Depois de marcar os objetos, execute o script de exclusão:

```bash
python delete_dc_objects.py
```

### Fase 2: Auditoria e Exclusão de Campos de DMOs

Após limpar os objetos órfãos, você pode analisar os campos dentro dos DMOs restantes.

Execute o script de auditoria de campos:

```bash
python auditDataCloudDMOFields.py
```

-   Isso criará o arquivo `audit_campos_dmo_nao_utilizados.csv`.
-   **Abra este novo arquivo CSV** e revise cada campo. Para cada campo que você deseja excluir, altere o valor na coluna `DELETAR` de `NAO` para `SIM`.

**AVISO:** A exclusão de campos é **irreversível**.

Depois de marcar os campos, execute o script de exclusão de campos:

```bash
python delete_dmo_fields.py
```

---

## Entendendo as Regras de Auditoria

### Regras para Objetos (`auditDataCloudobjects.py`)

1.  **Segmentos:**
    -   **Órfão:** Não publicado nos últimos 30 dias E não utilizado como filtro em outro segmento.
    -   **Inativo:** Última publicação > 30 dias, MAS é utilizado como filtro.
2.  **Ativações:**
    -   **Órfã:** Associada a um segmento classificado como "Órfão".
3.  **Data Model Objects (DMOs):**
    -   **Órfão:** É customizado (`__dlm`), não utilizado em Segmentos, Data Graphs, CIs ou Data Actions, E foi criado há mais de 90 dias.
4.  **Data Streams:**
    -   **Órfão:** Última atualização > 30 dias E o array `mappings` da API está vazio.
    -   **Inativo:** Última atualização > 30 dias, MAS possui `mappings`.
5.  **Calculated Insights (CIs):**
    -   **Inativo:** Último processamento bem-sucedido > 90 dias.

### Regras para Campos (`auditDataCloudDMOFields.py`)

1.  **Campo de DMO:**
    -   **Órfão:** O campo não é utilizado como atributo em nenhum **Segmento** ou **Ativação**, e não é uma dimensão ou medida em nenhum **Calculated Insight**.
