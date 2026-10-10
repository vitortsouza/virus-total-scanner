# VirusTotal Domain Scanner

Script em PowerShell para consultar a reputação de domínios utilizando a API v3 do VirusTotal. A ferramenta coleta estatísticas de detecção, identifica possíveis alertas e exporta os resultados para um arquivo CSV.

## Funcionalidades

- Consulta de domínios pela API oficial do VirusTotal.
- Identificação de detecções maliciosas e suspeitas.
- Classificação resumida dos resultados.
- Tratamento de erros HTTP e falhas de consulta.
- Intervalo configurável entre requisições.
- Exibição do progresso e de um resumo final.
- Exportação dos resultados para CSV.
- Abertura automática do relatório após a execução.

## Requisitos

- Windows com PowerShell 5.1 ou superior.
- Acesso à internet.
- Uma chave de API válida do VirusTotal.
- Permissão para consultar a API conforme os limites da sua conta.

## Configuração

### 1. Obtenha uma chave de API

Acesse a página oficial:

https://www.virustotal.com/gui/my-apikey

### 2. Configure a variável de ambiente

Abra o PowerShell e execute:

```powershell
$env:VT_API_KEY = "SUA_CHAVE_DA_API"
```

A chave será utilizada pelo script sem precisar ser escrita diretamente no arquivo `.ps1`.

**Segurança:** nunca envie sua chave de API para um repositório público. Para uso permanente, prefira configurar uma variável de ambiente do Windows ou utilizar um gerenciador de segredos.

### 3. Configure os domínios

Edite a variável `$dominios` no script:

```powershell
$dominios = @(
    "example.com",
    "microsoft.com",
    "github.com"
)
```

Substitua os exemplos pelos domínios que deseja consultar.

### 4. Execute o scanner

No diretório onde o arquivo foi salvo:

```powershell
.\VirusTotal-Scanner.ps1
```

Caso a política de execução do PowerShell impeça a execução, verifique a política aplicada no seu ambiente antes de alterá-la. Evite mudanças globais desnecessárias.

## Classificação dos resultados

| Classificação | Significado |
|---|---|
| `ALTO` | Pelo menos um mecanismo reportou o domínio como malicioso. |
| `MEDIO` | Nenhum resultado malicioso, mas pelo menos um mecanismo reportou o domínio como suspeito. |
| `SEM ALERTAS REPORTADOS` | Não foram encontradas detecções maliciosas ou suspeitas nas estatísticas consultadas. |
| `INDETERMINADO` | A consulta falhou ou não foi possível obter os dados esperados. |

A classificação é uma simplificação para facilitar a triagem. Uma detecção isolada não comprova que um domínio seja malicioso, assim como a ausência de alertas não garante que seja seguro.

## Relatório CSV

Ao final da execução, o script gera um arquivo com data e hora no nome, por exemplo:

`VirusTotal_Reporte_20261010_153000.csv`

O relatório contém campos como:

- `Dominio`: domínio consultado.
- `Malicioso`: quantidade de detecções maliciosas.
- `Suspeito`: quantidade de detecções suspeitas.
- `Harmless`: resultados classificados como inofensivos.
- `NaoDetectado`: resultados sem detecção.
- `Timeout`: consultas que excederam o tempo limite.
- `Total`: total de resultados de análise contabilizados.
- `Risco`: classificação resumida.
- `Status`: sucesso ou erro na consulta.
- `Erro`: mensagem de erro, quando aplicável.
- `ConsultadoEm`: data e hora da consulta.

O arquivo é salvo no diretório atual do PowerShell.

## Limites da API

O número de consultas permitidas depende do plano e das condições de uso da conta VirusTotal. O intervalo padrão de 20 segundos pode ser ajustado no script:

```powershell
$IntervaloSegundos = 20
```

Erros como HTTP 429 indicam que o limite de requisições foi atingido. Nesses casos, aguarde o período adequado antes de realizar novas consultas.

## Avisos

- O script consulta informações de reputação existentes no VirusTotal; não realiza uma varredura direta dos servidores dos domínios.
- Os resultados dependem dos dados disponíveis no serviço no momento da consulta.
- A consulta pode retornar erros de autenticação, autorização, limite de requisições ou ausência de dados.
- Utilize o scanner para fins legítimos de administração, segurança e investigação.
- Verifique os resultados antes de bloquear domínios ou tomar decisões operacionais.

## Licença

Este projeto ainda não especifica uma licença. Para permitir formalmente o uso, a modificação e a redistribuição, adicione um arquivo `LICENSE` com os termos escolhidos.

---

Desenvolvido em PowerShell para facilitar consultas de reputação de domínios e a geração de relatórios de segurança.
