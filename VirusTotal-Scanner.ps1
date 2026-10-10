# VirusTotal Domain Scanner
# Consulta a reputacao de dominios usando a API v3 do VirusTotal.

$ErrorActionPreference = "Stop"

# Configure a variavel de ambiente VT_API_KEY antes de executar.
$VT_API_KEY = $env:VT_API_KEY

if ([string]::IsNullOrWhiteSpace($VT_API_KEY)) {
    Write-Error "Configure a variavel de ambiente VT_API_KEY com sua chave da API."
    exit 1
}

# Dominios de exemplo: substitua pelos dominios que deseja analisar.
$dominios = @(
    "example.com",
    "microsoft.com",
    "github.com"
)

# Intervalo entre consultas, em segundos.
# Ajuste conforme os limites da sua conta VirusTotal.
$IntervaloSegundos = 20

function Get-VTDomainReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    $url = "https://www.virustotal.com/api/v3/domains/$Domain"
    $headers = @{ "x-apikey" = $VT_API_KEY }

    try {
        $response = Invoke-RestMethod `
            -Uri $url `
            -Headers $headers `
            -Method Get `
            -TimeoutSec 30

        $stats = $response.data.attributes.last_analysis_stats

        if ($null -eq $stats) {
            throw "A resposta nao contem estatisticas de analise."
        }

        $malicious = [int]$stats.malicious
        $suspicious = [int]$stats.suspicious
        $harmless = [int]$stats.harmless
        $undetected = [int]$stats.undetected
        $timeout = [int]$stats.timeout

        $total = 0
        foreach ($value in $stats.PSObject.Properties) {
            $total += [int]$value.Value
        }

        if ($malicious -gt 0) {
            $risco = "ALTO"
        }
        elseif ($suspicious -gt 0) {
            $risco = "MEDIO"
        }
        else {
            $risco = "SEM ALERTAS REPORTADOS"
        }

        return [PSCustomObject]@{
            Dominio    = $Domain
            Malicioso  = $malicious
            Suspeito   = $suspicious
            Harmless   = $harmless
            NaoDetectado = $undetected
            Timeout    = $timeout
            Total      = $total
            Risco      = $risco
            Status     = "Sucesso"
            Erro       = ""
            ConsultadoEm = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
    }
    catch {
        $statusCode = ""

        if ($null -ne $_.Exception.Response) {
            try {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            catch {
                $statusCode = ""
            }
        }

        $mensagem = $_.Exception.Message

        if ($statusCode -eq 429) {
            $mensagem = "Limite de requisicoes da API atingido (HTTP 429)."
        }
        elseif ($statusCode -eq 401 -or $statusCode -eq 403) {
            $mensagem = "Chave invalida ou acesso nao autorizado (HTTP $statusCode)."
        }
        elseif ($statusCode -eq 404) {
            $mensagem = "Dominio nao encontrado na API (HTTP 404)."
        }

        return [PSCustomObject]@{
            Dominio      = $Domain
            Malicioso    = $null
            Suspeito     = $null
            Harmless     = $null
            NaoDetectado = $null
            Timeout      = $null
            Total        = $null
            Risco        = "INDETERMINADO"
            Status       = "Erro"
            Erro         = $mensagem
            ConsultadoEm = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
    }
}

Write-Host "`n=== VIRUSTOTAL DOMAIN SCANNER ===" -ForegroundColor Cyan
Write-Host "Dominios na fila: $($dominios.Count)"
Write-Host "Intervalo entre consultas: $IntervaloSegundos segundos`n"

$resultados = [System.Collections.Generic.List[object]]::new()

for ($i = 0; $i -lt $dominios.Count; $i++) {
    $domain = $dominios[$i]
    $numero = $i + 1

    Write-Progress `
        -Activity "Consultando VirusTotal" `
        -Status "$numero/$($dominios.Count): $domain" `
        -PercentComplete (($numero / $dominios.Count) * 100)

    Write-Host "[$numero/$($dominios.Count)] Consultando $domain..." `
        -ForegroundColor Cyan

    $resultado = Get-VTDomainReport -Domain $domain
    $resultados.Add($resultado)

    if ($resultado.Status -eq "Sucesso") {
        if ($resultado.Malicioso -gt 0) {
            $cor = "Red"
        }
        elseif ($resultado.Suspeito -gt 0) {
            $cor = "Yellow"
        }
        else {
            $cor = "Green"
        }

        Write-Host "  Maliciosos: $($resultado.Malicioso) | Suspeitos: $($resultado.Suspeito) | $($resultado.Risco)" `
            -ForegroundColor $cor
    }
    else {
        Write-Host "  Falha: $($resultado.Erro)" -ForegroundColor Red
    }

    # Evita aguardar desnecessariamente depois da ultima consulta.
    if ($i -lt ($dominios.Count - 1) -and $IntervaloSegundos -gt 0) {
        Start-Sleep -Seconds $IntervaloSegundos
    }
}

Write-Progress -Activity "Consultando VirusTotal" -Completed

# Exporta o relatorio para a pasta atual.
$csvName = Join-Path (Get-Location) (
    "VirusTotal_Reporte_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss")
)

$resultados | Export-Csv `
    -Path $csvName `
    -NoTypeInformation `
    -Encoding UTF8

# Resumo final.
$sucessos = @($resultados | Where-Object { $_.Status -eq "Sucesso" })
$falhas = @($resultados | Where-Object { $_.Status -eq "Erro" })
$alertas = @($sucessos | Where-Object {
    $_.Malicioso -gt 0 -or $_.Suspeito -gt 0
})

Write-Host "`n=== RESULTADO FINAL ===" -ForegroundColor Cyan
Write-Host "Total consultado: $($resultados.Count)"
Write-Host "Consultas concluidas: $($sucessos.Count)"
Write-Host "Falhas: $($falhas.Count)"
Write-Host "Dominios com deteccoes: $($alertas.Count)"

if ($alertas.Count -gt 0) {
    Write-Host "`n=== DOMINIOS COM DETECCOES ===" -ForegroundColor Yellow
    $alertas |
        Select-Object Dominio, Malicioso, Suspeito, Risco |
        Format-Table -AutoSize
}

Write-Host "`nRelatorio salvo em: $csvName" -ForegroundColor Green

# Abre o CSV no aplicativo associado, se possivel.
try {
    Invoke-Item $csvName
}
catch {
    Write-Warning "Nao foi possivel abrir o CSV automaticamente."
}
