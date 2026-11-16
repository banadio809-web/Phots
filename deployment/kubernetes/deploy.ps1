[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:/-]*$')]
    [string]$Image,
    [string]$CatalogFile = (Join-Path $PSScriptRoot 'base/catalog.json'),
    [string]$EnvFile = (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) '.env.k8s')
)

$ErrorActionPreference = 'Stop'
$base = Join-Path $PSScriptRoot 'base'
if (-not (Test-Path -LiteralPath $CatalogFile -PathType Leaf)) {
    throw "Catalog file not found: $CatalogFile"
}
if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
    throw "Credentials file not found: $EnvFile. Copy .env.k8s.example to .env.k8s and fill it locally."
}

kubectl apply -f (Join-Path $base 'namespace.yaml')
if ($LASTEXITCODE -ne 0) { throw 'Could not create the phots namespace.' }
kubectl create secret generic phots-supabase `
    --namespace phots `
    --from-env-file=$EnvFile `
    --dry-run=client -o yaml | kubectl apply -f -
if ($LASTEXITCODE -ne 0) { throw 'Could not provision phots-supabase Secret.' }

$baseCatalog = Join-Path $base 'catalog.json'
$temporaryCatalog = $null
if ([IO.Path]::GetFullPath($CatalogFile) -ne [IO.Path]::GetFullPath($baseCatalog)) {
    $temporaryCatalog = Join-Path $base ('.catalog-' + [guid]::NewGuid().ToString('N') + '.json')
    Copy-Item -LiteralPath $baseCatalog -Destination $temporaryCatalog
    try {
        Copy-Item -LiteralPath $CatalogFile -Destination $baseCatalog -Force
        $manifest = kubectl kustomize $base
        if ($LASTEXITCODE -ne 0) { throw 'Kustomize manifest rendering failed.' }
    }
    finally {
        Copy-Item -LiteralPath $temporaryCatalog -Destination $baseCatalog -Force
        Remove-Item -LiteralPath $temporaryCatalog -Force
    }
}
else {
    $manifest = kubectl kustomize $base
    if ($LASTEXITCODE -ne 0) { throw 'Kustomize manifest rendering failed.' }
}
$rewrites = 0
$manifest = [regex]::Replace($manifest, '(?m)^([ \t]*)image: phots:local[ \t]*$', {
    param($match)
    $rewrites++
    $match.Groups[1].Value + 'image: ' + $Image
})
if ($rewrites -ne 2 -or $manifest -notmatch [regex]::Escape("image: $Image")) {
    throw 'Rendered manifests did not contain the requested Phots image; refusing to apply.'
}
$manifest | kubectl apply -f -
if ($LASTEXITCODE -ne 0) { throw 'Kubernetes resource apply failed.' }
Write-Output "Applied Phots scan and stream resources using image $Image."
