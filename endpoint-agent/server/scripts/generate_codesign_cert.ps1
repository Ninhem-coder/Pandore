<#
.SYNOPSIS
    Génère un certificat de signature de code auto-signé pour signer EndpointAgent.msi
    (jalon 5, étape 13) — à lancer UNE SEULE FOIS, depuis une session PowerShell normale
    (pas besoin d'admin : New-SelfSignedCertificate écrit dans Cert:\CurrentUser\My).

.DESCRIPTION
    Même esprit que generate_ca.py (CA mTLS du jalon 3) : un certificat auto-signé plutôt qu'un
    certificat acheté auprès d'une autorité publique — suffisant pour un projet personnel où
    c'est Nicolas lui-même qui distribue le certificat public aux postes cibles (import dans
    Cert:\LocalMachine\TrustedPublisher, voir README). Contrairement à la CA mTLS, ce n'est PAS
    une CA (pas de `-Type CA`/`ca=true`) : un simple certificat "Code Signing" auto-signé, qui
    se suffit à lui-même une fois son certificat PUBLIC posé dans TrustedPublisher sur chaque
    poste — Windows n'a pas besoin de faire confiance à un "émetteur" séparé pour de la
    signature Authenticode, seulement au certificat de signature lui-même.

    RSA plutôt qu'EC (contrairement à ca.py) : c'est le type de clé le plus largement supporté
    par signtool/Authenticode/SmartScreen sur tout le parc de versions Windows visées ici, pas
    de raison de prendre un risque de compatibilité pour ce cas d'usage précis.

    Le PFX (clé privée + certificat) est protégé par un mot de passe demandé de façon SÉCURISÉE
    (Read-Host -AsSecureString, jamais en clair sur la ligne de commande/dans ce script) et
    écrit sous endpoint-agent/server/data/codesign/ — déjà gitignoré en bloc
    (`endpoint-agent/server/data/`, voir .gitignore), même traitement que ca-key.pem
    (CA_KEY_PASSPHRASE) : un secret local à la machine, jamais committé.

    Le certificat PUBLIC (.cer, sans clé privée) est exporté à part : c'est LUI qu'il faut
    importer dans `Cert:\LocalMachine\TrustedPublisher` sur chaque poste cible pour que le MSI
    signé s'installe sans avertissement Windows (voir README pour la procédure Intune/manuelle).

.PARAMETER Force
    Regénère même si un certificat/PFX existe déjà (invalide la confiance déjà déployée sur
    les postes ayant importé l'ancien certificat public — mêmes conséquences qu'un
    `generate_ca.py --force`, à ne faire qu'en connaissance de cause).

.EXAMPLE
    cd endpoint-agent/server
    ./scripts/generate_codesign_cert.ps1
#>
param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$dataDir = Join-Path $PSScriptRoot "..\data\codesign" | Resolve-Path -ErrorAction SilentlyContinue
if (-not $dataDir) {
    $dataDir = New-Item -ItemType Directory -Force -Path (Join-Path $PSScriptRoot "..\data\codesign")
}
$pfxPath = Join-Path $dataDir "codesign.pfx"
$cerPath = Join-Path $dataDir "codesign.cer"

if ((Test-Path $pfxPath) -and (-not $Force)) {
    Write-Host "Un certificat existe déjà ($pfxPath). Relancer avec -Force pour le remplacer (invalide la confiance déjà déployée sur les postes cibles)."
    exit 1
}

$subject = "CN=Ninhem-coder - Endpoint Agent Code Signing"
Write-Host "Génération du certificat de signature de code auto-signé ($subject)..."

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $subject `
    -KeyAlgorithm RSA `
    -KeyLength 4096 `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddYears(5) `
    -CertStoreLocation "Cert:\CurrentUser\My"

Write-Host "Certificat créé (empreinte $($cert.Thumbprint)). Mot de passe du PFX :"
$pfxPassword = Read-Host -AsSecureString "Mot de passe pour protéger codesign.pfx"

Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPassword | Out-Null
Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null

# Retiré du magasin utilisateur une fois exporté : seul le PFX (protégé par mot de passe) fait
# foi désormais, pas la peine de laisser une 2e copie de la clé privée traîner dans
# Cert:\CurrentUser\My sur ce poste de build.
Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force

Write-Host ""
Write-Host "Terminé :"
Write-Host " - $pfxPath (clé privée + certificat, protégé par mot de passe — JAMAIS committé, gitignoré)"
Write-Host " - $cerPath (certificat public SEUL — à importer dans Cert:\LocalMachine\TrustedPublisher sur chaque poste cible, voir README)"
Write-Host ""
Write-Host "Pour signer le MSI (endpoint-agent/agent/Installer/) :"
Write-Host "  & 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe' sign /f `"$pfxPath`" /p <mot-de-passe> /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 EndpointAgent.msi"
