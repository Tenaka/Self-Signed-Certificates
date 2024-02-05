#https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate?view=windowsserver2022-ps
#KeyExportPolicy NonExportable, ExportableEncrypted, Exportable 
<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
          Declare Variables for Cert and Directories
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
$certExport = "C:\_Certs\"
$ScriptRepo = "C:\_PSScripts\"

$params = @{
    Subject = 'Self Signed PS Code Signing'
    DnsName = 'Self@Tenaka.net'
    FriendlyName = 'Self Signed PS Code Signing'
    NotAfter = (Get-Date).AddYears(5)
    Type = 'CodeSigning'  
    CertStoreLocation = 'cert:\CurrentUser\My' 
    KeyUsage = 'DigitalSignature'
    KeyAlgorithm = 'RSA'
    KeyLength = 2048         #2048, 4096
    HashAlgorithm = 'sha256' #sha1, sha256, sha512
    }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                      Create Direcotries
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
#Create directories for exporting cert and a place for scripts to be signed
try { Get-ChildItem $certExport -ErrorAction Stop } catch { New-Item -Path $certExport -Force -ItemType Directory }
try { Get-ChildItem $ScriptRepo -ErrorAction Stop } catch { New-Item -Path $ScriptRepo -Force -ItemType Directory }

$gtPSscripts =  Get-ChildItem -Path $ScriptRepo -filter *.ps1
if ($gtPSscripts -eq $null)
    {
            Write-Host "Don't get ahead of yourself, $ScriptRepo requires PowerShell script to sign before proceeding" -ForegroundColor Red
        Pause
    }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
               Creates New Self Signed Certificate
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
New-SelfSignedCertificate @params -OutVariable newCodeSigningCert

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
        Export Self Signed and Import into Trusted Root
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
#Do this to prevent Set-authenticode from displaying an error
Export-Certificate -Cert "cert:\CurrentUser\My\$($newCodeSigningCert.Thumbprint)" -FilePath "$($certExport)\CodeSigning.cer"
Import-Certificate -FilePath "$($certExport)\CodeSigning.cer" -Cert Cert:\LocalMachine\root

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
      Process C:\_PSScritps and Sign any PowerShell Scripts
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
#Code sign script with new certifcate
$gtPSscripts =  Get-ChildItem -Path $ScriptRepo -filter *.ps1 -Recurse -Force
foreach ($PSscriptItem in $gtPSscripts)
    {
        try
            {   
                #Sign the scirpt         
                Set-AuthenticodeSignature $PSscriptItem.fullname -Certificate (Get-ChildItem "cert:\CurrentUser\My\$($newCodeSigningCert.Thumbprint)" -CodeSigningCert -ErrorAction Stop)
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                    Write-Warning $exceptionMessage
            }

        #Confirm each script is signed
        $gtAuthent = Get-AuthenticodeSignature $PSscriptItem.fullname
        if ($gtAuthent.Status -ne "valid")
            {
                    Write-Warning "$PSscriptItem isn't Signed"
                Add-Content -Path "$($ScriptRepo)\error.log" -Value "$($PSscriptItem.fullname) $($gtAuthent.status)" 
            }
    }


#Remove double hashes (##) if required

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                Import Certificate on Clients 
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
#Copy over the .cer and import into Trusted Root of any client that will execute the signed scripts
#Copy over signed scripts
#Powershell Script execution to Signed only in Group Policy

##Import-Certificate -FilePath "$($certExport)\CodeSigning.cer" -Cert Cert:\LocalMachine\root


<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
            WARNING - Export Private Key to Keep it Safe
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
#Export with Private to backup - to remove private key from network access - take offline - keep it safe
#Do not export to any client or network accessible share

##$CertPassword = ConvertTo-SecureString -String "ChangeME1234" -Force -AsPlainText
##Export-PfxCertificate -Cert "cert:\CurrentUser\My\$($newCodeSigningCert.Thumbprint)" -FilePath "$($certExport)\selfsigncert.pfx" -Password $CertPassword 

#To Re-Import
##Import-PfxCertificate -FilePath "$($certExport)\elfsigncert.pfx" -Cert Cert:\LocalMachine\root -Password $CertPassword


