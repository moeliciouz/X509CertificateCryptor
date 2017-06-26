#
<#
.SYNOPSIS
This Powershell function decrypts a file using a given X.509 certificate private key.
.DESCRIPTION
This Powershell function decrypts a file using a given X.509 certificate private key.
This function accepts as inputs a file to decrypt and a certificate with which to decrypt it.
The file can only be decrypted with the private key of the certificate that was used to encrypt it.
.PARAMETER FileToDecrypt
Must be a System.IO.FileInfo object. $(Get-ChildItem C:\file.txt) will work.
.PARAMETER Cert
Must be a System.Security.Cryptography.X509Certificates.X509Certificate2 object. $(Get-ChildItem Cert:\CurrentUser\My\9554F368FEA619A655A1D49408FC13C3E0D60E11) will work. The public key of the certificate is used for encryption. The private key is used for decryption.
.EXAMPLE
PS C:\> . .\Decrypt-File.ps1
PS C:\> Decrypt-File $File $Cert
.EXAMPLE
PS C:\> . .\Decrypt-File.ps1
PS C:\> Decrypt-File $(Get-ChildItem C:\foo.txt) $(Get-ChildItem Cert:\CurrentUser\My\THUMBPRINT)
.INPUTS
Decrypt-File <System.IO.FileInfo> <System.Security.Cryptography.X509Certificates.X509Certificate2>
.OUTPUTS
An unencrypted file.
.NOTES
Written by Ryan Ries - ryan@myotherpcisacloud.com
.LINK
http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509certificate2.aspx
#>
 
Function Decrypt-File
{
    Param([Parameter(mandatory=$true)][System.IO.FileInfo]$FileToDecrypt,
          [Parameter(mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
 
    Try { [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Cryptography") }
    Catch { Write-Error "Could not load required assembly."; Return }
     
    $AesProvider                = New-Object System.Security.Cryptography.AesManaged
    $AesProvider.KeySize        = 256
    $AesProvider.BlockSize      = 128
    $AesProvider.Mode           = [System.Security.Cryptography.CipherMode]::CBC
    [Byte[]]$LenKey             = New-Object Byte[] 4
    [Byte[]]$LenIV              = New-Object Byte[] 4
    If($FileToDecrypt.Name.Split(".")[-1] -ne "encrypted")
    {
        Write-Error "The file to decrypt must be named *.encrypted."
        Return
    }
    If($Cert.HasPrivateKey -eq $False -or $Cert.PrivateKey -eq $null)
    {
        Write-Error "The supplied certificate does not contain a private key, or it could not be accessed."
        Return
    }
    Try { $FileStreamReader = New-Object System.IO.FileStream("$($FileToDecrypt.FullName)", [System.IO.FileMode]::Open) }
    Catch
    {
        Write-Error "Unable to open input file for reading."       
        Return
    }  
    $FileStreamReader.Seek(0, [System.IO.SeekOrigin]::Begin)         | Out-Null
    $FileStreamReader.Seek(0, [System.IO.SeekOrigin]::Begin)         | Out-Null
    $FileStreamReader.Read($LenKey, 0, 3)                            | Out-Null
    $FileStreamReader.Seek(4, [System.IO.SeekOrigin]::Begin)         | Out-Null
    $FileStreamReader.Read($LenIV,  0, 3)                            | Out-Null
    [Int]$LKey            = [System.BitConverter]::ToInt32($LenKey, 0)
    [Int]$LIV             = [System.BitConverter]::ToInt32($LenIV,  0)
    [Int]$StartC          = $LKey + $LIV + 8
    [Int]$LenC            = [Int]$FileStreamReader.Length - $StartC
    [Byte[]]$KeyEncrypted = New-Object Byte[] $LKey
    [Byte[]]$IV           = New-Object Byte[] $LIV
    $FileStreamReader.Seek(8, [System.IO.SeekOrigin]::Begin)         | Out-Null
    $FileStreamReader.Read($KeyEncrypted, 0, $LKey)                  | Out-Null
    $FileStreamReader.Seek(8 + $LKey, [System.IO.SeekOrigin]::Begin) | Out-Null
    $FileStreamReader.Read($IV, 0, $LIV)                             | Out-Null
    [Byte[]]$KeyDecrypted = $Cert.PrivateKey.Decrypt($KeyEncrypted, $false)
    $Transform = $AesProvider.CreateDecryptor($KeyDecrypted, $IV)
    Try { $FileStreamWriter = New-Object System.IO.FileStream("$($FileToDecrypt.Directory)\$($FileToDecrypt.Name.Replace(".encrypted",$null))", [System.IO.FileMode]::Create) }
    Catch
    {
        Write-Error "Unable to open output file for writing.`n$($_.Message)"
        $FileStreamReader.Close()
        Return
    }
    [Int]$Count  = 0
    [Int]$Offset = 0
    [Int]$BlockSizeBytes = $AesProvider.BlockSize / 8
    [Byte[]]$Data = New-Object Byte[] $BlockSizeBytes
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
    Do
    {
        $Count   = $FileStreamReader.Read($Data, 0, $BlockSizeBytes)
        $Offset += $Count
        $CryptoStream.Write($Data, 0, $Count)
    }
    While ($Count -gt 0)
    $CryptoStream.FlushFinalBlock()
    $CryptoStream.Close()
    $FileStreamWriter.Close()
    $FileStreamReader.Close()
}

foreach( $FileToDecrypt in Get-ChildItem )
{
Decrypt-File
}
