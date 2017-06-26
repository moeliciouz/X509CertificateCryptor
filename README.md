# X509CertificateCryptor
A Powershell script to encrypt and decrypt files in a folder using x509 public certificate to encrypt and private key to decrypt files
You need to make your own x509 keypair (best choice for me seems openSSL).

Use the following command to generate: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

Specify script to the path you want to encrypt/decrypt.

The original script was written by Ryan Ries - ryan@myotherpcisacloud.com

I just gonna extend it to more files within a folder and a range of file extensions

read about x509 => http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509certificate2.aspx


