# X509CertificateCryptor
A Powershell script to encrypt and decrypt files in a folder using x509 public certificate to encrypt and private key to decrypt files
You need to make your own x509 keypair (best choice for me seems openSSL).

Use the following command to generate keypair: 

openssl req -x509 -newkey rsa:4096 -keyout private.key -out public.cert -days 365

Then sign the public key with your private key and use the resulting certificate for decryption:

openssl pkcs12 -export -inkey private.key -in public.cert -out certificate.pem

Specify script to the path you want to encrypt/decrypt.

The original script was written by Ryan Ries - ryan@myotherpcisacloud.com

I just extend it to work with a chosen folder.

read about x509 => http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509certificate2.aspx


