# Using ECC key in Managed HSM for nginx

NOTE: This example shows how to use ECC key in Managed HSM for nginx. The prefix will be "managedHsm", for example
   `managedHsm:<Hsm Name>:testecckey`

## Steps:
1. Create and activate an Managed HSM
2. Create an Azure Linux VM and assign managed identity to the Azure Linux VM
3. Create role assignment to allow Azure Linux VM to access keys in Managed HSM
4. Build Azure Key Vault and Managed HSM engine on the Azure Linux VM
5. On the Azure Linux VM, create an self-signed cert for the nginx. Test nginx with curl.


## Create and activate an Managed HSM, also create an ECC key in it
1. Prepare your subscription
```
   az login
   az account set --subscription <your subscription>
   az group create --name "ContosoResourceGroup" --location westus3
```

2. Get the Managed HSM adminstrator ID and use it in the Managed HSM creation (remember to replace [HSM NAME] with your real HSM name and actual 'xxxx' value)
```
   az ad signed-in-user show --query objectId -o tsv
      xxxx

   az keyvault create --hsm-name "[HSM NAME]" --resource-group "ContosoResourceGroup" --location "West US 3" --administrators xxxx --retention-days 28
```

3. Activate the newly created Managed HSM (remember to replace [HSM NAME] with your real HSM name)
```
   openssl req -newkey rsa:2048 -nodes -keyout cert_1.key -x509 -days 365 -out cert_1.cer -config openssl.cnf
   openssl req -newkey rsa:2048 -nodes -keyout cert_2.key -x509 -days 365 -out cert_2.cer -config openssl.cnf
   openssl req -newkey rsa:2048 -nodes -keyout cert_3.key -x509 -days 365 -out cert_3.cer -config openssl.cnf
   az keyvault security-domain download --hsm-name "[HSM NAME]" --sd-wrapping-keys ./cert_1.cer ./cert_2.cer ./cert_3.cer --sd-quorum 2 --security-domain-file SD.json
```

4. Create an ECC key in the HSM (remember to replace [HSM NAME] with your real HSM name)
```
   az keyvault key create --curve p-256 --kty EC-HSM --name testecckey --hsm-name [HSM NAME] --ops sign
```

## Prepare an Azure Linux VM
1. In your subscription, create an Azure Linux VM "hsmlinux" with ubuntu 20. For example, 
```
   azureuser@hsmlinux:~/$ uname -a
   Linux hsmlinux 5.11.0-1021-azure #22~20.04.1-Ubuntu SMP Fri Oct 29 01:11:25 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```

2. Create managed identity to the Azure Linux VM
```
   az vm identity assign --name hsmlinux --resource-group contosoresourcegroup
   az vm identity show --name "hsmlinux" --resource-group "contosoresourcegroup" --query principalId -o tsv
      yyyy
```   

3. Create role assignment to allow the Azure Linux VM to access keys in Managed HSM (remember to replace [HSM NAME] with your real HSM name and the actual 'yyyy')
```
   az keyvault role assignment create  --hsm-name [HSM NAME] --assignee yyyy  --scope / --role "Managed HSM Crypto User"
```

## Build and Test the engine on the Azure Linux VM 
After logon to your Azure Linux VM

1. Install build-essential and nginx etc
```
   sudo apt install -y build-essential   libssl-dev   libcurl4-openssl-dev   libjson-c-dev   cmake   nginx
```   

2. Build Azure Key Vault and Managed HSM engine
```
   cd ~
   git clone https://github.com/microsoft/AzureKeyVaultManagedHSMEngine.git
   cd AzureKeyVaultManagedHSMEngine/src
   mkdir build
   cd build
   cmake ..
   make
```

3. Install the engine shared object to openssl engine folder

   The command `openssl version -a | grep ENGINESDIR` will show the engine folder. 

   For example, if the folder is `/usr/lib/x86_64-linux-gnu/engines-1.1`  
   
   Then run the following command  
   
    `sudo cp e_akv.so /usr/lib/x86_64-linux-gnu/engines-1.1/e_akv.so`

4. Create a self-signed certificate to be used by nginx (remember to replace [HSM NAME] with your real HSM name)
```
   cd ~/AzureKeyVaultManagedHSMEngine/samples/nginx-managedHsm
   openssl req -new -x509 -config openssl.cnf -engine e_akv -keyform engine -key managedHsm:[HSM NAME]:testecckey -out certecc.pem
   sudo cp certecc.pem /etc/ssl/certs/contoso_rsa_cert.cer`
```

5. Modify nginx to use the engine. Remember to replace the [HSM NAME] with your real HSM name.

   The real change is to add "ssl_engine e_akv;" line to nginx.conf and the following changes in nginx 'default' file
```
     ssl on;
     ssl_certificate /etc/ssl/certs/contoso_rsa_cert.cer;
     ssl_certificate_key "engine:e_akv:managedHsm:KEYVAULTNAME:testecckey";
```

6. Now copy the files and remember to replace [HSM NAME] with your real HSM name in default file
```
   sudo cp nginx.conf /etc/nginx/nginx.conf
   sudo cp default /etc/nginx/sites-available/default 
   sudo sed -i "s/KEYVAULTNAME/[HSM NAME]/g" /etc/nginx/sites-available/default
```

7. Restart nginx and test with Curl
```
   sudo /etc/init.d/nginx restart
   curl -k https://localhost:443 -vv
```

8. You should see something like below
```
   $ curl -k https://localhost:443 -vv
   *   Trying 127.0.0.1:443...
   * TCP_NODELAY set
   * Connected to localhost (127.0.0.1) port 443 (#0)
   * ALPN, offering h2
   * ALPN, offering http/1.1
   * successfully set certificate verify locations:
   *   CAfile: /etc/ssl/certs/ca-certificates.crt
   CApath: /etc/ssl/certs
   * TLSv1.3 (OUT), TLS handshake, Client hello (1):
   * TLSv1.3 (IN), TLS handshake, Server hello (2):
   * TLSv1.2 (IN), TLS handshake, Certificate (11):
   * TLSv1.2 (IN), TLS handshake, Server key exchange (12):
   * TLSv1.2 (IN), TLS handshake, Server finished (14):
   * TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
   * TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
   * TLSv1.2 (OUT), TLS handshake, Finished (20):
   * TLSv1.2 (IN), TLS handshake, Finished (20):
   * SSL connection using TLSv1.2 / ECDHE-ECDSA-AES256-GCM-SHA384
   * ALPN, server accepted to use http/1.1
   * Server certificate:
   *  subject: C=US; ST=WA; L=Redmond; O=Contoso; OU=AKV; CN=www.Contoso.com
   *  start date: Dec  2 05:37:14 2021 GMT
   *  expire date: Jan  1 05:37:14 2022 GMT
   *  issuer: C=US; ST=WA; L=Redmond; O=Contoso; OU=AKV; CN=www.Contoso.com
   *  SSL certificate verify result: self signed certificate (18), continuing anyway.
   > GET / HTTP/1.1
   > Host: localhost
   > User-Agent: curl/7.68.0
   > Accept: */*
   >
   * Mark bundle as not supporting multiuse
   < HTTP/1.1 200 OK
   < Server: nginx/1.18.0 (Ubuntu)
   < Date: Thu, 02 Dec 2021 06:28:40 GMT
   < Content-Type: text/html
   < Content-Length: 612
   < Last-Modified: Thu, 28 Oct 2021 03:11:13 GMT
   < Connection: keep-alive
   < ETag: "617a14d1-264"
   < Accept-Ranges: bytes
   <
   <!DOCTYPE html>
   <html>
   <head>
   <title>Welcome to nginx!</title>
   <style>
      body {
         width: 35em;
         margin: 0 auto;
         font-family: Tahoma, Verdana, Arial, sans-serif;
      }
   </style>
   </head>
   <body>
   <h1>Welcome to nginx!</h1>
   <p>If you see this page, the nginx web server is successfully installed and
   working. Further configuration is required.</p>

   <p>For online documentation and support please refer to
   <a href="http://nginx.org/">nginx.org</a>.<br/>
   Commercial support is available at
   <a href="http://nginx.com/">nginx.com</a>.</p>

   <p><em>Thank you for using nginx.</em></p>
   </body>
   </html>
   * Connection #0 to host localhost left intact
```
