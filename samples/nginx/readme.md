Using Azure Key Vault and Managed HSM engine for nginx

1. Install build-essential and nginx etc

   `sudo apt install -y build-essential   libssl-dev   libcurl4-openssl-dev   libjson-c-dev   cmake   nginx`
   
2. Build Azure Key Vault and Managed HSM engine

3. Install the engine shared object to openssl engine folder
   The command `openssl version -a | grep ENGINESDIR` will show the engine folder. 

   For example, if the folder is `/usr/lib/x86_64-linux-gnu/engines-1.1`  
   
   Then run the following command  
   
    `sudo cp e_akv.so /usr/lib/x86_64-linux-gnu/engines-1.1/e_akv.so`

4. Install Azure cli

   `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash`

5. Create an RSA private key 'testrsakey' in Azure Key Vault. Remember to replace the `<keyvalut name>` with your real Azure key vault

    `az login --identity --allow-no-subscriptions`
    
    `az keyvault key create --vault-name <keyvalut name> --name testrsakey --kty RSA --size 2048`

6. Create a self-signed certificate to be used by nginx
    
    `openssl req -new -x509 -config openssl.cnf -engine e_akv -keyform engine -key vault:$1:testrsakey -out cert.pem`
    
    `sudo cp cert.pem /etc/ssl/certs/contoso_rsa_cert.cer`

7. Modify nginx to use the engine. Remember to replace the `<keyvalut name>` with your real Azure key vault.

   The real change is to add "ssl_engine e_akv;" line to nginx.conf and the following changes in default file
   ```
     ssl on;
     ssl_certificate /etc/ssl/certs/contoso_rsa_cert.cer;
     ssl_certificate_key "engine:e_akv:vault:KEYVAULTNAME:testrsakey";
   ```

    `sudo cp nginx.conf /etc/nginx/nginx.conf`

    `sudo cp default /etc/nginx/sites-available/default`
    
    `sudo sed -i "s/KEYVAULTNAME/<keyvault name>/g" /etc/nginx/sites-available/default`

7. Restart nginx and test with Curl

    `sudo /etc/init.d/nginx restart`
    
    `curl -k https://localhost:443 -vv`
