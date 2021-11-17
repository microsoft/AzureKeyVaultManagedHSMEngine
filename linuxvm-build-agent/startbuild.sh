
sudo apt install -y build-essential   libssl-dev   libcurl4-openssl-dev   libjson-c-dev   cmake   nginx
cd /opt
git clone https://github.com/microsoft/AzureKeyVaultManagedHSMEngine.git
cd AzureKeyVaultManagedHSMEngine/src
mkdir build
cd build
cmake ..
make
openssl version -a | grep ENGINESDIR
sudo cp e_akv.so /usr/lib/x86_64-linux-gnu/engines-1.1/e_akv.so
openssl engine -vvv -t e_akv
cp ../../samples/nginx/openssl.cnf .
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login --identity --allow-no-subscriptions
az keyvault key create --vault-name $1 --name testrsakey --kty RSA --size 2048
openssl req -new -x509 -config openssl.cnf -engine e_akv -keyform engine -key vault:$1:testrsakey -out cert.pem
sudo cp cert.pem /etc/ssl/certs/contoso_rsa_cert.cer
sudo cp ../../samples/nginx/nginx.conf /etc/nginx/nginx.conf
sudo cp ../../samples/nginx/default /etc/nginx/sites-available/default
sudo sed -i "s/KEYVAULTNAME/$1/g" /etc/nginx/sites-available/default
sudo /etc/init.d/nginx restart
curl -k https://localhost:443 -vv