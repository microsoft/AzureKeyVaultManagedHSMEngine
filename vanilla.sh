echo ---------------- Rebuilding e_akv engine
cd src/build 
cmake ..
make

echo ---------------- stopping nginx
sudo /etc/init.d/nginx stop

echo ---------------- Copying e_akv engine
ENGINESDIR=`openssl version -a | grep ENGINESDIR | awk '{print $2}' | tr -d '"'`
sudo cp e_akv.so $ENGINESDIR/e_akv.so

echo ---------------- Copying configs
cd ~/repos/AzureKeyVaultManagedHSMEngine/samples/nginx
sudo cp nginx.conf /etc/nginx/nginx.conf
sudo cp default /etc/nginx/sites-available/default
sudo cp default /etc/nginx/sites-enabled/default
#sudo sed -i "s/KEYVAULTNAME/t-cbrugal-kv/g" /etc/nginx/sites-available/default

echo ---------------- copying certs
sudo cp azurefd-test.net.crt /etc/ssl/certs/azurefd-test.net.crt

echo ---------------- Testing e_akv engine
openssl engine -vvv -t e_akv

echo ---------------- restarting nginx
sudo /etc/init.d/nginx restart


#curl -k https://localhost:443 -v
echo ---------------- testing nginx with KV cert
echo -n | openssl s_client -connect 127.0.0.1:443 -servername azurefd-test.net -tls1_2 -showcerts


echo log file is at /var/log/nginx/akv_error.log