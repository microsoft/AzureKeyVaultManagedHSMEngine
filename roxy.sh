echo ---------------- Rebuilding e_akv engine
cd src/build 
cmake ..
make

echo ---------------- Copying e_akv engine
ENGINESDIR=`openssl version -a | grep ENGINESDIR | awk '{print $2}' | tr -d '"'`
sudo cp e_akv.so $ENGINESDIR/e_akv.so

echo ---------------- Testing e_akv engine
openssl engine -vvv -t e_akv