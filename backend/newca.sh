#for explanations please see https://jamielinux.com/docs/openssl-certificate-authority/online-certificate-status-protocol.html

mkdir ca
cp openssl_root.cnf ca
cp openssl_intermediate.cnf ca
cd ca

mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

openssl genrsa -aes256 -out private/ca.key.pem 4096
chmod 400 private/ca.key.pem
openssl req -config openssl_root.cnf \
     -key private/ca.key.pem \
     -new -x509 -days 7300 -sha256 -extensions v3_ca \
     -out certs/ca.cert.pem
chmod 444 certs/ca.cert.pem

openssl x509 -noout -text -in certs/ca.cert.pem


mkdir intermediate
mkdir intermediate/certs intermediate/crl intermediate/csr intermediate/newcerts intermediate/private
chmod 700 intermediate/private
touch intermediate/index.txt
echo 1000 > intermediate/serial
echo 1000 > intermediate/crlnumber

openssl genrsa -aes256 -out intermediate/private/intermediate.key.pem 4096
chmod 400 intermediate/private/intermediate.key.pem
openssl req -config openssl_intermediate.cnf -new -sha256 -key intermediate/private/intermediate.key.pem -out intermediate/csr/intermediate.csr.pem
openssl ca -config openssl_root.cnf -extensions v3_intermediate_ca  -days 3650 -notext -md sha256 -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem
chmod 444 intermediate/certs/intermediate.cert.pem
openssl x509 -noout -text -in intermediate/certs/intermediate.cert.pem

openssl verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate.cert.pem
cat intermediate/certs/intermediate.cert.pem certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem

openssl ca -config openssl_intermediate.cnf -gencrl -out intermediate/crl/intermediate.crl.pem
openssl crl -in intermediate/crl/intermediate.crl.pem -noout -text

#openssl genrsa -aes256 -out ca-key.pem 2048
#openssl req -x509 -new -nodes -extensions v3_ca -key ca-key.pem -days 1024 -out ca-root.pem -sha512

