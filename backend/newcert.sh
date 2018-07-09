mode="$1" #server_cert or usr_cert
cn="$2"
cd ca
openssl genrsa -aes256 -out intermediate/private/${cn}.key.pem 2048
chmod 400 intermediate/private/${cn}.key.pem
openssl req -config openssl_intermediate.cnf -key intermediate/private/${cn}.key.pem -new -sha256 -out intermediate/csr/${cn}.csr.pem
openssl ca  -config openssl_intermediate.cnf -extensions $mode -days 375 -notext -md sha256 -in intermediate/csr/${cn}.csr.pem -out intermediate/certs/${cn}.cert.pem
chmod 444 intermediate/certs/www.example.com.cert.pem
openssl x509 -noout -text -in intermediate/certs/${cn}.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem intermediate/certs/${cn}.cert.pem


