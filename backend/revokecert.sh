cn="$1"
cd ca
openssl ca -config openssl_intermediate.cnf -revoke intermediate/certs/${cn}.cert.pem
openssl ca -config openssl_intermediate.cnf -gencrl -out intermediate/crl/intermediate.crl.pem
openssl crl -in intermediate/crl/intermediate.crl.pem -noout -text

