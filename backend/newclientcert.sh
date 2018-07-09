openssl genrsa -out MyClient1.key 2048
openssl req -new -key MyClient1.key -out MyClient1.csr

openssl x509 -req -in MyClient1.csr -CA ca-root.pem -CAkey ca-key.pem -CAcreateserial -out MyClient1.pem -days 1024 -sha256


