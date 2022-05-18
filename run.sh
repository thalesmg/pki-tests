#!/usr/bin/env bash

set -xeuo pipefail

ROOT_DIR="$(cd "$(dirname "$(readlink "$0" || echo "$0")")"; pwd -P)"

cd "$ROOT_DIR"

#################################################
# Generate root CA
#################################################

figlet Generating root CA

mkdir -p certs crl newcerts private
# chmod 700 private
touch index.txt
echo 1000 > serial

# openssl genrsa -aes256 -out private/ca.key.pem 4096
openssl genrsa -out private/ca.key.pem 4096
# chmod 400 private/ca.key.pem

CA_C="${TLS_DN_C:-SE}"
CA_ST="${TLS_DN_ST:-Stockholm}"
CA_L="${TLS_DN_L:-Stockholm}"
CA_O="${TLS_DN_O:-MyOrgName}"
CA_OU="${TLS_DN_OU:-MyRootCA}"
CA_CN="MyRootCA"

openssl req -config openssl.cnf \
        -key private/ca.key.pem \
        -subj "/C=${CA_C}/ST=${CA_ST}/L=${CA_L}/O=${CA_O}/OU=${CA_OU}/CN=${CA_CN}" \
        -new -x509 -days 7300 -sha256 -extensions v3_ca \
        -out certs/ca.cert.pem
# chmod 444 certs/ca.cert.pem

openssl x509 -noout -text -in certs/ca.cert.pem

#################################################
# Generate intermediate
#################################################

figlet Generating intermediate CA

mkdir -p intermediate

pushd intermediate
mkdir -p certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber
popd

# openssl genrsa -aes256 \
#         -out intermediate/private/intermediate.key.pem 4096
openssl genrsa \
        -out intermediate/private/intermediate.key.pem 4096
# chmod 400 intermediate/private/intermediate.key.pem

CA_C="${TLS_DN_C:-SE}"
CA_ST="${TLS_DN_ST:-Stockholm}"
CA_L="${TLS_DN_L:-Stockholm}"
CA_O="${TLS_DN_O:-MyOrgName}"
CA_OU="${TLS_DN_OU:-MyIntermediateCA}"
CA_CN="MyIntermediateCA"

openssl req -config intermediate/openssl.cnf -new -sha256 \
        -subj "/C=${CA_C}/ST=${CA_ST}/L=${CA_L}/O=${CA_O}/OU=${CA_OU}/CN=${CA_CN}" \
        -key intermediate/private/intermediate.key.pem \
        -out intermediate/csr/intermediate.csr.pem

openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
        -batch \
        -days 3650 -notext -md sha256 \
        -in intermediate/csr/intermediate.csr.pem \
        -out intermediate/certs/intermediate.cert.pem
# chmod 444 intermediate/certs/intermediate.cert.pem

openssl x509 -noout -text \
        -in intermediate/certs/intermediate.cert.pem

openssl verify -CAfile certs/ca.cert.pem \
        intermediate/certs/intermediate.cert.pem

cat intermediate/certs/intermediate.cert.pem \
    certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem
# chmod 444 intermediate/certs/ca-chain.cert.pem

#################################################
# Generate server cert
#################################################

figlet Generating server cert

#  -aes256
openssl genrsa \
        -out intermediate/private/server.key.pem 2048
# chmod 400 intermediate/private/server.key.pem

CA_C="${TLS_DN_C:-SE}"
CA_ST="${TLS_DN_ST:-Stockholm}"
CA_L="${TLS_DN_L:-Stockholm}"
CA_O="${TLS_DN_O:-MyOrgName}"
CA_OU="${TLS_DN_OU:-MyIntermediateCA}"
CA_CN="MyServer"

openssl req -config intermediate/openssl.cnf \
        -subj "/C=${CA_C}/ST=${CA_ST}/L=${CA_L}/O=${CA_O}/OU=${CA_OU}/CN=${CA_CN}" \
        -key intermediate/private/server.key.pem \
        -new -sha256 -out intermediate/csr/server.csr.pem

openssl ca -config intermediate/openssl.cnf \
        -batch \
        -extensions server_cert -days 375 -notext -md sha256 \
        -in intermediate/csr/server.csr.pem \
        -out intermediate/certs/server.cert.pem
# chmod 444 intermediate/certs/server.cert.pem

openssl x509 -noout -text \
        -in intermediate/certs/server.cert.pem

openssl verify -CAfile intermediate/certs/ca-chain.cert.pem \
        intermediate/certs/server.cert.pem

#################################################
# Generate client cert
#################################################

figlet Generating client cert

#  -aes256
openssl genrsa \
        -out intermediate/private/client.key.pem 2048
# chmod 400 intermediate/private/client.key.pem

CA_C="${TLS_DN_C:-SE}"
CA_ST="${TLS_DN_ST:-Stockholm}"
CA_L="${TLS_DN_L:-Stockholm}"
CA_O="${TLS_DN_O:-MyOrgName}"
CA_OU="${TLS_DN_OU:-MyIntermediateCA}"
CA_CN="MyClient"

openssl req -config intermediate/openssl.cnf \
        -subj "/C=${CA_C}/ST=${CA_ST}/L=${CA_L}/O=${CA_O}/OU=${CA_OU}/CN=${CA_CN}" \
        -key intermediate/private/client.key.pem \
        -new -sha256 -out intermediate/csr/client.csr.pem

openssl ca -config intermediate/openssl.cnf \
        -batch \
        -extensions usr_cert -days 375 -notext -md sha256 \
        -in intermediate/csr/client.csr.pem \
        -out intermediate/certs/client.cert.pem
# chmod 444 intermediate/certs/client.cert.pem

openssl x509 -noout -text \
        -in intermediate/certs/client.cert.pem

openssl verify -CAfile intermediate/certs/ca-chain.cert.pem \
        intermediate/certs/client.cert.pem

#################################################
# Generate CRLs
#################################################

figlet Generating CRLs

openssl ca -config intermediate/openssl.cnf \
        -gencrl -out intermediate/crl/intermediate.crl.pem

openssl crl -in intermediate/crl/intermediate.crl.pem -noout -text