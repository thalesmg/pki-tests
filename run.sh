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
CA_CN="localhost"

openssl req -config intermediate/openssl.cnf \
        -subj "/C=${CA_C}/ST=${CA_ST}/L=${CA_L}/O=${CA_O}/OU=${CA_OU}/CN=${CA_CN}" \
        -key intermediate/private/server.key.pem \
        -new -sha256 -out intermediate/csr/server.csr.pem

openssl ca -config intermediate/openssl.cnf \
        -batch \
        -extensions server_cert -days 3750 -notext -md sha256 \
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
        -extensions usr_cert -days 3750 -notext -md sha256 \
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

openssl genrsa -out intermediate/private/client-revoked.key.pem 2048

CA_C="${TLS_DN_C:-SE}"
CA_ST="${TLS_DN_ST:-Stockholm}"
CA_L="${TLS_DN_L:-Stockholm}"
CA_O="${TLS_DN_O:-MyOrgName}"
CA_OU="${TLS_DN_OU:-MyIntermediateCA}"
CA_CN="client-revoked"

openssl req -new -key intermediate/private/client-revoked.key.pem \
        -subj "/C=${CA_C}/ST=${CA_ST}/L=${CA_L}/O=${CA_O}/OU=${CA_OU}/CN=${CA_CN}" \
        -out intermediate/csr/client-revoked.csr.pem

openssl ca -batch -config intermediate/openssl.cnf \
        -extensions usr_cert -notext -md sha256 \
        -in intermediate/csr/client-revoked.csr.pem \
        -out intermediate/certs/client-revoked.cert.pem

openssl ca -config intermediate/openssl.cnf \
        -revoke intermediate/certs/client-revoked.cert.pem

# re-create the CRL!

openssl ca -config intermediate/openssl.cnf \
        -gencrl -out intermediate/crl/intermediate-revoked.crl.pem

# generate a client cert without distribution points

CA_CN="client-no-dist-points"

openssl genrsa -out intermediate/private/client-no-dist-points.key.pem 2048

openssl req -new -key intermediate/private/client-no-dist-points.key.pem \
        -subj "/C=${CA_C}/ST=${CA_ST}/L=${CA_L}/O=${CA_O}/OU=${CA_OU}/CN=${CA_CN}" \
        -out intermediate/csr/client-no-dist-points.csr.pem

openssl ca -batch -config intermediate/openssl.cnf \
        -extensions usr_cert_no_crl -notext -md sha256 \
        -in intermediate/csr/client-no-dist-points.csr.pem \
        -out intermediate/certs/client-no-dist-points.cert.pem

#################################################
# Generate OCSP
#################################################

figlet Generating OCSP

# -aes256
openssl genrsa \
        -out intermediate/private/ocsp.server.key.pem 4096

CA_C="${TLS_DN_C:-SE}"
CA_ST="${TLS_DN_ST:-Stockholm}"
CA_L="${TLS_DN_L:-Stockholm}"
CA_O="${TLS_DN_O:-MyOrgName}"
CA_OU="${TLS_DN_OU:-MyIntermediateCA}"
CA_CN="ocsp.server"

openssl req -config intermediate/openssl.cnf -new -sha256 \
        -subj "/C=${CA_C}/ST=${CA_ST}/L=${CA_L}/O=${CA_O}/OU=${CA_OU}/CN=${CA_CN}" \
        -key intermediate/private/ocsp.server.key.pem \
        -out intermediate/csr/ocsp.server.csr.pem

CA_C="${TLS_DN_C:-SE}"
CA_ST="${TLS_DN_ST:-Stockholm}"
CA_L="${TLS_DN_L:-Stockholm}"
CA_O="${TLS_DN_O:-MyOrgName}"
CA_OU="${TLS_DN_OU:-MyIntermediateCA}"
CA_CN="ocsp.client"

# using the same key as the server
cp intermediate/private/ocsp.{server,client}.key.pem

openssl req -config intermediate/openssl.cnf -new -sha256 \
        -subj "/C=${CA_C}/ST=${CA_ST}/L=${CA_L}/O=${CA_O}/OU=${CA_OU}/CN=${CA_CN}" \
        -key intermediate/private/ocsp.client.key.pem \
        -out intermediate/csr/ocsp.client.csr.pem

# using the `ocsp` extension here is probably wrong?!
openssl ca -batch -config intermediate/openssl.cnf \
        # -extensions server_cert -days 3750 -notext -md sha256 \
        -extensions ocsp -days 3750 -notext -md sha256 \
        -in intermediate/csr/ocsp.server.csr.pem \
        -out intermediate/certs/ocsp.server.cert.pem

openssl ca -batch -config intermediate/openssl.cnf \
        -extensions usr_cert -days 3750 -notext -md sha256 \
        -in intermediate/csr/ocsp.client.csr.pem \
        -out intermediate/certs/ocsp.client.cert.pem

# openssl genrsa -out intermediate/private/test.server.key.pem 2048
# CA_C="${TLS_DN_C:-SE}"
# CA_ST="${TLS_DN_ST:-Stockholm}"
# CA_L="${TLS_DN_L:-Stockholm}"
# CA_O="${TLS_DN_O:-MyOrgName}"
# CA_OU="${TLS_DN_OU:-MyIntermediateCA}"
# CA_CN="test.server"
# openssl req -config intermediate/openssl.cnf \
#       -key intermediate/private/test.server.key.pem \
#       -new -sha256 -out intermediate/csr/test.server.csr.pem
# openssl ca -config intermediate/openssl.cnf \
#       -extensions server_cert -days 375 -notext -md sha256 \
#       -in intermediate/csr/test.server.csr.pem \
#       -out intermediate/certs/test.server.cert.pem
# -sha256
# openssl ocsp -port 127.0.0.1:9877 -text -sha256 \
#         -index intermediate/index.txt \
#         -CA intermediate/certs/ca-chain.cert.pem \
#         -rkey intermediate/private/ocsp.server.key.pem \
#         -rsigner intermediate/certs/ocsp.server.cert.pem \
#         -nrequest 1

# openssl ocsp -CAfile intermediate/certs/ca-chain.cert.pem \
#         -url http://127.0.0.1:9877 -resp_text \
#         -issuer intermediate/certs/intermediate.cert.pem \
#         -cert intermediate/certs/test.server.cert.pem

# openssl ca -config intermediate/openssl.cnf \
#         -revoke intermediate/certs/test.server.cert.pem
