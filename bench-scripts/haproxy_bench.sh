#!/usr/bin/env ksh
#
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#

set -x

INSTALL_ROOT=${BENCH_INSTALL_ROOT:-"/tmp/bench.binaries"}
RESULT_DIR=${BENCH_RESULTS:-"${INSTALL_ROOT}/results"}
WORKSPACE_ROOT=${BENCH_WORKSPACE_ROOT:-"/tmp/bench.workspace"}
MAKE_OPTS=${BENCH_MAKE_OPTS}
HTTPS_PORT=${BENCH_HTTPS_PORT:-'4430'}
HTTP_PORT=${BENCH_HTTP_PORT:-'8080'}
CERT_SUBJ=${BENCH_CERT_SUBJ:-'/CN=localhost'}
CERT_ALT_SUBJ=${BENCH_CERT_ALT_SUBJ:-'subjectAltName=DNS:localhost,IP:127.0.0.1'}
TEST_TIME=${BENCH_TEST_TIME:-'5M'}
HOST=${BENCH_HOST:-'127.0.0.1'}
HAPROXY_VERSION='v3.2.0'

function install_haproxy {
	typeset VERSION=${HAPROXY_VERSION:-v3.2.0}
	typeset SSL_LIB=openssl-master
    typeset HAPROXY_REPO="https://github.com/haproxy/haproxy.git"
    typeset BASENAME='haproxy'
    typeset DIRNAME="${BASENAME}-${VERSION}"
    typeset CERTDIR="${INSTALL_ROOT}/${SSL_LIB}/conf"

    if [[ -z "${INSTALL_ROOT}/${SSL_LIB}/sbin/haproxy" ]] ; then
        echo "haproxy already installed; skipping.."
    else
        cd "${WORKSPACE_ROOT}"
        mkdir -p "${DIRNAME}" || exit 1
        cd "${DIRNAME}"
        git clone "${HAPROXY_REPO}" -b ${VERSION} --depth 1 . || exit 1
        
        # haproxy does not have a configure script; only a big makefile
        make ${MAKE_OPTS} \
             TARGET=generic \
             USE_OPENSSL=1 \
             SSL_INC="${INSTALL_ROOT}/${SSL_LIB}/include" \
             SSL_LIB="${INSTALL_ROOT}/${SSL_LIB}/lib" || exit 1

        make install ${MAKE_OPTS} \
             PREFIX="${INSTALL_ROOT}/${SSL_LIB}" || exit 1
    fi

    # now generate the certificates
    # await that openssl-master is always installed
    echo "generating new certificates for haproxy"
    LD_LIBRARY_PATH=${INSTALL_ROOT}/openssl-master/lib ${INSTALL_ROOT}/openssl-master/bin/openssl req \
    -newkey rsa:2048 \
    -nodes \
    -x509 \
    -days 1 \
    -keyout "${CERTDIR}/haproxy_privateCA.pem" \
    -out "${CERTDIR}/haproxy_ca.crt" \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Inc/OU=IT/CN=example.com" || exit 1

    LD_LIBRARY_PATH=${INSTALL_ROOT}/openssl-master/lib ${INSTALL_ROOT}/openssl-master/bin/openssl req \
    -newkey rsa:2048 \
    -nodes \
    -subj "/CN=exampleUser/O=exampleOrganization" \
    -keyout "${CERTDIR}/clientKey.key" \
    -out client.csr || exit 1

    LD_LIBRARY_PATH=${INSTALL_ROOT}/openssl-master/lib ${INSTALL_ROOT}/openssl-master/bin/openssl req \
    -x509 \
    -in client.csr \
    -out "${CERTDIR}/haproxy_client.crt" \
    -CA "${CERTDIR}/haproxy_ca.crt" \
    -CAkey "${CERTDIR}/haproxy_privateCA.pem" \
    -days 1 \
    -copy_extensions copyall \
    -addext "basicConstraints=CA:FALSE" \
    -addext "keyUsage=digitalSignature" \
    -addext "extendedKeyUsage=clientAuth" \
    -addext "subjectKeyIdentifier=hash" \
    -addext "authorityKeyIdentifier=keyid,issuer" || exit 1

    # create the clientkey for haproxy
    cat "${CERTDIR}/haproxy_ca.crt" "${CERTDIR}/haproxy_privateCA.pem" > "${CERTDIR}/haproxy_server.pem"

    # setting up SSL Termination mode for now
    cat <<EOF > "${INSTALL_ROOT}/openssl-master/conf/haproxy.cfg"
frontend test_client
  mode http
  bind :${HTTPS_PORT} ssl crt ${CERTDIR}/haproxy_server.pem
  default_backend test_webserver

backend test_webserver
  mode http
  balance roundrobin
  server s1 ${HOST}:${HTTPS_PORT}
EOF
}

function run_haproxy {
    typeset OPENSSL_DIR="${INSTALL_ROOT}/openssl-master"

    # configure siege to use haproxy
	if [[ -z "${OPENSSL_DIR}/etc/siegerc" ]] ; then
        echo "Did not found siegerc. Siege should be installed first."
        exit 1
	fi
    echo "#haproxy" >> "${OPENSSL_DIR}/etc/siegerc"
    echo "ssl-cert = ${OPENSSL_DIR}/conf/haproxy_ca.crt" >> "${OPENSSL_DIR}/etc/siegerc"

    LD_LIBRARY_PATH="${OPENSSL_DIR}/lib:${LD_LIBRARY_PATH}" "${OPENSSL_DIR}/sbin/haproxy" -f "${OPENSSL_DIR}/conf/haproxy.cfg" -D
    if [[ $? -ne 0 ]] ; then
        echo "could not start haproxy"
        exit 1
    fi
}

function kill_haproxy {
    typeset OPENSSL_DIR="${INSTALL_ROOT}/openssl-master"

    # clear the siege config
    sed '/#haproxy/{N;d;}' "${OPENSSL_DIR}/etc/siegerc" || exit 1

    pkill -f haproxy
}

#TODO add options to configure server/client/both side certificate for haproxy
install_haproxy
