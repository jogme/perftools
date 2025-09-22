#!/bin/ksh -x
#
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#

#
#
# make sure to disable firewall
#	ufw disable
# it feels like ipv6 loopback traffic is disabled on ubuntu
#

#
# This is the output of apachectl -V  we use to test
#  libraries:
#
# Server version: Apache/2.4.65 (Unix)
# Server built:   Sep 12 2025 14:49:08
# Server's Module Magic Number: 20120211:141
# Server loaded:  APR 1.7.6, APR-UTIL 1.6.3, PCRE 10.42 2022-12-11
# Compiled using: APR 1.7.6, APR-UTIL 1.6.3, PCRE 10.42 2022-12-11
# Architecture:   64-bit
# Server MPM:     event
#   threaded:     yes (fixed thread count)
#     forked:     yes (variable process count)
#
# the siege client downloads static files which look as follows
# for all tests:
#    64 Sep 12 14:49 test.txt
#   128 Sep 12 14:49 test_1.txt
#   256 Sep 12 14:49 test_2.txt
#   512 Sep 12 14:49 test_3.txt
#  1.0K Sep 12 14:49 test_4.txt
#  2.0K Sep 12 14:49 test_5.txt
#  4.0K Sep 12 14:49 test_6.txt
#  8.0K Sep 12 14:49 test_7.txt
#   16K Sep 12 14:49 test_8.txt
#   32K Sep 12 14:49 test_9.txt
#   64K Sep 12 14:49 test_10.txt
#  128K Sep 12 14:49 test_11.txt
#  256K Sep 12 14:49 test_12.txt
#  512K Sep 12 14:49 test_13.txt
#  1.0M Sep 12 14:49 test_14.txt
#  2.0M Sep 12 14:49 test_15.txt
#  4.0M Sep 12 14:49 test_16.txt
#

INSTALL_ROOT=${BENCH_INSTALL_ROOT:-"$HOME/work.openssl/bench.binaries"}
RESULT_DIR=${BENCH_RESULTS:-"${INSTALL_ROOT}/results"}
WORKSPACE_ROOT=${BENCH_WORKSPACE_ROOT:-"$HOME/work.openssl/bench.workspace"}
MAKE_OPTS=${BENCH_MAKE_OPTS}
HTTPS_PORT=${BENCH_HTTPS_PORT:-'4430'}
HTTP_PORT=${BENCH_HTTP_PORT:-'8080'}
CERT_SUBJ=${BENCH_CERT_SUBJ:-'/CN=localhost'}
CERT_ALT_SUBJ=${BENCH_CERT_ALT_SUBJ:-'subjectAltName=DNS:localhost,IP:127.0.0.1'}
TEST_TIME=${BENCH_TEST_TIME:-'5M'}
HOST=${BENCH_HOST:-'127.0.0.1'}
APACHE_VERSION='2.4.65'

. ./common_util.sh

function install_wolfssl_for_apache {
	typeset VERSION=$1
	typeset WOLFSSL_TAG="v${VERSION}-stable"
	typeset DIRNAME="wolfssl-${VERSION}"
	typeset WOLFSSL_WORKSPCE="${WORKSPACE_ROOT}/${DIRNAME}"
	typeset WOLFSSL_REPO='https://github.com/wolfSSL/wolfssl'

	if [[ -z ${VERSION} ]] ; then
		DIRNAME='wolfssl'
		WOLFSSL_WORKSPCE="${WORKSPACE_ROOT}/${DIRNAME}"
	fi
	mkdir -p ${WOLFSSL_WORKSPCE}
	cd ${WOLFSSL_WORKSPCE}
	git clone "${WOLFSSL_REPO}" .
	if [[ $? -ne 0 ]] ; then
		#
		# make sure master is up-to date just in
		# case we build a master version
		#
		git checkout master || exit 1
		git pull --rebase || exit 1
	fi

	if [[ -n "${VERSION}" ]] ; then

		git branch -l | grep ${VERSION}
		if [[ $? -ne 0 ]] ; then
			git checkout tags/${WOLFSSL_TAG} -b wolfssl-${VERSION} || exit 1
		fi
	fi

	AUTOCONF_VERSION=2.72 AUTOMAKE_VERSION=1.16 ./autogen.sh || exit 1

	LDFLAGS="-Wl,-rpath,${INSTALL_ROOT}/${SSL_LIB}/lib" ./configure --prefix="${INSTALL_ROOT}/${DIRNAME}" \
	    --enable-apachehttpd  \
	    --enable-postauth || exit 1

	make ${MAKE_OPTS} || exit 1
	make ${MAKE_OPTS} install || exit 1
}

#
# download apr and apr-util and unpack them to apachr-src/srclib directory. The
# unpacked directories must be renamed to basenames (name without version
# string) otherwise apache configure script will complain.
#
function bundle_apr {
	typeset VERSION=${APR_VERSION:-1.7.6}
	typeset SUFFIX='tar.gz'
	typeset BASENAME='apr'
	typeset DOWNLOAD_FILE="${BASENAME}-${VERSION}.${SUFFIX}"
	typeset BUILD_DIR="${BASENAME}-${VERSION}"
	typeset DOWNLOAD_URL='https://dlcdn.apache.org/apr'
	typeset DOWNLOAD_LINK="${DOWNLOAD_URL}/${DOWNLOAD_FILE}"
	typeset SAVE_CWD=`pwd`

	if [[ ! -f "${WORKSPACE_ROOT}/${DOWNLOAD_FILE}" ]] ; then
		wget -O "${WORKSPACE_ROOT}/${DOWNLOAD_FILE}" "${DOWNLOAD_LINK}" || exit 1
	fi

	cd $1
	tar xzf "${WORKSPACE_ROOT}/${DOWNLOAD_FILE}"
	mv "${BASENAME}-${VERSION}" "${BASENAME}" || exit 1

	typeset VERSION="${APRU_VERSION:-1.6.3}"
	typeset BASENAME='apr-util'
	typeset DOWNLOAD_FILE="${BASENAME}-${VERSION}.${SUFFIX}"
	typeset DOWNLOAD_LINK="${DOWNLOAD_URL}/${DOWNLOAD_FILE}"
	if [[ ! -f "${WORKSPACE_ROOT}/${DOWNLOAD_FILE}" ]] ; then
		wget -O "${WORKSPACE_ROOT}/${DOWNLOAD_FILE}" "${DOWNLOAD_LINK}" || exit 1
	fi
	tar xzf "${WORKSPACE_ROOT}/${DOWNLOAD_FILE}"
	mv "${BASENAME}-${VERSION}" "${BASENAME}" || exit 1

	cd "${SAVE_CWD}"
}

function install_apache {
	typeset VERSION=${APACHE_VERSION:-2.4.65}
	typeset SUFFIX='tar.bz2'
	typeset BASENAME='httpd'
	typeset DOWNLOAD_FILE="${BASENAME}-${VERSION}.${SUFFIX}"
	typeset BUILD_DIR="${BASENAME}-${VERSION}"
	typeset DOWNLOAD_URL='https://archive.apache.org/dist/httpd'
	typeset DOWNLOAD_LINK="${DOWNLOAD_URL}/${DOWNLOAD_FILE}"
	typeset SSL_LIB=$1

	if [[ -z "${SSL_LIB}" ]] ; then
		SSL_LIB='openssl-master'
	fi

	cd "$WORKSPACE_ROOT"
	if [[ ! -f "${DOWNLOAD_FILE}" ]] ; then
		wget -O "$DOWNLOAD_FILE" "$DOWNLOAD_LINK" || exit 1
	fi
	tar xjf "${DOWNLOAD_FILE}" || exit 1
	bundle_apr "${WORKSPACE_ROOT}/${BUILD_DIR}/srclib"
	cd "${BUILD_DIR}"
	LDFLAGS="-Wl,-rpath,${INSTALL_ROOT}/${SSL_LIB}/lib" ./configure --prefix="${INSTALL_ROOT}/${SSL_LIB}" \
		--enable-info \
		--enable-ssl \
		--disable-ab \
		--with-included-apr \
		--with-ssl="${INSTALL_ROOT}/${SSL_LIB}" || exit 1
	make ${MAKE_OPTS} || exit 1
	make ${MAKE_OPTS} install || exit 1
}

function install_apache_aws {
	typeset VERSION=${APACHE_VERSION:-2.4.65}
	typeset SUFFIX='tar.bz2'
	typeset BASENAME='httpd'
	typeset DOWNLOAD_FILE="${BASENAME}-${VERSION}.${SUFFIX}"
	typeset BUILD_DIR="${BASENAME}-${VERSION}"
	typeset DOWNLOAD_URL='https://archive.apache.org/dist/httpd'
	typeset DOWNLOAD_LINK="${DOWNLOAD_URL}/${DOWNLOAD_FILE}"
	typeset SSL_LIB=$1

	if [[ -z "${SSL_LIB}" ]] ; then
		SSL_LIB='openssl-master'
	fi

	cd "$WORKSPACE_ROOT"
	if [[ ! -f "${DOWNLOAD_FILE}" ]] ; then
		wget -O "$DOWNLOAD_FILE" "$DOWNLOAD_LINK" || exit 1
	fi
	tar xjf "${DOWNLOAD_FILE}" || exit 1
	bundle_apr "${WORKSPACE_ROOT}/${BUILD_DIR}/srclib"
	#
	# we need to patch apache so it builds with aws.
	# this patch seems to be good enough for testing.
	# should not be used in production
	#
	cd "${BUILD_DIR}"
cat <<EOF | patch -p0 || exit 1
--- modules/ssl/ssl_engine_init.c	2025-07-07 12:09:30.000000000 +0000
+++ modules/ssl/ssl_engine_init.c	2025-09-12 13:32:58.637510805 +0000
@@ -536,6 +536,7 @@
     ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01893)
                  "Configuring TLS extension handling");
 
+#ifndef OPENSSL_IS_AWSLC
     /*
      * The Server Name Indication (SNI) provided by the ClientHello can be
      * used to select the right (name-based-)vhost and its SSL configuration
@@ -550,6 +551,7 @@
         ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
         return ssl_die(s);
     }
+#endif
 
 #if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
     /*
@@ -1358,7 +1360,7 @@
  * off the OpenSSL stack and evaluates to true only for the first
  * case.  With OpenSSL < 3 the second case is identifiable by the
  * function code, but function codes are not used from 3.0. */
-#if OPENSSL_VERSION_NUMBER < 0x30000000L
+#if OPENSSL_VERSION_NUMBER < 0x30000000L && !defined(OPENSSL_IS_AWSLC)
 #define CHECK_PRIVKEY_ERROR(ec) (ERR_GET_FUNC(ec) != X509_F_X509_CHECK_PRIVATE_KEY)
 #else
 #define CHECK_PRIVKEY_ERROR(ec) (ERR_GET_LIB(ec) != ERR_LIB_X509            \\
@@ -1751,7 +1753,7 @@
 
     ap_assert(store != NULL); /* safe to assume always non-NULL? */
 
-#if OPENSSL_VERSION_NUMBER >= 0x1010100fL && !defined(LIBRESSL_VERSION_NUMBER)
+#if OPENSSL_VERSION_NUMBER >= 0x1010100fL && !(defined(LIBRESSL_VERSION_NUMBER) || defined(OPENSSL_IS_AWSLC))
     /* For OpenSSL >=1.1.1, turn on client cert support which is
      * otherwise turned off by default (by design).
      * https://github.com/openssl/openssl/issues/6933 */
EOF
	CFLAGS='-DOPENSSL_NO_TLSEXT' LDFLAGS="-Wl,-rpath,${INSTALL_ROOT}/${SSL_LIB}/lib" ./configure --prefix="${INSTALL_ROOT}/${SSL_LIB}" \
		--enable-info \
		--enable-ssl \
		--disable-ab \
		--with-included-apr \
		--with-ssl="${INSTALL_ROOT}/${SSL_LIB}" || exit 1
	make ${MAKE_OPTS} || exit 1
	make ${MAKE_OPTS} install || exit 1
}

#
# we need as build dependency for apache
# looks like apache build system not always picks it up
# from system
#
function install_pcre {
	typeset SSL_LIB=$1
	typeset VERSION='8.45'
	typeset SUFFIX='tar.bz2'
	typeset BASENAME='pcre'
	typeset DOWNLOAD_FILE="${BASENAME}-${VERSION}.${SUFFIX}"
	typeset BUILD_DIR="${BASENAME}-${VERSION}"
	typeset DOWNLOAD_URL="https://sourceforge.net/projects/pcre/files/pcre/${VERSION}"
	typeset DOWNLOAD_LINK="${DOWNLOAD_URL}/${DOWNLOAD_FILE}"/download

	cd "${WORKSPACE_ROOT}"
	if [[ -z "${SSL_LIB}" ]] ; then
		exit 1
	fi

	if [[ ! -f "${DOWNLOAD_FILE}" ]] ; then
		wget -O "${DOWNLOAD_FILE}" "${DOWNLOAD_LINK}" || exit 1
	fi
	tar xjf "${DOWNLOAD_FILE}" || exit 1
	cd "${BUILD_DIR}"
	./configure --prefix="${INSTALL_ROOT}/${SSL_LIB}" || exit 1
	make ${MAKE_OPTS} || exit 1
	make ${MAKE_OPTS} install || exit 1
	cd "${WORKSPACE_ROOT}"
}

#
# we need a libtool to be able to run buildconf
#
function install_libtool {
	typeset SSL_LIB=$1
	typeset VERSION='2.5.4'
	typeset SUFFIX='tar.gz'
	typeset BASENAME='libtool'
	typeset DOWNLOAD_FILE="${BASENAME}-${VERSION}.${SUFFIX}"
	typeset BUILD_DIR="${BASENAME}-${VERSION}"
	typeset DOWNLOAD_URL="https://ftpmirror.gnu.org/libtool/"
	typeset DOWNLOAD_LINK="${DOWNLOAD_URL}/${DOWNLOAD_FILE}"

	if [[ -z "${SSL_LIB}" ]] ; then
		exit 1
	fi

	cd "${WORKSPACE_ROOT}"
	if [[ ! -f "${DOWNLOAD_FILE}" ]] ; then
		wget -O "${DOWNLOAD_FILE}" "${DOWNLOAD_LINK}" || exit 1
	fi
	tar xzf "${DOWNLOAD_FILE}" || exit 1
	cd "${BUILD_DIR}"
	./configure --prefix="${INSTALL_ROOT}/${SSL_LIB}" || exit 1
	make ${MAKE_OPTS} || exit 1
	make ${MAKE_OPTS} install || exit 1
	cd "${WORKSPACE_ROOT}"
}


function install_wolf_apache {
	typeset VERSION='2.4.51'
	typeset SUFFIX='tar.bz2'
	typeset BASENAME='httpd'
	typeset DOWNLOAD_FILE="${BASENAME}-${VERSION}.${SUFFIX}"
	typeset BUILD_DIR="${BASENAME}-${VERSION}"
	typeset DOWNLOAD_URL='https://archive.apache.org/dist/httpd'
	typeset DOWNLOAD_LINK="${DOWNLOAD_URL}/${DOWNLOAD_FILE}"
	typeset SSL_LIB=$1

	if [[ -z "${SSL_LIB}" ]] ; then
		echo 'ssl library must be specified'
		exit 1
	fi

	install_pcre "${SSL_LIB}"
	install_libtool "${SSL_LIB}"

	cd "${WORKSPACE_ROOT}"
	#
	# downgrade apache version for wolf, because
	# wolf needs to apply its own set of patches.
	#
	DOWNLOAD_FILE="${BASENAME}-${VERSION}.${SUFFIX}"
	DOWNLOAD_LINK="${DOWNLOAD_URL}/${DOWNLOAD_FILE}"
	BUILD_DIR="${BASENAME}-${VERSION}"
	if [[ ! -f "${DOWNLOAD_FILE}" ]] ; then
		wget -O "$DOWNLOAD_FILE" "$DOWNLOAD_LINK" || exit 1
	fi
	tar xjf "${DOWNLOAD_FILE}" || exit 1
	#
	# clone wolf's opens source projects (a.k.a. wolf's ports)
	# https://github.com/wolfSSL/osp
	# we need this to obtain patch for apache sources
	#
	git clone https://github.com/wolfSSL/osp || exit 1
	cd "${BUILD_DIR}"
	patch -p1 < ../osp/apache-httpd/svn_apache-${VERSION}_patch.diff || exit 1
	cd "${WORKSPACE_ROOT}"
	bundle_apr "${WORKSPACE_ROOT}/${BUILD_DIR}/srclib"
	cd "${BUILD_DIR}"
	#
	# unlike other ssl implementations wofl requires
	# mod_ssl to be linked statically with apache daemon
	#
	PATH=${PATH}:"${INSTALL_ROOT}/${SSL_LIB}/bin" ./buildconf || exit 1
	./configure --prefix="${INSTALL_ROOT}/${SSL_LIB}" \
		--enable-info \
		--enable-ssl \
		--disable-ab \
		--with-included-apr \
		--with-pcre="${INSTALL_ROOT}/${SSL_LIB}" \
		--with-wolfssl="${INSTALL_ROOT}/${SSL_LIB}"\
		--disable-shared \
		--with-libxml2 \
		--enable-mods-static=all  || exit 1
	make ${MAKE_OPTS} || exit 1
	make ${MAKE_OPTS} install || exit 1
}

function generate_download_files {
	typeset SSL_LIB=$1
	typeset i=0

	if [[ -z "${SSL_LIB}" ]] ; then
		SSL_LIB='openssl-master'
	fi

	#
	# we start with 64 bytes long file
	#
	typeset HTDOCS="${INSTALL_ROOT}/${SSL_LIB}"/htdocs
	for i in `seq 16` ; do
		echo -n 'test' >> "${HTDOCS}"/test.txt
	done

	#
	# here we double the size of last file with each
	# iteration. starting at 64, then 128, 254, 512,...
	#
	typeset LAST="${HTDOCS}"/test.txt
	for i in `seq 16` ; do
		cat "${LAST}" "${LAST}" > "${HTDOCS}/test_${i}.txt"
		LAST="${HTDOCS}/test_${i}.txt"
	done
}

function config_apache {
	typeset SSL_LIB=$1
	if [[ -z "${SSL_LIB}" ]] ; then
		SSL_LIB='openssl-master'
	fi
	typeset CONF_FILE="${INSTALL_ROOT}/${SSL_LIB}/conf/httpd.conf"
	typeset HTTPS_CONF_FILE="${INSTALL_ROOT}/${SSL_LIB}/conf/extra/httpd-ssl.conf"
	typeset SERVERCERT="${INSTALL_ROOT}/${SSL_LIB}/conf/server.crt"
	typeset SERVERKEY="${INSTALL_ROOT}/${SSL_LIB}/conf/server.key"
	#
	# this is hack as we always assume openssl from master version
	# is around. We need the tool to create cert and key for server
	#
	typeset OPENSSL="${INSTALL_ROOT}/openssl-master/bin/openssl"
	typeset MOD_SSL="${INSTALL_ROOT}/${SSL_LIB}/modules/mod_ssl.so"
	typeset SERVER_NAME="${BENCH_SERVER_NAME:-localhost}"
	SERVER_NAME="${SERVER_NAME}:${HTTPS_PORT}"

	#
	# enable mod_ssl
	#
	# we also need slashes in openssl not to confuse sed(1) which adjusts
	# apache configuration.
	#
	typeset SANITZE_SSL=$(echo ${MOD_SSL} | sed -e 's/\//\\\//g')
	cp "${CONF_FILE}" "${CONF_FILE}".wrk
	sed -e "s/^#\(LoadModule ssl_module\)\(.*$\)/\1 ${SANITZE_SSL}/" \
 	    "${CONF_FILE}".wrk > "${CONF_FILE}" || exit 1

	#
	# load ssl config
	# 
	cp "${CONF_FILE}" "${CONF_FILE}".wrk
	sed -e 's/^#\(Include conf.*httpd-ssl.conf*$\)/\1/g' \
	    "${CONF_FILE}".wrk > "${CONF_FILE}" || exit 1

	#
	# https 443 will be on 4430
	#
	cp "${HTTPS_CONF_FILE}" "${HTTPS_CONF_FILE}".wrk
	sed -e "s/^Listen 443.*$/Listen ${HTTPS_PORT}/g" \
	    "${HTTPS_CONF_FILE}".wrk > "${HTTPS_CONF_FILE}" || exit 1
	#
	# http 80 will be on 8080
	#
	cp "${CONF_FILE}" "${CONF_FILE}".wrk
	sed -e "s/^Listen 80.*$/Listen ${HTTP_PORT}/g" \
	    "${CONF_FILE}".wrk > "${CONF_FILE}" || exit 1

	#
	#
	# fix VirtualHost for 4430
	#
	cp "${HTTPS_CONF_FILE}" "${HTTPS_CONF_FILE}".wrk
	sed -e "s/\(^<VirtualHost _default_\:\)\(443>\)$/\1${HTTPS_PORT}>/g" \
	    "${HTTPS_CONF_FILE}".wrk > "${HTTPS_CONF_FILE}" || exit 1

	#
	# fix ServerName in http.conf
	#
	cp "${CONF_FILE}" "${CONF_FILE}".wrk
	sed -e "s/^#ServerName.*/ServerName ${SERVER_NAME}/g" \
	    "${CONF_FILE}".wrk > "${CONF_FILE}" || exit 1
	#
	# fix ServerName
	#
	cp "${HTTPS_CONF_FILE}" "${HTTPS_CONF_FILE}".wrk
	sed -e "s/^ServerName.*/ServerName ${SERVER_NAME}/g" \
	    "${HTTPS_CONF_FILE}".wrk > "${HTTPS_CONF_FILE}" || exit 1

	#
	# disable SSLSessionCache, we use worker thread model, if I understand
	# documentation right we don't need to share cache between processes.
	#
	cp "${HTTPS_CONF_FILE}" "${HTTPS_CONF_FILE}".wrk
	sed -e 's/\(^SSLSessionCache.*$\)/#\1/g' "${HTTPS_CONF_FILE}".wrk > \
	    "${HTTPS_CONF_FILE}" || exit 1
	#
	# generate self-signed cert with key
	# note this is hack because we always assume
	# openssl-master is installed in INSTALL root
	#
	$(LD_LIBRARY_PATH="${INSTALL_ROOT}/openssl-master/lib" "${OPENSSL}" \
	    req -x509 -newkey rsa:4096 -days 180 -noenc -keyout \
	    "${SERVERKEY}" -out "${SERVERCERT}" -subj "${CERT_SUBJ}" \
	    -addext "${CERT_ALT_SUBJ}") || exit 1

	generate_download_files "${SSL_LIB}"
}

function run_test {
	typeset SSL_LIB=$1
	typeset HTTP='https'
	typeset i=0
	typeset PORT=${HTTPS_PORT}
	if [[ -z "${SSL_LIB}" ]] ; then
		SSL_LIB='openssl-master'
	fi
	typeset RESULTS="${SSL_LIB}".txt
	if [[ "${SSL_LIB}" = 'nossl' ]] ; then
		HTTP='http'
		SSL_LIB='openssl-master'
		RESULTS='nossl.txt'
		PORT=${HTTP_PORT}
	fi
	typeset HTDOCS="${INSTALL_ROOT}/${SSL_LIB}"/htdocs
	typeset SIEGE="${INSTALL_ROOT}"/openssl-master/bin/siege

	#
	# we always try to use siege from openssl master by default,
	# if not found then we try the one which is installed for
	# openssl version we'd like to test.
	#
	if [[ ! -x "${SIEGE}" ]] ; then
		echo "no ${SIEGE}"
		exit 1
	fi

	#
	# generate URLs for sewage
	#
	rm -f siege_urls.txt
	for i in `ls -1 ${HTDOCS}/*.txt` ; do
		echo "${HTTP}://${HOST}:${PORT}/`basename $i`" >> siege_urls.txt
	done

	#
	# start apache httpd server
	#
	"${INSTALL_ROOT}/${SSL_LIB}/bin/httpd"
	if [[ $? -ne 0 ]] ; then
		echo "could not start ${INSTALL_ROOT}/${SSL_LIB}/bin/httpd"
		exit 1
	fi
	LD_LIBRARY_PATH=${INSTALL_ROOT}/openssl-master/lib "${SIEGE}" -t ${TEST_TIME}  -b \
	    -f siege_urls.txt 2> "${RESULT_DIR}/${RESULTS}"

	$("${INSTALL_ROOT}/${SSL_LIB}/bin/apachectl" stop) || exit 1
}

function setup_tests {
	install_openssl master
	install_siege openssl-master
	install_apache openssl-master
	config_apache openssl-master
	cd "${WORKSPACE_ROOT}"
	clean_build

	for i in 3.0 3.1 3.2 3.3 3.4 3.5 3.6 ; do
		install_openssl openssl-$i ;
		install_apache openssl-$i
		config_apache openssl-$i
		cd "${WORKSPACE_ROOT}"
		clean_build
	done

	#
	# wolf-ssl does not work. It installs it starts,
	# client can establish connection but handshake
	# seems to get stuck. I can see client sends its
	# hello with TLS-1.2/TLS-1.3 and there is no
	# reply from server, for more than 10secs.
	#
	# this is the configuration I'm using:
	# ServerName localhost
	# Listen 4430
	#
	# SSLCipherSuite HIGH:MEDIUM:!MD5:!RC4:!3DES
	# SSLHonorCipherOrder on
	# SSLProtocol all -SSLv3
	# <VirtualHost *:443>
	# ServerName localhost
	# DocumentRoot "/home/sashan/work.openssl/bench.binaries/wolfssl-5.8.2/htdocs"
	# ErrorLog "/home/sashan/work.openssl/bench.binaries/wolfssl-5.8.2/logs/error_log"
	# TransferLog "/home/sashan/work.openssl/bench.binaries/wolfssl-5.8.2/logs/access_log"
	# SSLEngine on
	# SSLCertificateFile "/home/sashan/work.openssl/bench.binaries/wolfssl-5.8.2/conf/server.crt"
	# SSLCertificateKeyFile "/home/sashan/work.openssl/bench.binaries/wolfssl-5.8.2/conf/server.key"
	# </VirtualHost>
	#
	# Unlike the suggested configuration here:
	#	https://github.com/wolfSSL/osp/blob/master/apache-httpd/README.md#running-simple-https
	# I had to add SSLCipherSuite SSLHonorCipherOrder SSLProtocol. The configuration from
	# link above does not work either. The httpd process refuses to start, leaving message:
	#
	# [Fri Aug 29 17:10:39.065428 2025] [ssl:emerg] [pid 3263901:tid 133639498441152] AH01898: Unable to configure permitted SSL ciphers
	# [Fri Aug 29 17:10:39.065460 2025] [ssl:emerg] [pid 3263901:tid 133639498441152] AH02311: Fatal error initialising mod_ssl, exiting. See /home/sashan/work.openssl/bench.binaries/wolfssl-5.8.2/logs/error_log for more information
	# AH00016: Configuration Failed
	#
	# any hints/advise on how to get apache with wolfssl going is welcomed
	#
	install_wolfssl_for_apache 5.8.2
	install_wolf_apache wolfssl-5.8.2
	config_apache wolfssl-5.8.2
	cd "${WORKSPACE_ROOT}"
	clean_build

	install_libressl 4.1.0
	install_apache libressl-4.1.0
	config_apache libressl-4.1.0
	cd "${WORKSPACE_ROOT}"
	clean_build

	install_boringssl
	install_apache boringssl
	config_apache boringssl
	cd "${WORKSPACE_ROOT}"
	clean_build

	install_aws_lc
	install_apache_aws aws-lc
	config_apache aws-lc
	cd "${WORKSPACE_ROOT}"
	clean_build
}

function run_tests {
	run_test nossl
	for i in 3.0 3.1 3.2 3.3 3.4 3.5 3.6 ; do
		run_test openssl-${i}
	done
	run_test openssl-master
	run_test libressl-4.1.0
	#
	# could not get apache with wolfssl working
	#
	# run_test wolfssl-5.8.2
	run_test boringssl
	run_test aws-lc
}

check_env
setup_tests
run_tests
plot_results

echo "testing using siege is complete, results can be found ${RESULT_DIR}:"
