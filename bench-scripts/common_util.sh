#!/bin/ksh -x
#
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#

function check_env {
	if [[ ! -x "$(which gnuplot)" ]] ; then
		echo 'No gnuplot in PATH'
		exit 1
	fi

	if [[ ! -x "$(which git)" ]] ; then
		echo 'No git in PATH'
		exit 1
	fi

	if [[ ! -x "$(which ninja)" ]] ; then
		echo "No ninja in PATH"
		exit 1
	fi

	if [[ ! -x "$(which cmake)" ]] ; then
		echo 'No cmake in PATH'
		exit 1
	fi

	if [[ ! -x "$(which wget)" ]] ; then
		echo 'No wget in PATH'
		exit 1
	fi

	if [[ ! -x "$(which autoconf)" ]] ; then
		echo 'No autoconf in PATH'
		exit 1
	fi

	if [[ ! -x "$(which automake)" ]] ; then
		echo 'No automake in PATH'
		exit 1
	fi

	if [[ ! -x "$(which seq)" ]] ; then
		echo 'No seq in PATH'
		exit 1
	fi

	typeset TEST_FILE=".test_file.$$"
	mkdir -p "${WORKSPACE_ROOT}"
	if [[ $? -ne 0 ]] ; then
		echo "Can not create ${WORKSPACE_ROOT}"
		exit 1;
	fi
	touch "${WORKSPACE_ROOT}/${TEST_FILE}"
	if [[ $? -ne 0 ]] ; then
		echo "${WORKSPACE_ROOT} is not writable"
		exit 1
	fi

	mkdir -p "${INSTALL_ROOT}"
	if [[ $? -ne 0 ]] ; then
		echo "Can not create ${INSTALL_ROOT}"
		exit 1;
	fi
	touch "${INSTALL_ROOT}/${TEST_FILE}"
	if [[ $? -ne 0 ]] ; then
		echo "${INSTALL_ROOT} is not writable"
		exit 1
	fi

	mkdir -p "${RESULT_DIR}"
	touch "${RESULT_DIR}/${TEST_FILE}"
	if [[ $? -ne 0 ]] ; then
		echo "${RESULT_DIR} is not writable"
		exit 1
	fi

	rm -f "${INSTALL_ROOT}/${TEST_FILE}"
	rm -f "${WORKSPACE_ROOT}/${TEST_FILE}"
}

function cleanup {
	rm -rf ${INSTALL_ROOT}
	rm -rf ${WORKSPACE_ROOT}
}

function clean_build {
	typeset SAVE_DIR=`pwd`
	cd "${WORKSPACE_ROOT}"
	for i in * ; do
		if [[ -d $i ]] ; then
			rm -rf $i
		fi
	done
	cd "${SAVE_DIR}"
}

function install_openssl {
	typeset OPENSSL_REPO='https://github.com/openssl/openssl'
	typeset BRANCH_NAME=$1
	typeset DIRNAME=''

	if [[ "${BRANCH_NAME}" = 'master' ]] ; then
		DIRNAME='openssl-master'
	else
		DIRNAME="${BRANCH_NAME}"
	fi

	cd ${WORKSPACE_ROOT}
	mkdir -p ${DIRNAME}
	cd ${DIRNAME}

	git clone --single-branch -b ${BRANCH_NAME} --depth 1 \
		"${OPENSSL_REPO}" . || exit 1

	./Configure --prefix="${INSTALL_ROOT}/${DIRNAME}" \
		--libdir="${INSTALL_ROOT}/${DIRNAME}/lib" no-docs || exit 1
	make ${MAKE_OPTS} || exit 1
	make ${MAKE_OPTS} install || exit 1
}

function install_wolfssl {
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

	./configure --prefix="${INSTALL_ROOT}/${DIRNAME}" \
	    --enable-nginx || exit 1

	make ${MAKE_OPTS} || exit 1
	make ${MAKE_OPTS} install || exit 1
}

function install_libressl {
	typeset VERSION=${1:-4.1.0}
	typeset SUFFIX='tar.gz'
	typeset BASENAME='libressl'
	typeset DOWNLOAD_FILE="${BASENAME}-${VERSION}.${SUFFIX}"
	typeset BUILD_DIR="${BASENAME}-${VERSION}"
	typeset DOWNLOAD_URL='https://cdn.openbsd.org/pub/OpenBSD/LibreSSL/'
	typeset DOWNLOAD_LINK="${DOWNLOAD_URL}/${DOWNLOAD_FILE}"

	cd "$WORKSPACE_ROOT"
	if [[ ! -f "${DOWNLOAD_FILE}" ]] ; then
		wget -O "$DOWNLOAD_FILE" "$DOWNLOAD_LINK" || exit 1
	fi
	tar xzf "${DOWNLOAD_FILE}"
	cd ${BUILD_DIR}
	./configure --prefix="${INSTALL_ROOT}/${BUILD_DIR}" || exit 1
	make ${MAKE_OPTS} || exit 1
	make ${MAKE_OPTS} install || exit 1
}

function install_boringssl {
	typeset BORING_REPO='https://boringssl.googlesource.com/boringssl'
	typeset BORING_NAME='boringssl'
	cd "${WORKSPACE_ROOT}"
	mkdir -p "${BORING_NAME}"
	cd "${BORING_NAME}"
	git clone "${BORING_REPO}" . || exit 1
	cmake -B build -DCMAKE_INSTALL_PREFIX="${INSTALL_ROOT}/${BORING_NAME}" \
	    -DBUILD_SHARED_LIBS=1 \
	    -DCMAKE_BUILD_TYPE=Release || exit 1
	cd build || exit 1
	make ${MAKE_OPTS} || exit 1
	make ${MAKE_OPTS} install || exit 1
	cd "${WORKSPACE_ROOT}"
}

function install_aws_lc {
	typeset AWS_REPO='https://github.com/aws/aws-lc.git'
	typeset AWS_NAME="aws-lc"
	cd "${WORKSPACE_ROOT}"
	mkdir -p "${AWS_NAME}"
	cd "${AWS_NAME}"
	git clone "${AWS_REPO}" . || exit 1
	cmake -B build -DCMAKE_INSTALL_PREFIX="${INSTALL_ROOT}/${AWS_NAME}" \
	    -DBUILD_SHARED_LIBS=1 \
	    -DCMAKE_BUILD_TYPE=Release || exit 1
	cd build || exit 1
	make ${MAKE_OPTS} || exit 1
	make ${MAKE_OPTS} install || exit 1
	cd "${WORKSPACE_ROOT}"
}

function install_siege {
	typeset VERSION='4.1.7'
	typeset SUFFIX='tar.gz'
	typeset BASENAME='siege'
	typeset DOWNLOAD_FILE="${BASENAME}-${VERSION}.${SUFFIX}"
	typeset BUILD_DIR="${BASENAME}-${VERSION}"
	typeset DOWNLOAD_URL='http://download.joedog.org/siege/'
	typeset DOWNLOAD_LINK="${DOWNLOAD_URL}/${DOWNLOAD_FILE}"
	typeset SSL_LIB=$1

	if [[ -z "${SSL_LIB}" ]] ; then
		SSL_LIB='openssl-master'
	fi

	cd "$WORKSPACE_ROOT"
	if [[ ! -f "${DOWNLOAD_FILE}" ]] ; then
		wget -O "$DOWNLOAD_FILE" "$DOWNLOAD_LINK" || exit 1
	fi
	tar xzf "${DOWNLOAD_FILE}"
	cd ${BUILD_DIR}
	./configure --prefix="${INSTALL_ROOT}/${SSL_LIB}" \
		--with-ssl=${SSL_LIB}
	make ${MAKE_OPTS} || exit 1
	make ${MAKE_OPTS} install || exit 1
}

function plot_chart {
	typeset BASENAME=$1
	typeset TITLE=$2
	typeset MATCH=$3
	typeset COUNT=1
	typeset RESULT_FILE
	typeset DATA_FILE=${RESULT_DIR}/${BASENAME}.data
	typeset PLOT_FILE=${RESULT_DIR}/${BASENAME}.plot
	typeset PNG_FILE=${RESULT_DIR}/${BASENAME}.png
	typeset LIBRARY=''

	echo "#Library	${TITLE}" > ${DATA_FILE}
	cd "${RESULT_DIR}"
	for LIBRARY in `ls *.txt |sed -e 's/\.txt$//g'` ; do
		RESULT_FILE="${RESULT_DIR}/${LIBRARY}.txt"
		VALUE=`grep "^${MATCH}" ${RESULT_FILE} | cut -f 2 -d : | awk '{ print($1); }'`
		echo "${COUNT}	${LIBRARY}	${VALUE}" >> ${DATA_FILE}
		COUNT=$((COUNT + 1))
	done
cat <<EOF > ${PLOT_FILE}
set style fill solid border -1
set term png size 1600, 600
set boxwidth 0.4
set autoscale
set output "${PNG_FILE}"
plot "${DATA_FILE}" using 1:3:xtic(2) with boxes
EOF
	gnuplot ${PLOT_FILE}
}

function plot_results {
	plot_chart 'transactions' 'Transactions Total' 'Transactions:'
	plot_chart 'data_transferred' 'Data transferred' 'Data transferred:'
	plot_chart 'response_time' 'Avg. response time' 'Response time:'
	plot_chart 'transaction_rate' 'Transaction Rate' 'Transaction rate:'
	plot_chart 'throughput' 'Throughput' 'Throughput:'
	plot_chart 'concurrency' 'Concurrency' 'Concurrency:'
}
