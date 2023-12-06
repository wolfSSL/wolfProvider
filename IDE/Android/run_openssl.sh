RUNDIR=/data/local/tmp/
export LD_LIBRARY_PATH=${RUNDIR}:${RUNDIR}/openssl-install/lib
export OPENSSL_MODULES=${RUNDIR}
export OPENSSL_CONF=${RUNDIR}/provider.conf
${RUNDIR}/openssl-install/bin/openssl list -provider-path ${RUNDIR} -providers -verbose
#${RUNDIR}/openssl-install/bin/openssl help list

${RUNDIR}/openssl_example
