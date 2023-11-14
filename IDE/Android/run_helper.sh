RUNDIR=/data/local/tmp/
export LD_LIBRARY_PATH=${RUNDIR}:${RUNDIR}/openssl-install/lib
export OPENSSL_MODULES=${RUNDIR}
export OPENSSL_CONF=${RUNDIR}/provider.conf
${RUNDIR}/openssl-install/bin/openssl list -provider-path ${RUNDIR} -providers -verbose
#${RUNDIR}/openssl-install/bin/openssl help list

EVP_TESTS=(
#    evpciph_aes_ccm_cavs.txt
#    evpciph_aes_common.txt
    evpciph_aes_wrap.txt
    evpencod.txt
    evpkdf_hkdf.txt
    evpkdf_pbkdf2.txt
    evpkdf_tls11_prf.txt
    evpkdf_tls12_prf.txt
    evpkdf_tls13_kdf.txt
#    evpmac_common.txt
    evpmd_md.txt
    evpmd_sha.txt
    evppbe_pbkdf2.txt
    evppbe_pkcs12.txt
#    evppkey_dh.txt
#    evppkey_ecc.txt
#    evppkey_ecdh.txt
#    evppkey_ecdsa.txt
#    evppkey_ecx.txt
#    evppkey_ffdhe.txt
#    evppkey_kas.txt
    evppkey_kdf_hkdf.txt
    evppkey_kdf_tls1_prf.txt
#    evppkey_mismatch.txt
#    evppkey_rsa_common.txt
#    evppkey_rsa.txt
)
for T in ${EVP_TESTS[@]}
do
    printf "\t\t$T ... "
    ${RUNDIR}/openssl/test/evp_test -config ${RUNDIR}/provider.conf \
        ${RUNDIR}/scripts/evp_test/$T \
        >$T.log 2>&1
    if [ "$?" = "0" ]; then
        echo "PASS"
    else
        echo "ERROR"
        FAIL_CNT=$((FAIL_CNT+1))
    fi
done

