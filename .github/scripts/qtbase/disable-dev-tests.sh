#!/bin/bash

# This script creates the BLACKLIST file for the 'dev' Qt branch.

cat << EOF > tests/auto/network/ssl/qsslsocket/BLACKLIST
[connectToHostEncrypted:WithoutProxy]
ci
[connectToHostEncryptedWithVerificationPeerName:WithoutProxy]
ci
[sessionCipher:WithoutProxy]
ci
[sessionCipher:WithSocks5Proxy]
ci
[sessionCipher:WithSocks5ProxyAuth]
ci
[sessionCipher:WithHttpProxy]
ci
[sessionCipher:WithHttpProxyBasicAuth]
ci
[protocol:WithoutProxy]
ci
[setSslConfiguration:WithoutProxy:set-root-cert]
ci
[setSslConfiguration:WithoutProxy:secure]
ci
[verifyMode:WithoutProxy]
ci
[resetProxy:WithoutProxy]
ci
[readFromClosedSocket:WithoutProxy]
ci
[forwardReadChannelFinished:WithoutProxy]
ci
EOF

