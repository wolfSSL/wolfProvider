#!/usr/bin/perl

# wolfProvider PQC test for the http ssl module.
#
# Exercises post-quantum TLS 1.3 through nginx backed by wolfProvider: an
# ML-DSA server certificate (FIPS 204) for authentication and ML-KEM / hybrid
# groups (FIPS 203) for key exchange. Mirrors the open-quantum-safe oqs-demos
# nginx test by connecting with each quantum-safe group and asserting the
# negotiated group, the ML-DSA peer signature, and a verified chain.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my @groups = qw/X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024 MLKEM768/;
my $sig = 'ML-DSA-65';

my $t = Test::Nginx->new()->has(qw/http http_ssl/)->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key server.key;
    ssl_certificate server.crt;

    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:MLKEM768;

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        return 200 "$ssl_curve";
    }
}

EOF

my $d = $t->testdir();

# ML-DSA certificate chain generated through wolfProvider (the default
# provider in a --replace-default build): an ML-DSA CA signing an ML-DSA
# server certificate, the oqs-demos SIG_ALG=mldsa65 arrangement.
system("openssl req -x509 -new -newkey $sig -nodes "
	. "-keyout $d/ca.key -out $d/ca.crt -subj /CN=wolfProvider-PQC-CA "
	. "-addext basicConstraints=critical,CA:TRUE "
	. "-addext keyUsage=critical,keyCertSign "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create ML-DSA CA: $!\n";

system("openssl genpkey -algorithm $sig -out $d/server.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create ML-DSA server key: $!\n";

system("openssl req -new -key $d/server.key -subj /CN=localhost "
	. "-addext subjectAltName=DNS:localhost -out $d/server.csr "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create server CSR: $!\n";

system("openssl x509 -req -in $d/server.csr -CA $d/ca.crt -CAkey $d/ca.key "
	. "-CAcreateserial -days 30 -copy_extensions copy -out $d/server.crt "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't sign server certificate: $!\n";

$t->run()->plan(scalar @groups * 3);

###############################################################################

my $p = port(8443);

foreach my $g (@groups) {
	my $out = `printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' | openssl s_client -connect 127.0.0.1:$p -groups $g -CAfile $d/ca.crt -servername localhost 2>&1`;

	like($out, qr/Negotiated TLS1.3 group: \Q$g\E/, "$g: negotiated group");
	like($out, qr/Peer signature type: mldsa65/i, "$g: ML-DSA peer signature");
	like($out, qr/Verify return code: 0 \(ok\)/, "$g: ML-DSA chain verified");
}

###############################################################################
