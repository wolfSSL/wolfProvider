This directory contains keys used for running iperf tests. Keys were created using the flow documented in the iperf repo (see https://github.com/esnet/iperf/blob/master/docs/invoking.rst). The passkey is '1234'.

```
openssl genrsa -des3 -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
openssl rsa -in private.pem -out private_not_protected.pem -outform PEM
```

Also there is a list of authorized users in the file credentials.csv. This is verbatim from the iperf example.


