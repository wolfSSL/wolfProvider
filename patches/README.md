This patch replaces the openssl default provider with wolfProvider. This means 
wolfProvider will be registered under the name "default" and any attempts
to fetch the default provider will yield wolfProvider instead. This patch
works for all versions of openssl > 3.0
