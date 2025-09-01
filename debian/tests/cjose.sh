cc -O2 -o cjose_smoke cjose_smoke.c $(pkg-config --cflags --libs cjose) && \
./cjose_smoke; rm -f cjose_smoke || true
