#!/bin/bash
killall -9 proxylb dummy_uds_backend benchmark_cps 2>/dev/null || true
rm -f /tmp/mock_socks5.sock /tmp/proxylb_bench.sock
./target/release/dummy_uds_backend /tmp/mock_socks5.sock > /dev/null 2>&1 &
sleep 1

./target/release/proxylb -c ./bench/bench_config.yaml --log-level info > bench.log 2>&1 &
PROXYLB_PID=$!
sleep 3

echo "Running benchmark..."
./target/release/benchmark_cps \
    --proxy-uds /tmp/proxylb_bench.sock \
    --target-host 127.0.0.1 --target-port 10800 \
    --concurrency 300 --duration 10 --random-domains

echo "Killing proxylb..."
kill -9 $PROXYLB_PID
sleep 1
killall -9 dummy_uds_backend 2>/dev/null || true
echo "Done"
