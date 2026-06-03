#!/bin/sh

# Start Nginx service in background
nginx

# Exec ProxyLB (replaces this process with ProxyLB, preserving signals)
exec proxylb -c config.yaml
