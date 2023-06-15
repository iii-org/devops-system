#!/bin/sh

set -e

# If arguments are passed to docker, run them instead
if [ ! "$#" -gt 0 ]; then
  PYTHONPATH=/usr/src/app/apis gunicorn --worker-class eventlet -w 1 'apis.api:start_prod()' --timeout 120 --threads 1 -b 0.0.0.0:10009
fi

exec "$@"
