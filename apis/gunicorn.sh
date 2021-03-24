#!/bin/sh
gunicorn --worker-class eventlet -w 2 'apis.api:start_prod()' --threads 2 -b 0.0.0.0:10009