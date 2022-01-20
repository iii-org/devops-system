#!/bin/sh
JQ=/usr/bin/jq
curl https://stedolan.github.io/jq/download/linux64/jq > $JQ && chmod +x $JQ
TOKEN=$(curl "https://auth.docker.io/token?service=registry.docker.io&scope=repository:iiiorg/devops-api:pull" | jq -r .token)
curl --head -H "Authorization: Bearer $TOKEN" https://registry-1.docker.io/v2/iiiorg/devops-api/manifests/master | grep ratelimit-remaining