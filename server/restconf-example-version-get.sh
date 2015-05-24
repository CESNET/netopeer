#!/bin/bash

if [[ $1 == '-h' ]]; then
    echo This example shows a simple GET on the /restconf/version resource.
else
    curl -H "Accept: application/yang.api+json" -k -1 -E ~/.netopeer-cli/client.pem --cacert ~/.netopeer-cli/certs/ca_rootCA.pem --capath ~/.netopeer-cli/certs/ https://127.0.0.1:8080/restconf/version
fi
