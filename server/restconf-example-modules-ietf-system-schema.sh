#!/bin/bash

if [[ $1 == '-h' ]]; then
    echo This example shows a simple GET on the /restconf/modules/ietf-system/schema resource which returns the ietf-system schema.
else
    curl -H "Accept: application/yang" -k -1 -E ~/.netopeer-cli/client.pem --cacert ~/.netopeer-cli/certs/ca_rootCA.pem --capath ~/.netopeer-cli/certs/ https://127.0.0.1:8080/restconf/modules/module/ietf-system/schema
fi
