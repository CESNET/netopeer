#!/bin/bash

if [[ $1 == '-h' ]]; then
    echo This example shows a simple GET on the /restconf/data resource. No query parameters are specified - expect lots of output.
else
    curl -k -1 -E ~/.netopeer-cli/client.pem --cacert ~/.netopeer-cli/certs/ca_rootCA.pem --capath ~/.netopeer-cli/certs/ https://127.0.0.1:8080/restconf/data
fi
