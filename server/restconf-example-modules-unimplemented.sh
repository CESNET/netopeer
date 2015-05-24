#!/bin/bash

if [[ $1 == '-h' ]]; then
    echo This example shows a HEAD request on the /restconf/modules resource. Since the method is unimplemented on this resource, the server returns 501.
else
    curl -I -H "Accept: application/yang.api+json" -k -1 -E ~/.netopeer-cli/client.pem --cacert ~/.netopeer-cli/certs/ca_rootCA.pem --capath ~/.netopeer-cli/certs/ https://127.0.0.1:8080/restconf/modules
fi
