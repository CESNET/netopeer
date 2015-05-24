#!/bin/bash

if [[ $1 == '-h' ]]; then
    echo This example shows a GET request on the /restconf/modules resource, but it specifies incorrect headers. A 400 should be returned. This example has the -v \(verbose\) flag set so that the supplied headers and returned status code can be seen.
else
    curl -v -H "Accept: application/yang.data+xml" -k -1 -E ~/.netopeer-cli/client.pem --cacert ~/.netopeer-cli/certs/ca_rootCA.pem --capath ~/.netopeer-cli/certs/ https://127.0.0.1:8080/restconf/modules/brgdsf
fi
