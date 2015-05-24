#!/bin/bash

if [[ $1 == '-h' ]]; then
    echo This example shows a simple POST on the /restconf/data resource. It creates the thesis-tmp user \(such user has NOT been created on the virtual machine before\). The user is then visible in the GET example. The user created is easily changed by modifying this script.
else
    curl -v -k -1 -X POST -d ' { "user" : { "name" : "thesis-tmp" } } ' -E ~/.netopeer-cli/client.pem --cacert ~/.netopeer-cli/certs/ca_rootCA.pem --capath ~/.netopeer-cli/certs/ https://127.0.0.1:8080/restconf/data/ietf-system:system/authentication/
fi
