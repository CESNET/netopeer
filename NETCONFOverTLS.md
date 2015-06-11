# Introduction #

NETCONF over TLS is almost fully implemented in netopeer according to the relevant RFC. However, many of these RFCs were still drafts or had some ambiguous parts and wordings at the time of the implementation, so it likely does not completely conform to the RFC specification. Any known deviations are mentioned in the last part of this page.

# General NETCONF TLS transport #

There are always 2 sides of a connection, the server and the client. Once an unsecure connection is established, these two entities exchange their certificates and both verify the other certificate. Based on the RFCs available at the time of the implementation (liable to change), either a standard trusted CA chain verification takes place before accepting the peer certificate or the particular presented peer certificate is already considered trustworthy and CA chain verification is not necessary. Common TLS verification is finished at this point, but in NETCONF there a few additional steps.

## server ##

Having successfully verified the client certificate, the server must somehow obtain a NETCONF username of the client to restrict their permissions accordingly. Since all the server is offered is a certificate, it must derive the username from the certificate and this process is called _cert-to-name_.

Specifics of this process can be learnt from the _netopeer-cfgnetopeer_ model and the corresponding RFC. Any configuration is also included in the model.

## client ##

Beside the aforementioned certificate verification, the client should also perform a check of the actual hostname it used to connect to a server and the one (or one from several) extracted from the server certificate. Our client does not perform this check, please refer to the last section.

# netopeer-server(8) #

After installation, **netopeer-server(8)** is configured to use example certificates for both peer verification and to present itself with. Nevertheless, the server certificate and its trusted Certificate Authority store can be fully customized using **netopeer-configurator(1)**.

Certificate Revocation Lists (CRLs) are special certificates that include a list of signed certificates by a certain CA that were for some reason revoked and are no longer considered trustworthy. Basic support for this is implemented and if correctly configured, the CRLs will be checked for client certificate revocation. However, you must manually download CRLs of your trusted Certificate Authorities and keep this list up-to-date.

cert-to-name (CTN) configuration is part of _netopeer-cfgnetopeer_ model. It includes one entry by default resolving the example client certificate to the username **default\_ca**.

# netopeer-cli(1) #

Having completed the installation, **netopeer-cli(1)** will not include any certificates. For the simplest working configuration use CLI command _cert_ to arrange for **netopeer-cli(1)** to use the example client certificate and import its example CA signer certificate, which are supplied with it.

CRL support is included in the client as well, the complete management of these certificates is accomplished by the _crl_ command.

Also, it is possible to use specific client certificate and/or trusted CA store for a single connection (ignoring the defaults) if these are supplied as arguments to the corresponding _connect_ or _listen_ commands.

# Unimplemented/skipped verification steps #

There is one step that our client does not perform during TLS verification:

**netopeer-cli(1) - Hostname check against the names in the certificate**

To accept server certificate and consider it valid, every NETCONF client should compare the hostname it used to connect to the server with the names (_commonName_ and/or _subjectAltNames_) presented in the certificate. This check is skipped in **netopeer-cli(1)**.