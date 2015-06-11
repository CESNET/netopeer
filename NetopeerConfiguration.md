# Model #

The netopeer-cfgnetopeer model can be found in _netopeer/server/config/netopeer-cfgnetopeer.yang_. In this model there are several general server options and then one SSH-exclusive container and one TLS-exclusive one. They can be used only when netopeer is compiled with the support for the particular transport protocol. Every node includes a description, which should be read before trying to understand the following example configuration.

# Example configuration #

```
<netopeer xmlns="urn:cesnet:tmc:netopeer:1.0" xmlns:x509c2n="urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name">
 <hello-timeout>600</hello-timeout>
 <idle-timeout>3600</idle-timeout>
 <max-sessions>8</max-sessions>
 <response-time>50</response-time>
 <client-removal-time>10</client-removal-time>
 <ssh>
  <server-keys>
   <rsa-key>/etc/ssh/ssh_host_rsa_key</rsa-key>
   <dsa-key>/etc/ssh/ssh_host_dsa_key</dsa-key>
  </server-keys>
  <client-auth-keys>
   <client-auth-key>
    <path>/etc/netopeer_config/john_brown.pub</path>
    <username>jbrown</username>
   </client-auth-key>
   <client-auth-key>
    <path>/etc/netopeer_config/alice.pub</path>
    <username>admin</username>
   </client-auth-key>
  </client-auth-keys>
  <password-auth-enabled>yes</password-auth-enabled>
  <auth-attempts>3</auth-attempts>
  <auth-timeout>10</auth-timeout>
 </ssh>
 <tls>
  <server-cert>VE9QLVNFQ1JFVC1NRVNTQUdF</server-cert>
  <server-key>
   <key-data>QVZFUkFHRS1TRUNSRVQtTUVTU0FHRQ==</key-data>
   <key-type>RSA</key-type>
  </server-key>
  <trusted-ca-certs>
   <trusted-ca-cert>UFVCTElDLU1FU1NBR0U=</trusted-ca-cert>
  </trusted-ca-certs>
  <trusted-client-certs>
   <trusted-client-cert>RU1QVFktTUVTU0FHRQ==</trusted-client-cert>
  </trusted-client-certs>
  <crl-dir>/etc/crl</crl-dir>
  <cert-maps>
   <cert-to-name>
    <id>1</id>
    <fingerprint>02:E9:38:1F:F6:8B:62:AB:CD:EF:01:02:03:04:05:06:07:08:09:10:11</fingerprint>
    <map-type>x509c2n:specified</map-type>
    <name>default_ca</name>
   </cert-to-name>
   <cert-to-name>
    <id>2</id>
    <fingerprint>01:52:28:D1:67:5A:00:DE:17:07:FA:CE:F2:42:18:2D:57</fingerprint>
    <map-type>x509c2n:san-rfc822-name</map-type>
   </cert-to-name>
  </cert-maps>
 </tls>
 <modules>
  <module>
   <name>cfginterfaces</name>
   <enabled>true</enabled>
  </module>
  <module>
   <name>cfgsystem</name>
   <enabled>false</enabled>
  </module>
 </modules>
</netopeer>
```

## General settings ##

  * _hello-timeout_ - The number of seconds the server will wait for the hello message upon accepting a new connection before dropping the client.
  * _idle-timeout_ - Maximum number of seconds a client does not need to send any data before it is dropped. Client with active notification subscription will never be dropped this way.
  * _max-sessions_ - Maximum number of simultaneous sessions the server will create. After reaching this limit every new connection is immediately dropped.
  * _response-time_ - The number of miliseconds every request will usually be responded to. Lower values will increase CPU utilization, higher values the response time.
  * _client-removal-time_ - Additional number of miliseconds a request response may be postponed. At most this long will be waited for a lock needed for removing clients.

## SSH ##

  * _server-keys_ - Paths to private keys whose public counterpart will be used by clients for server verification.
  * _client-auth-key_ - If the public key presented by a client will match the one found in the path, the client must use username to pass authentication.
  * _password-auth-enabled_ - If enabled, the "password" authentication method will be advertised by the server as supported. If a client uses it, the presented username and password will be searched for a match in the locally-configured authentication method. These are usually entries found in "/etc/passwd" and "/etc/shadow".
  * _auth-attempts_ - Number of attempts a client has to successfully authenticate. The client is disconnected after reaching this limit.
  * _auth-timeout_ - Number of seconds the server will wait for the client to authenticate. Unauthenticated client connected for this long is disconnected.

## TLS ##

  * _server-cert_ - The certificate that the server sends to clients during TLS verification.
  * _server-key_ - The private key matching the server certificate.
  * _trusted-ca-cert_ - This certificate is marked as trusted and so are any certificates signed by this Certificate Authority. The certificates from the server certificate trusted CA chain must be trusted.
  * _trusted-client-cert_ - This certificate is marked as trusted and so is any client that presents this certificate as their own.
  * _crl-dir_ - The directory containing Certificate Revocation Lists of the trusted Certificate Authorities.
  * _cert-to-name_ - If the fingerprint of any certificate from a client certificate chain matches this fingerprint, this cert-to-name entry is considered a match. After that, based on the map-type value the server tries to assign a NETCONF username to this client.

## transAPI modules ##

  * _module_ - The module with name is either enabled or disabled.