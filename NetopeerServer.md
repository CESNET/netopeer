# Introduction #

Our Netopeer NETCONF server follows architecture described [here](http://libnetconf.googlecode.com/git/doc/doxygen/html/da/db3/server.html). The source codes of this application can be found in the project Git repository inside the `/server/` directory. From here, this server is referred as the _Netopeer server_.

The Netopeer server is the main part of the Netopeer project.
It uses [libnetconf](https://code.google.com/p/libnetconf/) for handling NETCONF messages and applying operations. Running in background as a system daemon, it allows centralized access to managed devices.

Netopeer server utilize libnetconf [transAPI](http://libnetconf.googlecode.com/git/doc/doxygen/html/d9/d25/transapi.html) modules to control devices (from here, referred as the _Netopeer modules_). The default module, called Netopeer, is responsible for managing other Netopeer modules specified in the Netopeer configuration data (more described below).

# Requirements #

Before compiling the source code, make sure that your system provides the following libraries or applications. Some of them are optional or can be avoided in cost of missing of some feature - see the notes for the specific item. All requirements are checked by the `configure` script.

  * compiler (_gcc_, _clang_,...) and standard headers
  * _pkg-config_
  * _libpthreads_
  * _libxml2_ (including headers from the devel package)
  * _libnetconf_ (including headers from the devel package)
  * _libssh_ (including headers from the devel package)
    * can be omitted by `--disable-ssh` configure's option. In that case the SSH transport is not supported by the server.
  * _OpenSSL_ (libssl and libcrypto including headers from the devel package)
    * only required with `--enable-tls` configure's option. In that case the TLS transport is supported by the server.
  * python 2.6 or higher with the following modules:
    * os, copy, string, re, argparse, subprocess, inspect, curses, xml, libxml2
  * roff2html
    * optional, used for building HTML version of man pages (make doc)
  * rpmbuild
    * optional, used for building RPM package (make rpm).

# Installation #

Notorious sequence
```
./configure && make && make install
```
will configure, build project and install the following binaries:
  1. [netopeer-server(8)](http://netopeer.googlecode.com/git/server/netopeer-server.8.html) - the Netopeer server
  1. [netopeer-manager(1)](http://netopeer.googlecode.com/git/server/manager/netopeer-manager.1.html) - tool used to manage the Netopeer modules
  1. [netopeer-configurator(1)](http://netopeer.googlecode.com/git/server/configurator/netopeer-configurator.1.html) - tool used for the Netopeer server first run configuration including NACM rules and SSH and/or TLS configuration, if the server supports it

# Usage #
## Managing the Netopeer modules ##
The Netopeer server needs a configuration XML file for each module with path to the .so file, paths to data models and the datastore. The data models are loaded in their order in the configuration to account for any import/augment situation. To manage the Netopeer modules, there is the **netopeer-manager(1)** tool. For more information about using this tool, see the [man page](http://netopeer.googlecode.com/git/server/manager/netopeer-manager.1.html):
```
$ man netopeer-manager
```

## First run configuration ##
Before the starting **netopeer-server(8)**, we recommend to configure it using the **netopeer-configurator(1)** tool. It takes information from the compilation process and allows you to change (or at least to show) various **netopeer-server(8)** settings.

The following subsections describes what you can change using **netopeer-configurator(1)**.

### Netopeer ###
This section shows where the Netopeer binaries were installed. Furthermore, it allows user to disable/enable the Netopeer modules added by **netopeer-manager(1)**

### NACM ###
This section covers NETCONF Access Control Module configuration. By default NACM avoids any write to the configuration data. To change this, the user can here the default write action or specify the user(s) with unlimited access. There are more configuration switches including a possibility to completely turn off the NACM.

### SSH Authentication ###
If SSH is enabled, this tab allows to specify authorized SSH public keys and the NETCONF username that will be used for each key. Public keys not included in this configuration Netopeer **refuses** by default.

### TLS Authentication ###
With the TLS support compiled in, in this tab it is possible to set basic authentication options for TLS connections. Firstly, the server certificate and private key pair can be set or removed. Without these the server cannot authenticate itself to clients and every TLS connect will **fail**. Also, all the trusted Certificate Authority certificates can be managed. Full CA chain of the server certificate **must** be trusted and included here. Finally, all the certificates can be displayed with all the standard fields shown.

## Starting the server ##
The server is started this way:
```
# netopeer-server -d
```

The _-d_ option makes the server to start in a daemon mode. You can also set logging verbosity by specifying parameter for the _-v_ option from 0 to 3 (errors, warnings, verbose, debug).

When the Netopeer server starts, it automatically initiates the Netopeer and the NETCONF-server build-in module. The former loads its startup configuration and manages all other modules added by the **netopeer-manager(1)** tool, the latter manages the communication with clients. When a module is added, it is enabled by default. To disable starting a specific module, **netopeer-configurator(1)** can be used or it can be done directly via NETCONF by modifying the Netopeer's configuration data.

**Example**: disable _my\_magic\_module_:
```
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
  <edit-config>
    <target>
      <running/>
    </target>
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <netopeer xmlns="urn:cesnet:tmc:netopeer:1.0">
        <modules>
          <module>
            <module-name>my-magic-module</module-name>
            <module-allowed xc:operation="merge">false</module-allowed>
          </module>
        </modules>
      </netopeer>
    </config>
  </edit-config>
</rpc>
```