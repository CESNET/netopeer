**The single-level server is considered deprecated, should not be used and is no longer included in the _master_ branch. However, it can still be found in the _libnetconf-0.9.x_ branch.**


---


# Introduction #

As an example, we provide NETCONF server following [single-level](http://libnetconf.googlecode.com/git/doc/doxygen/html/da/db3/server.html) architecture. The source codes of this application can be found in the project Git repository inside the /server-sl/ directory. From here, we refer this server as the _Example server_.

Please note, that single-level architecture of the NETCONF servers is not very suitable for an operational use. On the other hand, this architecture is very simple and can be beneficially used for testing and debugging purposes.

As all Netopeer applications, the Example server is based on the [libnetconf](https://libnetconf.googlecode.com) library.

# Installation #

Common sequence
```
./configure && make && make install
```

which produces `netopeer-server-sl` binary and necessary toaster module files. By default, binary is installed into `/usr/local/bin/` directory and toaster module files will be located at `/var/lib/libnetconf/server/` directory. To change these locations, configure's options can be used (see `./configure --help`).

To make the Example server run as SSH Subsystem, you have to correctly [set your SSH daemon settings](SSHDaemonSettings.md).

# Usage #

When your SSH daemon is set to start the Example server as its netconf Subsystem, the Example server is launched automatically whenever an SSH session requires execution of the netconf SSH Subssytem (i.e., whenever a NETCONF client is connecting to this server).

The Example server logs its activity into the Syslog service. So, according your specific Syslog configuration, you can find these logs in Syslog's storage (usually located in `/var/log/messages`).

> _**Note:**_ If you get error like the one below (or something very similar), trying to edit configuration data, the problem is probably in NACM. For more information, see [NACM description](http://libnetconf.googlecode.com/git/doc/doxygen/html/dd/d59/nacm.html) in libnetconf documentation. The [multi-level server](MultiLevelServer.md) manages NACM using [netopeer-configurator(1)](http://netopeer.googlecode.com/git/server/configurator/netopeer-configurator.1.html).

```
NETCONF error: access-denied (application) - creating "toaster" data node is not permitted.
```

# Toaster module #

As an example, the Example server comes with the toaster module, that is loaded as a standard libnetconf transAPI module. Data model can be found at [netconf central](http://www.netconfcentral.org/modulereport/toaster)

> _**Note:**_ Here we use printings from the [Netopeer CLI](NetopeerCLI.md) to show how to interact with the Example server. Please note, that when using another NETCONF client, the user commands in such an interface can differ.

By default, the toaster service is not available. To enable the toaster service, its top-level configuration container must be created:

```
netconf> edit-config running

  Type the edit configuration data (close editor by Ctrl-D):
<toaster xmlns="http://netconfcentral.org/ns/toaster"/>
```

This is the only configuration that can be done in this module. Other operations on the toaster service are provided via its RPCs.

To perform transAPI module specific RPCs, our CLI provides `user-rpc` command. So, to start making the toast (with default settings), you can use the following command:

```
netconf> user-rpc

  Type the content of a RPC operation (close editor by Ctrl-D):
<?xml version="1.0"?>
<make-toast xmlns="http://netconfcentral.org/ns/toaster" />
```

To show a current status of the toaster service, use `get` command:

```
netconf> get --filter

  Type the filter (close editor by Ctrl-D):
<toaster xmlns="http://netconfcentral.org/ns/toaster"/>

  Result:
<toaster xmlns="http://netconfcentral.org/ns/toaster">
    <toasterManufacturer>CESNET, z.s.p.o.</toasterManufacturer>
    <toasterModelNumber>toaster</toasterModelNumber>
    <toasterStatus>up</toasterStatus>
  </toaster>
```