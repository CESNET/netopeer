Netopeer is a set of NETCONF tools built on the [libnetconf](https://libnetconf.googlecode.com) library. It allows operators to connect to their NETCONF-enabled devices as well as developers to allow control their devices via NETCONF. More information about NETCONF protocol can be found at [NETCONF WG](http://trac.tools.ietf.org/wg/netconf/trac/wiki).

&lt;wiki:gadget url="https://www.ohloh.net/p/315997/widgets/project\_factoids\_stats.xml" height="270" width="800" border="0"/&gt;

## Tools Overview ##

![http://wiki.netopeer.googlecode.com/git/new_netopeer_arch.png](http://wiki.netopeer.googlecode.com/git/new_netopeer_arch.png)

### netopeer-cli ###
CLI interface allowing user to connect to a NETCONF-enabled device and to obtain and manipulate its configuration data.

#### Man Pages ####
  * [netopeer-cli(1)](http://netopeer.googlecode.com/git/cli/doc/netopeer-cli.1.html)

### netopeer-server ###
The main Netopeer server following the [integrated architecture](http://libnetconf.googlecode.com/git/doc/doxygen/html/da/db3/server.html#server-arch-integrated). **netopeer-server** is supposed to run as a system service controlling a device. By default, we provide example modules to control several areas of a GNU/Linux desktop (network interfaces, packet filter and overall system information). The **netopeer-server** allows you to simply switch the modules to use your own control modules.

As part of the Netopeer server, there is a set of the following tools:
  * **netopeer-server** as the main service daemon integrating the SSH/TLS server.
  * **netopeer-manager** as a tool to manage the **netopeer-server**'s modules.
  * **netopeer-configurator** as a tool for the server first run configuration.

#### Man Pages ####
  * [netopeer-server(8)](http://netopeer.googlecode.com/git/server/netopeer-server.8.html)
  * [netopeer-manager(1)](http://netopeer.googlecode.com/git/server/manager/netopeer-manager.1.html)
  * [netopeer-configurator(1)](http://netopeer.googlecode.com/git/server/configurator/netopeer-configurator.1.html)

### TransAPI modules ###

Netopeer projects provides several basic transAPI modules that, besides their functionality, serve as examples for writing the libnetconf transAPI modules. These modules are located inside the transAPI/ directory.

#### [cfgsystem](cfgsystem.md) ####

TransAPI module implementing ietf-system data model following <a href='http://tools.ietf.org/html/rfc7317'>RFC 7317</a>.


### Netopeer GUI ###
The Apache module with a web-based GUI allowing user to connect to a NETCONF-enabled device and to obtain and manipulate its configuration data from a graphical interface.

This part is available as a standalone project at [GitHub](https://github.com/CESNET/Netopeer-GUI).


## Interoperability ##

In November 2012, prior to the IETF 85 meeting, some of these tools were participating in [NETCONF Interoperability Testing](http://www.internetsociety.org/articles/successful-netconf-interoperability-testing-announced-ietf-85).

All tools are built on top of the libnetconf library and allows you to use the following NETCONF features:

  * NETCONF v1.0 and v1.1 compliant ([RFC 6241](http://tools.ietf.org/html/rfc6241))
  * NETCONF over SSH ([RFC 6242](http://tools.ietf.org/html/rfc6242)) including Chunked Framing Mechanism
  * NETCONF over TLS ([RFC 5539bis](http://tools.ietf.org/html/draft-ietf-netconf-rfc5539bis-05))
  * NETCONF Writable-running capability ([RFC 6241](http://tools.ietf.org/html/rfc6241))
  * NETCONF Candidate configuration capability ([RFC 6241](http://tools.ietf.org/html/rfc6241))
  * NETCONF Validate capability ([RFC 6241](http://tools.ietf.org/html/rfc6241))
  * NETCONF Distinct startup capability ([RFC 6241](http://tools.ietf.org/html/rfc6241))
  * NETCONF URL capability ([RFC 6241](http://tools.ietf.org/html/rfc6241))
  * NETCONF Event Notifications ([RFC 5277](http://tools.ietf.org/html/rfc5277) and [RFC 6470](http://tools.ietf.org/html/rfc6470))
  * NETCONF With-defaults capability ([RFC 6243](http://tools.ietf.org/html/rfc6243))
  * NETCONF Access Control ([RFC 6536](http://tools.ietf.org/html/rfc6536))
  * NETCONF Call Home ([Reverse SSH draft](http://tools.ietf.org/html/draft-ietf-netconf-reverse-ssh-05), [RFC 5539bis](http://tools.ietf.org/html/draft-ietf-netconf-rfc5539bis-05))
  * NETCONF Server Configuration ([IETF Draft](http://tools.ietf.org/html/draft-kwatsen-netconf-server-01))