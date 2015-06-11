**This page describes SSHD configuration needed for _netopeer-server-sl_, which is deprecated, but can still be found in the _libnetconf-0.9.x_ branch.**

# Introduction #
When using netopeer-server-sl, it is needed to configure SSH daemon to cooperate with it. Here is described how to configure [OpenSSH](http://www.openssh.com/) daemon. Other SSH implementations may vary.

## Configuration ##
SSH daemon configuration file that need to be edited is typically /etc/ssh/sshd\_config (may vary on your distribution).
An SSH Subsystem must be added to configuration and it is recommended to add NETCONF over SSH port (830).

### Subsystem ###
The server-sl is designed to run as an SSH Subsystem ([RFC6242](https://tools.ietf.org/html/rfc6242)). It is needed to specify which binary should be run for SSH Subsystem called "netconf".

Add line like this to SSH daemon configuration if you are using netopeer-server-sl:
```
Subsystem netconf /path/to/netopeer-server-sl
```

### Port ###
IANA assigned the TCP port 830 as the default port for NETCONF over SSH.

You can add new Port entry with port number 830 to use SSH daemon for NETCONF as well as for remote access.
```
Port 22
Port 830
```

Or you can change the Port entry if you want to use SSH daemon for NETCONF only.
```
Port 830
```

Or you can choose to ignore the IANA recommendation and specify any port(s) you like.