#ifndef WIFI_H_
#define WIFI_H_

int iface_wifi(const char* if_name, char* device, char* mode, char* ssid, char* encryption, char* key, int hidden, XMLDIFF_OP op, char** msg);

int iface_wifi_enabled(const char* device, unsigned char boolean, char** msg);

#endif