#define _GNU_SOURCE
#define _XOPEN_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <libnetconf_xml.h>

#include "cfginterfaces.h"
#include "config.h"

extern int callback_if_interfaces_if_interface_ip_ipv4_ip_address(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error);

/* /proc/sys/net/(ipv4,ipv6)/conf/(if_name)/(variable) = value */
static int write_to_proc_net(unsigned char ipv4, const char* if_name, const char* variable, const char* value) {
	int fd;
	char* full_path;

	asprintf(&full_path, "/proc/sys/net/%s/conf/%s/%s", (ipv4 ? "ipv4" : "ipv6"), if_name, variable);
	fd = open(full_path, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		return EXIT_FAILURE;
	}

	if (write(fd, value, strlen(value)) < strlen(value)) {
		close(fd);
		return EXIT_FAILURE;
	}
	close(fd);

	return EXIT_SUCCESS;
}

static char* read_from_proc_net(unsigned char ipv4, const char* if_name, const char* variable) {
	int fd, size;
	char* full_path, ret[64];

	asprintf(&full_path, "/proc/sys/net/%s/conf/%s/%s", (ipv4 ? "ipv4" : "ipv6"), if_name, variable);
	if ((fd = open(full_path, O_RDONLY)) == -1) {
		free(full_path);
		return NULL;
	}
	free(full_path);

	if ((size = read(fd, ret, 64)) < 1 || size == 64) {
		close(fd);
		return NULL;
	}
	close(fd);
	if (ret[size-1] == '\n') {
		ret[size-1] = '\0';
	} else {
		ret[size] = '\0';
	}

	return strdup(ret);
}

static int write_sysctl_proc_net(unsigned char ipv4, const char* if_name, const char* variable, const char* value) {
	char* content = NULL, *var_ptr = NULL, *var_dot;
	int fd = -1;
	struct stat st;

	asprintf(&var_dot, "net.%s.conf.%s.%s", (ipv4 ? "ipv4" : "ipv6"), if_name, variable);

	errno = 0;
	if (stat(SYSCTL_CONF_PATH, &st) == -1 && errno != ENOENT) {
		goto fail;
	}

	/* opening/creating sysctl.conf */
	if (errno == ENOENT) {
		if ((fd = open(SYSCTL_CONF_PATH, O_RDWR|O_CREAT|O_EXCL|00600)) == -1) {
			goto fail;
		}
	} else {
		if ((fd = open(SYSCTL_CONF_PATH, O_RDWR)) == -1) {
			goto fail;
		}
		content = malloc(st.st_size+1);
		if (read(fd, content, st.st_size) != st.st_size) {
			goto fail;
		}
		content[st.st_size] = '\0';
		if (ftruncate(fd, 0) == -1 || lseek(fd, 0, SEEK_SET) == -1) {
			goto fail;
		}
		var_ptr = strstr(content, var_dot);
	}

	/* write the content before our variable */
	if (content != NULL) {
		if (var_ptr == NULL) {
			if (write(fd, content, st.st_size) != st.st_size) {
				goto fail;
			}
			if (content[st.st_size-1] != '\n' && write(fd, "\n", 1) != 1) {
				goto fail;
			}
		} else {
			if (write(fd, content, var_ptr-content) != var_ptr-content) {
				goto fail;
			}
		}
	}

	/* write our variable */
	if (write(fd, var_dot, strlen(var_dot)) != strlen(var_dot) || write(fd, " = ", 3) != 3 ||
			write(fd, value, strlen(value)) != strlen(value) || write(fd, "\n", 1) != 1) {
		goto fail;
	}

	/* write the rest of the content */
	if (content != NULL && var_ptr != NULL && (var_ptr = strchr(var_ptr, '\n')) != NULL) {
		++var_ptr;
		if (write(fd, var_ptr, strlen(var_ptr)) != strlen(var_ptr)) {
			goto fail;
		}
	}

	free(var_dot);
	free(content);
	close(fd);

	return EXIT_SUCCESS;

fail:
	free(var_dot);
	free(content);
	if (fd != -1) {
		close(fd);
	}

	return EXIT_FAILURE;
}

/* /sys/class/net/(if_name)/(variable) */
static int write_to_sys_net(const char* if_name, const char* variable, const char* value) {
	int fd;
	char* full_path;

	asprintf(&full_path, "/sys/class/net/%s/%s", if_name, variable);
	fd = open(full_path, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		return EXIT_FAILURE;
	}

	if (write(fd, value, strlen(value)) < strlen(value)) {
		close(fd);
		return EXIT_FAILURE;
	}
	close(fd);

	return EXIT_SUCCESS;
}

static char* read_from_sys_net(const char* if_name, const char* variable) {
	int fd, size;
	char* full_path, ret[64];

	asprintf(&full_path, "/sys/class/net/%s/%s", if_name, variable);
	if ((fd = open(full_path, O_RDONLY)) == -1) {
		free(full_path);
		return NULL;
	}
	free(full_path);

	if ((size = read(fd, ret, 64)) < 1 || size == 64) {
		close(fd);
		return NULL;
	}
	close(fd);
	if (ret[size-1] == '\n') {
		ret[size-1] = '\0';
	} else {
		ret[size] = '\0';
	}

	return strdup(ret);
}

/* variables ending with the "x" suffix get a unique suffix instead,
 * other variables are rewritten if found in the file
 */
static int write_ifcfg_var(const char* if_name, const char* variable, const char* value) {
#if defined(REDHAT) || defined(SUSE)
	int fd = -1, i;
	unsigned int size;
	char* path, *content = NULL, *ptr, *tmp = NULL, *new_var = NULL;

	asprintf(&path, "%s/ifcfg-%s", IFCFG_FILES_PATH, if_name);

	if ((fd = open(path, O_RDWR)) == -1) {
		goto fail;
	}

	if ((size = lseek(fd, 0, SEEK_END)) == -1) {
		goto fail;
	}
	if (lseek(fd, 0, SEEK_SET) == -1) {
		goto fail;
	}

	content = malloc(size+10+strlen(value)+1+1);

	/* we store the whole file content */
	if (read(fd, content, size) != size) {
		goto fail;
	}
	content[size] = '\0';

	if (ftruncate(fd, 0) == -1 || lseek(fd, 0, SEEK_SET) == -1) {
		goto fail;
	}

	if (variable[strlen(variable)-1] == 'x') {
		/* generate a unique suffix */
		i = 0;
		new_var = malloc(strlen(variable)+5);
		do {
			strncpy(new_var, variable, strlen(variable)-1);
			sprintf(new_var+strlen(new_var), "%d", i);
			++i;
			ptr = strstr(content, new_var);
		} while (ptr != NULL);
	} else {
		ptr = content;
		while ((ptr = strstr(ptr, variable)) != NULL) {
			if (ptr[strlen(variable)] == '=' || ptr[strlen(variable)] == ' ') {
				break;
			}
			++ptr;
		}
	}

	/* write the stuff before the variable, if any */
	if (ptr != NULL) {
		if (write(fd, content, ptr-content) != ptr-content) {
			goto fail;
		}
		if ((ptr = strchr(ptr, '\n')) != NULL) {
			++ptr;
		}
	}

	/* write the variable and its new value */
	asprintf(&tmp, "%s=%s\n", (new_var == NULL ? variable : new_var), value);
	if (write(fd, tmp, strlen(tmp)) != strlen(tmp)) {
		goto fail;
	}

	if (ptr == NULL) {
		ptr = content;
	}

	/* either write the remaining part of the old content or the whole previous content */
	if (write(fd, ptr, strlen(ptr)) != strlen(ptr)) {
		goto fail;
	}

	close(fd);
	free(path);
	free(content);
	free(tmp);
	free(new_var);
	return EXIT_SUCCESS;

fail:
	if (fd != -1) {
		close(fd);
	}
	free(path);
	free(content);
	free(tmp);
	free(new_var);
	return EXIT_FAILURE;
#endif
}

static char* read_ifcfg_var(const char* if_name, const char* variable) {
#if defined(REDHAT) || defined(SUSE)
	int fd = -1;
	unsigned int size;
	char* path, *ptr, *ptr2, *values = NULL, *content = NULL;

	asprintf(&path, "%s/ifcfg-%s", IFCFG_FILES_PATH, if_name);

	if ((fd = open(path, O_RDONLY)) == -1) {
		goto finish;
	}

	if ((size = lseek(fd, 0, SEEK_END)) == -1) {
		goto finish;
	}
	if (lseek(fd, 0, SEEK_SET) == -1) {
		goto finish;
	}

	content = malloc((size+1)*sizeof(char));

	/* we store the whole file content */
	if (read(fd, content, size) != size) {
		goto finish;
	}
	close(fd);
	fd = -1;
	content[size] = '\0';

	ptr = content;
	while ((ptr = strstr(ptr, variable)) != NULL) {
		if (ptr[strlen(variable)] == '=' || ptr[strlen(variable)] == ' ') {
			break;
		}
		++ptr;
	}
	if (ptr == NULL) {
		goto finish;
	}

	if ((ptr = strchr(ptr, '=')) == NULL) {
		goto finish;
	}
	++ptr;
	while (*ptr == ' ') {
		++ptr;
	}

	/* cut ptr at the end of all the values */
	if (ptr[0] == '"') {
		++ptr;
		if (strchr(ptr, '"') == NULL) {
			goto finish;
		}
		*strchr(ptr, '"') = '\0';
	} else {
		ptr2 = ptr;

		while (strstr(ptr2, "\\\n") != NULL && (strchr(ptr2, '=') == NULL || strstr(ptr2, "\\\n") < strchr(ptr2, '='))) {
			ptr2 = strstr(ptr2, "\\\n")+2;
		}
		if (strchr(ptr2, '\n') != NULL) {
			*strchr(ptr2, '\n') = '\0';
		}
	}

	values = malloc((strlen(ptr)+1)*sizeof(char));
	values[0] = '\0';
	ptr2 = strtok(ptr, "\\\n");
	while (ptr2 != NULL) {
		strcat(values, ptr2);
		ptr2 = strtok(NULL, "\\\n");
	}

finish:
	if (fd != -1) {
		close(fd);
	}
	free(path);
	free(content);
	return values;
#endif
}

/* variables ending with the "x" suffix are interpreted as a regexp "*" instead of the "x" */
static int remove_ifcfg_var(const char* if_name, const char* variable, const char* value, char** suffix) {
#if defined(REDHAT) || defined(SUSE)
	int fd = -1;
	unsigned int size;
	char* path, *content = NULL, *ptr, *tmp = NULL, *new_var = NULL;

	asprintf(&path, "%s/ifcfg-%s", IFCFG_FILES_PATH, if_name);

	if ((fd = open(path, O_RDWR)) == -1) {
		goto fail;
	}

	if ((size = lseek(fd, 0, SEEK_END)) == -1) {
		goto fail;
	}
	if (lseek(fd, 0, SEEK_SET) == -1) {
		goto fail;
	}

	content = malloc(size+10+strlen(value)+1+1);

	/* we store the whole file content */
	if (read(fd, content, size) != size) {
		goto fail;
	}
	content[size] = '\0';

	if (variable[strlen(variable)-1] == 'x') {
		new_var = strndup(variable, strlen(variable)-1);
		/* find the variable with the exact same value */
		ptr = strstr(content, new_var);
		while (strncmp(strchr(ptr, '=')+1, value, strlen(value)) != 0) {
			ptr = strstr(ptr+1, new_var);
			if (ptr == NULL) {
				break;
			}
		}
	} else {
		/* find the exact variable with the exact same value */
		ptr = content;
		while ((ptr = strstr(ptr, variable)) != NULL) {
			if (ptr[strlen(variable)] == '=' || ptr[strlen(variable)] == ' ') {
				break;
			}
			++ptr;
		}
		if (ptr != NULL) {
			if (strncmp(strchr(ptr, '=')+1, value, strlen(value)) != 0) {
				ptr = NULL;
			}
		}
	}

	if (ptr == NULL) {
		/* variable was not found */
		goto fail;
	} else if (suffix != NULL) {
		/* return the found suffix */
		tmp = ptr+strlen(variable)-1;
		*suffix = strndup(tmp, strchr(tmp, '=')-tmp);
	}

	if (ftruncate(fd, 0) == -1 || lseek(fd, 0, SEEK_SET) == -1) {
		goto fail;
	}

	/* write the stuff before the variable */
	if (write(fd, content, ptr-content) != ptr-content) {
		goto fail;
	}
	if ((ptr = strchr(ptr, '\n')) != NULL) {
		++ptr;
	}

	/* write the remaining part of the content */
	if (write(fd, ptr, strlen(ptr)) != strlen(ptr)) {
		goto fail;
	}

	close(fd);
	free(path);
	free(content);
	free(tmp);
	free(new_var);

	return EXIT_SUCCESS;

fail:
	if (fd != -1) {
		close(fd);
	}
	free(path);
	free(content);
	free(tmp);
	free(new_var);

	return EXIT_FAILURE;
#endif
}

#ifdef REDHAT
static int write_ifcfg_multival_var(const char* if_name, const char* variable, const char* value) {
	int fd = -1;
	unsigned int size;
	char* path, *content = NULL, *ptr, *ptr2, *tmp = NULL;

	if ((ptr = read_ifcfg_var(if_name, variable)) != NULL && strstr(ptr, value) != NULL) {
		free(ptr);
		return EXIT_SUCCESS;
	}

	asprintf(&path, "%s/ifcfg-%s", IFCFG_FILES_PATH, if_name);

	if ((fd = open(path, O_RDWR)) == -1) {
		goto fail;
	}

	if ((size = lseek(fd, 0, SEEK_END)) == -1) {
		goto fail;
	}
	if (lseek(fd, 0, SEEK_SET) == -1) {
		goto fail;
	}

	content = malloc(size+10+strlen(value)+1+1);

	/* we store the whole file content */
	if (read(fd, content, size) != size) {
		goto fail;
	}
	content[size] = '\0';

	if (ftruncate(fd, 0) == -1 || lseek(fd, 0, SEEK_SET) == -1) {
		goto fail;
	}

	/* find the exact same variable */
	ptr = content;
	while ((ptr = strstr(ptr, variable)) != NULL) {
		if (ptr[strlen(variable)] == '=' || ptr[strlen(variable)] == ' ') {
			break;
		}
		++ptr;
	}

	/* write the stuff before the variable, if any */
	if (ptr != NULL) {
		if (write(fd, content, ptr-content) != ptr-content) {
			goto fail;
		}
	}

	/* write the variable and its new value */
	if (ptr == NULL) {
		asprintf(&tmp, "%s=%s\n", variable, value);
		if (write(fd, tmp, strlen(tmp)) != strlen(tmp)) {
			goto fail;
		}
		free(tmp);
		tmp = NULL;
		ptr = content;
	/* add the value to the variable */
	} else {
		if (strchr(ptr, '=') == NULL) {
			goto fail;
		}
		/* ptr:VARIABLE   =   values... */
		if (write(fd, ptr, (strchr(ptr, '=')+1)-ptr) != (strchr(ptr, '=')+1)-ptr) {
			goto fail;
		}

		ptr = strchr(ptr, '=')+1;
		/* ptr:    values... */

		while (*ptr == ' ') {
			++ptr;
		}
		/* ptr:values... */

		/* we need " for more values */
		if (write(fd, "\"", 1) != 1) {
			goto fail;
		}

		if (ptr[0] != '"') {
			if (strchr(ptr, '\n') == NULL) {
				tmp = strdup(ptr);
				ptr += strlen(ptr);
			} else {
				tmp = strndup(ptr, strchr(ptr, '\n')-ptr);
				ptr = strchr(ptr, '\n')+1;
			}
		} else {
			++ptr;
			if (strstr(ptr, "\"\n") == NULL) {
				goto fail;
			}
			tmp = strndup(ptr, strstr(ptr, "\"\n")-ptr);
			ptr = strstr(ptr, "\"\n")+2;
		}

		if (tmp[strlen(tmp)-1] == '"') {
			tmp[strlen(tmp)-1] = '\0';
		}

		/* tmp has all the values */
		ptr2 = strtok(tmp, " \\\n");
		while (ptr2 != NULL) {
			if (write(fd, ptr2, strlen(ptr2)) != strlen(ptr2)) {
				goto fail;
			}
			if (write(fd, " \\\n", 3) != 3) {
				goto fail;
			}
			ptr2 = strtok(NULL, " \\\n");
		}

		/* all the previous values are written now */
		if (write(fd, value, strlen(value)) != strlen(value)) {
			goto fail;
		}
		if (write(fd, "\"\n", 2) != 2) {
			goto fail;
		}

	}

	/* either write the remaining part of the old content or the whole previous content */
	if (write(fd, ptr, strlen(ptr)) != strlen(ptr)) {
		goto fail;
	}

	close(fd);
	free(path);
	free(content);
	free(tmp);
	return EXIT_SUCCESS;

fail:
	if (fd != -1) {
		close(fd);
	}
	free(path);
	free(content);
	free(tmp);
	return EXIT_FAILURE;
}

static int remove_ifcfg_multival_var(const char* if_name, const char* variable, const char* value) {
	int fd = -1;
	unsigned int size;
	char* path, *content = NULL, *ptr, *ptr2, *values = NULL;

	if ((values = read_ifcfg_var(if_name, variable)) == NULL || strstr(values, value) == NULL) {
		goto fail;
	}

	asprintf(&path, "%s/ifcfg-%s", IFCFG_FILES_PATH, if_name);
	if ((fd = open(path, O_RDWR)) == -1) {
		goto fail;
	}
	if ((size = lseek(fd, 0, SEEK_END)) == -1) {
		goto fail;
	}
	if (lseek(fd, 0, SEEK_SET) == -1) {
		goto fail;
	}

	content = malloc(size+10+strlen(value)+1+1);

	/* we store the whole file content */
	if (read(fd, content, size) != size) {
		goto fail;
	}
	content[size] = '\0';

	/* find the exact same variable */
	ptr = content;
	while ((ptr = strstr(ptr, variable)) != NULL) {
		if (ptr[strlen(variable)] == '=' || ptr[strlen(variable)] == ' ') {
			break;
		}
		++ptr;
	}
	if (ptr == NULL) {
		goto fail;
	}

	if (ftruncate(fd, 0) == -1 || lseek(fd, 0, SEEK_SET) == -1) {
		goto fail;
	}

	/* write the stuff before the variable */
	if (write(fd, content, ptr-content) != ptr-content) {
		goto fail;
	}

	/* make ptr point to the next variable */
	ptr2 = strchr(ptr, '=')+1;
	while (strstr(ptr2, "\\\n") != NULL && (strchr(ptr2, '=') == NULL || strstr(ptr2, "\\\n") < strchr(ptr2, '='))) {
		ptr2 = strstr(ptr2, "\\\n")+2;
	}
	if (strchr(ptr2, '\n') != NULL) {
		ptr = strchr(ptr2, '\n')+1;
	} else {
		ptr = ptr2+strlen(ptr2);
	}

	/* write the variable with the new content */
	if (strcmp(values, value) != 0) {
		if (write(fd, variable, strlen(variable)) != strlen(variable)) {
			goto fail;
		}
		if (write(fd, "=\"", 2) != 2) {
			goto fail;
		}

		ptr2 = strtok(values, " ");
		while (ptr2 != NULL) {
			if (write(fd, ptr2, strlen(ptr2)) != strlen(ptr2)) {
				goto fail;
			}

			if ((ptr2 = strtok(NULL, " ")) != NULL) {
				if (strcmp(ptr2, value) != 0) {
					if (write(fd, " \\\n", 3) != 3) {
						goto fail;
					}
				} else {
					ptr2 = strtok(NULL, " ");
				}
			}
		}

		if (write(fd, "\"\n", 2) != 2) {
			goto fail;
		}
	}

	/* write the remaining part of the original content */
	if (write(fd, ptr, strlen(ptr)) != strlen(ptr)) {
		goto fail;
	}

	close(fd);
	free(path);
	free(content);
	free(values);

	return EXIT_SUCCESS;

fail:
	if (fd != -1) {
		close(fd);
	}
	free(path);
	free(content);
	free(values);

	return EXIT_FAILURE;
}
#endif

/*
 * cfginterfaces.h function definitions
 */

int iface_enabled(const char* if_name, unsigned char boolean, char** msg) {
	int ret;
	char* cmd, *line = NULL;
	FILE* output;
	size_t len = 0;

	asprintf(&cmd, "ip link set dev %s %s 2>&1", if_name, (boolean ? "up" : "down"));
	output = popen(cmd, "r");
	free(cmd);

	if (output == NULL) {
		asprintf(msg, "%s: failed to execute a command.", __func__);
		return EXIT_FAILURE;
	}

	if (getline(&line, &len, output) == -1) {
		ret = EXIT_SUCCESS;
	} else {
		asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
		ret = EXIT_FAILURE;
	}

	free(line);
	pclose(output);

	/* permanent */
#ifdef REDHAT
	if (write_ifcfg_var(if_name, "ONBOOT", (boolean ? "yes" : "no")) != EXIT_SUCCESS)
#endif
#ifdef SUSE
	if (write_ifcfg_var(if_name, "STARTMODE", (boolean ? "auto" : "off")) != EXIT_SUCCESS)
#endif
	{
		asprintf(msg, "%s: failed to write to ifcfg file of %s.", __func__, if_name);
		return EXIT_FAILURE;
	}

	return ret;
}

int iface_ipv4_forwarding(const char* if_name, unsigned char boolean, char** msg) {
	if (write_to_proc_net(1, if_name, "forwarding", (boolean ? "1" : "0")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	/* permanent */
	if (write_sysctl_proc_net(1, if_name, "forwarding", (boolean ? "1" : "0")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to save permanently to sysctl.conf.", __func__, if_name);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int iface_ipv4_mtu(const char* if_name, unsigned short mtu, char** msg) {
	char str_mtu[15], *ipv6_mtu;
	unsigned int old_mtu;

	if ((ipv6_mtu = iface_get_ipv6_mtu(if_name, msg)) == NULL) {
		return EXIT_FAILURE;
	}
	old_mtu = atoi(ipv6_mtu);
	free(ipv6_mtu);

	sprintf(str_mtu, "%d", mtu);
	/* this adjusts the IPv6 MTU as well, that is why we save it first and set it afterwards */
	if (write_to_sys_net(if_name, "mtu", str_mtu) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/sys/class/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	/* permanent */
	if (write_ifcfg_var(if_name, "MTU", str_mtu) != EXIT_SUCCESS) {
		asprintf(msg, "%s: failed to write to the ifcfg file of %s.", __func__, if_name);
		return EXIT_FAILURE;
	}

	return iface_ipv6_mtu(if_name, old_mtu, msg);
}

int iface_ipv4_ip(const char* if_name, const char* ip, unsigned char prefix, XMLDIFF_OP op, char** msg) {
#ifdef REDHAT
	char* suffix = NULL, str_prefix[4];
#endif
	char* cmd, *line = NULL, *value = NULL;
	FILE* output;
	size_t len = 0;

	asprintf(&cmd, "ip addr %s %s/%d dev %s 2>&1", (op & XMLDIFF_ADD ? "add" : "del"), ip, prefix, if_name);
	output = popen(cmd, "r");
	free(cmd);

	if (output == NULL) {
		asprintf(msg, "%s: failed to execute a command.", __func__);
		return EXIT_FAILURE;
	}

	/* the IPs may not be actually set anymore, for instance on the whole "ipv4" node deletion */
	if (getline(&line, &len, output) != -1 && op & XMLDIFF_ADD) {
		asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
		free(line);
		pclose(output);
		return EXIT_FAILURE;
	}
	free(line);
	pclose(output);

	/* permanent */
#ifdef REDHAT
	if (op & XMLDIFF_ADD) {
		if (write_ifcfg_var(if_name, "IPADDRx", ip) != EXIT_SUCCESS) {
			asprintf(msg, "%s: failed to write to the ifcfg file of %s.", __func__, if_name);
			return EXIT_FAILURE;
		}
		/* let's assume the suffix will be equal to that of IPADDR, should normally be */
		sprintf(str_prefix, "%d", prefix);
		if (write_ifcfg_var(if_name, "PREFIXx", str_prefix) != EXIT_SUCCESS) {
			asprintf(msg, "%s: failed to write to the ifcfg file of %s.", __func__, if_name);
			free(value);
			return EXIT_FAILURE;
		}
		free(value);
	} else {
		if (remove_ifcfg_var(if_name, "IPADDRx", ip, &suffix) != EXIT_SUCCESS) {
			free(suffix);
			asprintf(msg, "%s: failed to remove an entry from the ifcfg file of %s.", __func__, if_name);
			return EXIT_FAILURE;
		}
		asprintf(&value, "PREFIX%s", suffix);
		free(suffix);
		if (remove_ifcfg_var(if_name, value, str_prefix, NULL) != EXIT_SUCCESS) {
			free(value);
			asprintf(msg, "%s: failed to write to the ifcfg file of %s.", __func__, if_name);
			return EXIT_FAILURE;
		}
	}
#endif
#ifdef SUSE
	asprintf(&value, "%s/%d", ip, prefix);
	if (op & XMLDIFF_ADD) {
		if (write_ifcfg_var(if_name, "IPADDRx", value) != EXIT_SUCCESS) {
			free(value);
			asprintf(msg, "%s: failed to write to the ifcfg file of %s.", __func__, if_name);
			return EXIT_FAILURE;
		}
	} else {
		if (remove_ifcfg_var(if_name, "IPADDRx", value, NULL) != EXIT_SUCCESS) {
			free(value);
			asprintf(msg, "%s: failed to remove an entry from the ifcfg file of %s.", __func__, if_name);
			return EXIT_FAILURE;
		}
	}
#endif

	free(value);
	return EXIT_SUCCESS;
}

int iface_ipv4_neighbor(const char* if_name, const char* ip, const char* mac, XMLDIFF_OP op, char** msg) {
	char* cmd = NULL, *line = NULL, *path = NULL, *content = NULL, *ptr;
	FILE* output = NULL;
	int fd = -1;
	struct stat st;
	size_t len = 0;

	asprintf(&cmd, "ip neigh %s %s lladdr %s dev %s 2>&1", (op & XMLDIFF_ADD ? "add" : "del"), ip, mac, if_name);
	output = popen(cmd, "r");

	if (output == NULL) {
		asprintf(msg, "%s: failed to execute a command.", __func__);
		goto fail;
	}

	if (getline(&line, &len, output) != -1 && op & XMLDIFF_ADD) {
		if (strstr(line, "File exists") != NULL) {
			pclose(output);
			asprintf(&cmd, "ip neigh replace %s lladdr %s dev %s 2>&1", ip, mac, if_name);
			output = popen(cmd, "r");

			if (output == NULL) {
				asprintf(msg, "%s: failed to execute a command.", __func__);
				goto fail;
			}

			if (getline(&line, &len, output) != -1) {
				asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
				goto fail;
			}
		} else {
			asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
			goto fail;
		}
	}
	free(line);
	line = NULL;
	pclose(output);
	output = NULL;

	/* permanent */

#ifdef REDHAT
	asprintf(&cmd, "if test \"$1\"=\"%s\"; then\n\tip neigh add %s lladdr %s dev %s\nfi\n", if_name, ip, mac, if_name);
	asprintf(&path, "%s", IFCFG_SCRIPTS_PATH);
#endif

#ifdef SUSE
	asprintf(&cmd, "ip neigh add %s lladdr %s dev %s\n", ip, mac, if_name);
	asprintf(&path, "%s/ifup-%s-neigh", IFCFG_SCRIPTS_PATH, if_name);
#endif

	errno = 0;
	if (stat(path, &st) == -1 && errno != ENOENT) {
		asprintf(msg, "%s: failed to stat the script \"%s\": %s", __func__, path, strerror(errno));
		goto fail;
	}

	if (op & XMLDIFF_ADD) {
#ifdef SUSE
		if (write_ifcfg_var(if_name, "POST_UP_SCRIPT", path) != EXIT_SUCCESS) {
			asprintf(msg, "%s: failed to write to the ifcfg file of %s.", __func__, if_name);
			goto fail;
		}
#endif
		/* opening/creating the script */
		if (errno == ENOENT) {
			if ((fd = open(IFCFG_SCRIPTS_PATH, O_WRONLY|O_CREAT|O_EXCL|00700)) == -1) {
				asprintf(msg, "%s: failed to create \"%s\": %s", __func__, path, strerror(errno));
				goto fail;
			}
			if (write(fd, "#! /bin/bash\n", 13) != 13) {
				asprintf(msg, "%s: failed to write to the script \"%s\": %s", __func__, path, strerror(errno));
				goto fail;
			}
		} else {
			if ((fd = open(path, O_RDWR)) == -1) {
				asprintf(msg, "%s: failed to open \"%s\": %s", __func__, path, strerror(errno));
				goto fail;
			}
			content = malloc(st.st_size+1);
			if (read(fd, content, st.st_size) != st.st_size) {
				asprintf(msg, "%s: failed to read from \"%s\": %s", __func__, path, strerror(errno));
				goto fail;
			}
			content[st.st_size] = '\0';
			if (strstr(content, cmd) != NULL) {
				asprintf(msg, "%s: duplicate neighbor entry of %s for neighbor %s - %s.", __func__, if_name, ip, mac);
				goto fail;
			}
			free(content);
			content = NULL;
		}

		/* write new content */
		if (write(fd, cmd, strlen(cmd)) != strlen(cmd)) {
			asprintf(msg, "%s: failed to write a new neighbor to the script \"%s\": %s", __func__, path, strerror(errno));
			goto fail;
		}
	} else {
		if ((fd = open(path, O_RDWR)) == -1) {
			asprintf(msg, "%s: failed to open \"%s\": %s", __func__, path, strerror(errno));
			goto fail;
		}
		content = malloc(st.st_size);
		if (read(fd, content, st.st_size) != st.st_size) {
			asprintf(msg, "%s: failed to read from \"%s\": %s", __func__, path, strerror(errno));
			goto fail;
		}
		if ((ptr = strstr(content, cmd)) == NULL) {
			asprintf(msg, "%s: missing neighbor entry to be deleted of %s for neighbor %s - %s.", __func__, if_name, ip, mac);
			goto fail;
		}
		/* removing the only entry */
		if (st.st_size == 13 + strlen(cmd)) {
			goto delete_script;
		}
		if (ftruncate(fd, 0) == -1) {
			asprintf(msg, "%s: failed to truncate the file \"%s\": %s", __func__, path, strerror(errno));
			goto fail;
		}
		if (lseek(fd, 0, SEEK_SET) == -1) {
			asprintf(msg, "%s: failed to rewinding the file \"%s\": %s", __func__, path, strerror(errno));
			goto fail;
		}
		/* write the content before our entry */
		if (write(fd, content, ptr-content) != ptr-content) {
			asprintf(msg, "%s: failed to write to the script \"%s\": %s", __func__, path, strerror(errno));
			goto fail;
		}
		/* write the content after our entry */
		if (write(fd, ptr+strlen(cmd), strlen(ptr+strlen(cmd))) != strlen(ptr+strlen(cmd))) {
			asprintf(msg, "%s: failed to write to the script \"%s\": %s", __func__, path, strerror(errno));
			goto fail;
		}
		free(content);
		content = NULL;
	}

	close(fd);
	free(cmd);
	free(path);

	return EXIT_SUCCESS;

delete_script:
	close(fd);
	fd = -1;
	free(cmd);
	cmd = NULL;
	free(content);
	content = NULL;

	if (unlink(path) == -1) {
		asprintf(msg, "%s: failed to unlink \"%s\": %s", __func__, path, strerror(errno));
		goto fail;
	}
#ifdef SUSE
	if (remove_ifcfg_var(if_name, "POST_UP_SCRIPT", path, NULL) != EXIT_SUCCESS) {
		asprintf(msg, "%s: failed to remove \"%s\" from the script \"%s\".", __func__, "POST_UP_SCRIPT", path);
		goto fail;
	}
#endif

	free(path);

	return EXIT_SUCCESS;

fail:
	free(cmd);
	free(line);
	free(path);
	free(content);
	if (output != NULL) {
		pclose(output);
	}
	if (fd != -1) {
		close(fd);
	}

	return EXIT_FAILURE;
}

/* enabled - 0 (disable), 1 (enable DHCP), 2 (enable static) */
int iface_ipv4_enabled(const char* if_name, unsigned char enabled, xmlNodePtr node, char** msg) {
	xmlNodePtr cur;
	char* cmd, *line = NULL;
	FILE* output;
	size_t len = 0;

	/* kill DHCP daemon and flush IPv4 addresses */
	if (enabled == 0 || enabled == 2) {
		asprintf(&cmd, DHCP_CLIENT_RELEASE " %s 2>&1", if_name);
		output = popen(cmd, "r");
		free(cmd);

		if (output == NULL) {
			asprintf(msg, "%s: failed to execute a command.", __func__);
			return EXIT_FAILURE;
		}

		if (getline(&line, &len, output) != -1 && strstr(line, "dhcpcd not running") == NULL) {
			asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
			free(line);
			pclose(output);
			return EXIT_FAILURE;
		}

		free(line);
		line = NULL;
		pclose(output);

		asprintf(&cmd, "ip -4 addr flush dev %s 2>&1", if_name);
		output = popen(cmd, "r");
		free(cmd);

		if (output == NULL) {
			asprintf(msg, "%s: failed to execute a command.", __func__);
			return EXIT_FAILURE;
		}

		if (getline(&line, &len, output) != -1) {
			asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
			free(line);
			pclose(output);
			return EXIT_FAILURE;
		}

		free(line);
		pclose(output);

	/* flush IPv4 addresses and enable DHCP daemon */
	} else if (enabled == 1) {
		asprintf(&cmd, "ip -4 addr flush dev %s 2>&1", if_name);
		output = popen(cmd, "r");
		free(cmd);

		if (output == NULL) {
			asprintf(msg, "%s: failed to execute a command.", __func__);
			return EXIT_FAILURE;
		}

		if (getline(&line, &len, output) != -1) {
			asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
			free(line);
			pclose(output);
			return EXIT_FAILURE;
		}

		free(line);
		line = NULL;
		pclose(output);

		asprintf(&cmd, DHCP_CLIENT_RENEW " %s 2>&1", if_name);
		output = popen(cmd, "r");
		free(cmd);

		if (output == NULL) {
			asprintf(msg, "%s: failed to execute a command.", __func__);
			return EXIT_FAILURE;
		}

		if (getline(&line, &len, output) != -1) {
			asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
			free(line);
			pclose(output);
			return EXIT_FAILURE;
		}

		free(line);
		pclose(output);
	}

	/* add all the configured static addresses */
	if (enabled == 1 || enabled == 2) {
		/* it may be NULL if the whole ipv4 node was added/removed,
		 * all the ipv4 addresses will be added/removed in their callback
		 */
		if (node != NULL) {
			for (cur = node->parent->children; cur != NULL; cur = cur->next) {
				if (cur->name == NULL) {
					continue;
				}

				if (xmlStrEqual(cur->name, BAD_CAST "address")) {
					if (callback_if_interfaces_if_interface_ip_ipv4_ip_address(NULL, XMLDIFF_ADD, cur, NULL) != EXIT_SUCCESS) {
						asprintf(msg, "%s: interface %s fail.", __func__, if_name);
						return EXIT_FAILURE;
					}
				}
			}
		}
	}

	/* permanent */
#ifdef REDHAT
	if (write_ifcfg_var(if_name, "BOOTPROTO", (enabled == 1 ? "dhcp" : "none")) != EXIT_SUCCESS)
#endif
#ifdef SUSE
	if (write_ifcfg_var(if_name, "BOOTPROTO", (enabled == 1 ? "dhcp4" : "static")) != EXIT_SUCCESS)
#endif
	{
		asprintf(msg, "%s: failed to write to the ifcfg file of %s.", __func__, if_name);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int iface_ipv6_forwarding(const char* if_name, unsigned char boolean, char** msg) {
	if (write_to_proc_net(0, if_name, "forwarding", (boolean ? "1" : "0")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	/* permanent */
	if (write_sysctl_proc_net(0, if_name, "forwarding", (boolean ? "1" : "0")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to save permanently to sysctl.conf.", __func__, if_name);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int iface_ipv6_mtu(const char* if_name, unsigned short mtu, char** msg) {
	char str_mtu[10];

	sprintf(str_mtu, "%d", mtu);
	if (write_to_proc_net(0, if_name, "mtu", str_mtu) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	/* permanent */
#ifdef REDHAT
	if (write_ifcfg_var(if_name, "IPV6_MTU", str_mtu) != EXIT_SUCCESS) {
		asprintf(msg, "%s: failed to write to the ifcfg file of %s.", __func__, if_name);
		return EXIT_FAILURE;
	}
#endif
#ifdef SUSE
	if (write_sysctl_proc_net(0, if_name, "mtu", str_mtu) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to save permanently to sysctl.conf.", __func__, if_name);
		return EXIT_FAILURE;
	}
#endif

	return EXIT_SUCCESS;
}

int iface_ipv6_ip(const char* if_name, const char* ip, unsigned char prefix, XMLDIFF_OP op, char** msg) {
#ifdef SUSE
	return iface_ipv4_ip(if_name, ip, prefix, op, msg);
#endif
#ifdef REDHAT
	char* cmd, *line = NULL, *value, *var;
	FILE* output;
	size_t len = 0;

	asprintf(&cmd, "ip addr %s %s/%d dev %s 2>&1", (op & XMLDIFF_ADD ? "add" : "del"), ip, prefix, if_name);
	output = popen(cmd, "r");
	free(cmd);

	if (output == NULL) {
		asprintf(msg, "%s: failed to execute a command.", __func__);
		return EXIT_FAILURE;
	}

	/* the IPs may not be actually set anymore, for instance on the whole "ipv6" node deletion */
	if (getline(&line, &len, output) != -1 && op & XMLDIFF_ADD) {
		asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
		free(line);
		pclose(output);
		return EXIT_FAILURE;
	}
	free(line);
	pclose(output);

	/* permanent */
	asprintf(&value, "%s/%d", ip, prefix);
	if (op & XMLDIFF_ADD) {
		var = read_ifcfg_var(if_name, "IPV6ADDR");
		if (var == NULL) {
			/* no IPV6ADDR entry, add it */
			if (write_ifcfg_var(if_name, "IPV6ADDR", value) != EXIT_SUCCESS) {
				free(value);
				asprintf(msg, "%s: failed to write to the ifcfg file of %s.", __func__, if_name);
				return EXIT_FAILURE;
			}
		} else if (strcmp(var, value) == 0) {
			/* already there */
			free(var);
		} else {
			free(var);
			/* we have an IPV6ADDR entry, add it to secondaries */
			if (write_ifcfg_multival_var(if_name, "IPV6ADDR_SECONDARIES", value) != EXIT_SUCCESS) {
				free(value);
				asprintf(msg, "%s: failed to write to the ifcfg file of %s.", __func__, if_name);
				return EXIT_FAILURE;
			}
		}
	} else {
		if (remove_ifcfg_var(if_name, "IPV6ADDR", value, NULL) == EXIT_SUCCESS) {
			/* it was the primary address, make one of the secondaries into primary, if there are any */
			if ((var = read_ifcfg_var(if_name, "IPV6ADDR_SECONDARIES")) != NULL) {
				if (strchr(var, ' ') != NULL) {
					*strchr(var, ' ') = '\0';
				}
				if (remove_ifcfg_multival_var(if_name, "IPV6ADDR_SECONDARIES", var) != EXIT_SUCCESS) {
					free(var);
					free(value);
					asprintf(msg, "%s: failed to remove an entry from the ifcfg file of %s.", __func__, if_name);
					return EXIT_FAILURE;
				}
				if (write_ifcfg_var(if_name, "IPV6ADDR", var) != EXIT_SUCCESS) {
					free(var);
					free(value);
					asprintf(msg, "%s: failed to write to the ifcfg file of %s.", __func__, if_name);
					return EXIT_FAILURE;
				}
				free(var);
			}
		} else {
			/* it is not a primary address, so just delete it from the secondaries */
			if (remove_ifcfg_multival_var(if_name, "IPV6ADDR_SECONDARIES", value) != EXIT_SUCCESS) {
				free(value);
				asprintf(msg, "%s: failed to remove an entry from the ifcfg file of %s.", __func__, if_name);
				return EXIT_FAILURE;
			}
		}
	}

	free(value);
	return EXIT_SUCCESS;
#endif
}

int iface_ipv6_neighbor(const char* if_name, const char* ip, const char* mac, XMLDIFF_OP op, char** msg) {
	return iface_ipv4_neighbor(if_name, ip, mac, op, msg);
}

int iface_ipv6_dup_addr_det(const char* if_name, unsigned int dup_addr_det, char** msg) {
	char str_dad[15];

	sprintf(str_dad, "%d", dup_addr_det);
	if (write_to_proc_net(0, if_name, "dad_transmits", str_dad) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	/* permanent */
	if (write_sysctl_proc_net(0, if_name, "dad_transmits", str_dad) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to save permanently to sysctl.conf.", __func__, if_name);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int iface_ipv6_creat_glob_addr(const char* if_name, unsigned char boolean, char** msg) {
	char* cmd, *line = NULL;
	FILE* output;
	size_t len = 0;

	if (write_to_proc_net(0, if_name, "autoconf", (boolean ? "1" : "0")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	if (!boolean) {
		asprintf(&cmd, "ip -6 addr flush dev %s scope link 2>&1", if_name);
		output = popen(cmd, "r");
		free(cmd);

		if (output == NULL) {
			asprintf(msg, "%s: failed to execute a command.", __func__);
			return EXIT_FAILURE;
		}

		if (getline(&line, &len, output) != -1) {
			asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
			free(line);
			pclose(output);
			return EXIT_FAILURE;
		}

		free(line);
		pclose(output);
	}

	/* permanent */
#ifdef REDHAT
	if (write_ifcfg_var(if_name, "IPV6_AUTOCONF", (boolean ? "yes" : "no")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: failed to write to the ifcfg file of %s.", __func__, if_name);
		return EXIT_FAILURE;
	}
#endif
#ifdef SUSE
	if (write_sysctl_proc_net(0, if_name, "autoconf", (boolean ? "1" : "0")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to save permanently to sysctl.conf.", __func__, if_name);
		return EXIT_FAILURE;
	}
#endif

	return EXIT_SUCCESS;
}

int iface_ipv6_creat_temp_addr(const char* if_name, unsigned char boolean, char** msg) {
	int ret = EXIT_SUCCESS;
	char* cmd, *line = NULL;
	FILE* output;
	size_t len = 0;

	if (write_to_proc_net(0, if_name, "use_tempaddr", (boolean ? "1" : "0")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	if (!boolean) {
		asprintf(&cmd, "ip -6 addr flush dev %s temporary 2>&1", if_name);
		output = popen(cmd, "r");
		free(cmd);

		if (output == NULL) {
			asprintf(msg, "%s: failed to execute a command.", __func__);
			return EXIT_FAILURE;
		}

		if (getline(&line, &len, output) != -1) {
			asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
			ret = EXIT_FAILURE;
		}

		free(line);
		pclose(output);
	}

	/* permanent */
	if (write_sysctl_proc_net(0, if_name, "use_tempaddr", (boolean ? "1" : "0")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to save permanently to sysctl.conf.", __func__, if_name);
		return EXIT_FAILURE;
	}

	return ret;
}

int iface_ipv6_temp_val_lft(const char* if_name, unsigned int temp_val_lft, char** msg) {
	char str_tvl[15];

	sprintf(str_tvl, "%d", temp_val_lft);
	if (write_to_proc_net(0, if_name, "temp_valid_lft", str_tvl) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	/* permanent */
	if (write_sysctl_proc_net(0, if_name, "temp_valid_lft", str_tvl) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to save permanently to sysctl.conf.", __func__, if_name);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int iface_ipv6_temp_pref_lft(const char* if_name, unsigned int temp_pref_lft, char** msg) {
	char str_tpl[15];

	sprintf(str_tpl, "%d", temp_pref_lft);
	if (write_to_proc_net(0, if_name, "temp_prefered_lft", str_tpl) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	/* permanent */
	if (write_sysctl_proc_net(0, if_name, "temp_prefered_lft", str_tpl) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to save permanently to sysctl.conf.", __func__, if_name);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int iface_ipv6_enabled(const char* if_name, unsigned char boolean, char** msg) {
	if (write_to_proc_net(0, if_name, "disable_ipv6", (boolean ? "1" : "0")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	/* permanent */
#ifdef REDHAT
	if (write_ifcfg_var(if_name, "IPV6INIT", (boolean ? "yes" : "no")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: failed to write to the ifcfg file of %s.", __func__, if_name);
		return EXIT_FAILURE;
	}
#endif
#ifdef SUSE
	if (write_sysctl_proc_net(0, if_name, "disable_ipv6", (boolean ? "1" : "0")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to save permanently to sysctl.conf.", __func__, if_name);
		return EXIT_FAILURE;
	}
#endif

	return EXIT_SUCCESS;
}

char** iface_get_ifcs(unsigned char only_managed, unsigned int* dev_count, char** msg) {
	DIR* dir;
	struct dirent* dent;
	char** ret = NULL, *path;

	if ((dir = opendir("/sys/class/net")) == NULL) {
		asprintf(msg, "%s: failed to open \"/sys/class/net\" (%s).", __func__, strerror(errno));
		return NULL;
	}

	while ((dent = readdir(dir))) {
		if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0) {
			continue;
		}

		/* check if the device is managed by ifup/down scripts */
		if (only_managed) {
			asprintf(&path, "%s/ifcfg-%s", IFCFG_FILES_PATH, dent->d_name);
			if (access(path, F_OK) == -1 && errno == ENOENT) {
				free(path);
				continue;
			}
			free(path);
		}

		/* add a device */
		if (ret == NULL) {
			*dev_count = 1;
			ret = malloc(sizeof(char*));
		} else {
			++(*dev_count);
			ret = realloc(ret, (*dev_count)*sizeof(char*));
		}
		ret[*dev_count-1] = strdup(dent->d_name);
	}
	closedir(dir);

	if (ret == NULL) {
		asprintf(msg, "%s: no network interfaces detected.", __func__);
	}

	return ret;
}

char* iface_get_type(const char* if_name, char** msg) {
	char* val;
	int num;

	if ((val = read_from_sys_net(if_name, "type")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/sys/class/net/...\".", __func__);
		return NULL;
	}

	num = atoi(val);
	free(val);
	if (num == 0 && strcmp(val, "0") != 0) {
		num = -1;
	}

	/* from linux/if_arp.h */
	switch (num) {
	case 1:
		return strdup("ethernetCsmacd");
		break;
	case 4:
		return strdup("iso88025TokenRing");
		break;
	case 7:
		return strdup("arcnet");
		break;
	case 15:
		return strdup("frDlciEndPt");
		break;
	case 19:
		return strdup("atm");
		break;
	case 24:
		return strdup("ieee1394");
		break;
	case 32:
		return strdup("infiniband");
		break;
	case 513:
		return strdup("hdlc");
		break;
	case 768:
	case 769:
		return strdup("tunnel");
		break;
	case 772:
		return strdup("softwareLoopback");
		break;
	default:
		return strdup("other");
		break;
	}

	return strdup("other");
}

char* iface_get_operstatus(const char* if_name, char** msg) {
	char* sysval;

	if ((sysval = read_from_sys_net(if_name, "operstate")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/sys/class/net/...\".", __func__);
		return NULL;
	}

	if (strcmp(sysval, "up") == 0 || strcmp(sysval, "down") == 0 || strcmp(sysval, "testing") == 0 ||
			strcmp(sysval, "unknown") == 0 || strcmp(sysval, "dormant") == 0) {
		return sysval;
	} else if (strcmp(sysval, "notpresent") == 0) {
		free(sysval);
		return strdup("not-present");
	} else if (strcmp(sysval, "lowerlayerdown") == 0) {
		free(sysval);
		return strdup("lower-layer-down");
	}

	free(sysval);
	return strdup("unknown");
}

char* iface_get_lastchange(const char* if_name, char** msg) {
	char* path;
	struct stat st;

	asprintf(&path, "/sys/class/net/%s/operstate", if_name);

	if (stat(path, &st) == -1) {
		asprintf(msg, "%s: stat on \"%s\" failed (%s).", __func__, path, strerror(errno));
		free(path);
		return NULL;
	}
	free(path);

	return nc_time2datetime(st.st_mtime, NULL);
}

char* iface_get_hwaddr(const char* if_name, char** msg) {
	char* ret;

	if ((ret = read_from_sys_net(if_name, "address")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/sys/class/net/...\".", __func__);
		return NULL;
	}

	return ret;
}

char* iface_get_speed(const char* if_name, char** msg) {
	char* ret;

	ret = read_from_sys_net(if_name, "speed");

	if (ret != NULL) {
		ret = realloc(ret, (strlen(ret)+6+1) * sizeof(char));
		strcat(ret, "000000");
	}

	return ret;
}

static unsigned int if_count = 0;
static char** if_names;
static struct device_stats* if_old_stats;

void iface_cleanup(void) {
	int i;

	for (i = 0; i < if_count; ++i) {
		free(if_names[i]);
	}

	if (if_count != 0) {
		free(if_names);
		free(if_old_stats);
	}
}

int iface_get_stats(const char* if_name, struct device_stats* stats, char** msg) {
	FILE* file;
	char* line = NULL, *ptr;
	size_t len = 0;
	char aux[16];
	int i;

	if ((file = fopen(DEV_STATS_PATH, "r")) == NULL) {
		asprintf(msg, "%s: unable to open \"%s\" (%s).", __func__, DEV_STATS_PATH, strerror(errno));
		return EXIT_FAILURE;
	}

	while (getline(&line, &len, file) != -1) {
		if (strchr(line, '|') != NULL || strchr(line, ':') == NULL) {
			continue;
		}

		ptr = line;
		while (*ptr == ' ' || *ptr == '\t') {
			++ptr;
		}

		/* we found our device */
		if (strncmp(ptr, if_name, strlen(if_name)) == 0) {
			ptr = strchr(line, ':')+1;
			sscanf(ptr, "%s %s %s %s %s %s %s %s %s %s %s %s",
				stats->in_octets,
				stats->in_pkts,
				stats->in_errors,
				stats->in_discards,
				aux, aux, aux,
				stats->in_mult_pkts,
				stats->out_octets,
				stats->out_pkts,
				stats->out_errors,
				stats->out_discards);
			free(line);
			fclose(file);

			/* find or create if_old_stats for this interface */
			if (if_count == 0) {
				if_names = malloc(sizeof(char*));
				if_names[0] = strdup(if_name);
				if_old_stats = malloc(sizeof(struct device_stats));
				if_old_stats[0].reset_time[0] = '\0';
				i = 0;
				if_count = 1;
			} else {
				for (i = 0; i < if_count; ++i) {
					if (strcmp(if_name, if_names[i]) == 0) {
						break;
					}
				}

				/* no saved stats */
				if (i == if_count) {
					if_names = realloc(if_names, (if_count+1)*sizeof(char*));
					if_names[if_count] = strdup(if_name);
					if_old_stats = realloc(if_old_stats, (if_count+1)*sizeof(struct device_stats));
					if_old_stats[if_count].reset_time[0] = '\0';
					++if_count;
				}
			}

			/* compare old stats and detect any reset */
			if (if_old_stats[i].reset_time[0] == '\0') {
				ptr = nc_time2datetime(time(NULL), NULL);
				strcpy(stats->reset_time, ptr);
				free(ptr);
			} else {
				if (strcmp(stats->in_octets, if_old_stats[i].in_octets) < 0 ||
						strcmp(stats->in_pkts, if_old_stats[i].in_pkts) < 0 ||
						strcmp(stats->in_errors, if_old_stats[i].in_errors) < 0 ||
						strcmp(stats->in_discards, if_old_stats[i].in_discards) < 0 ||
						strcmp(stats->in_mult_pkts, if_old_stats[i].in_mult_pkts) < 0 ||
						strcmp(stats->out_octets, if_old_stats[i].out_octets) < 0 ||
						strcmp(stats->out_pkts, if_old_stats[i].out_pkts) < 0 ||
						strcmp(stats->out_errors, if_old_stats[i].out_errors) < 0 ||
						strcmp(stats->out_discards, if_old_stats[i].out_discards) < 0) {
					ptr = nc_time2datetime(time(NULL), NULL);
					strcpy(stats->reset_time, ptr);
					free(ptr);
				} else {
					strcpy(stats->reset_time, if_old_stats[i].reset_time);
				}
			}
			memcpy(if_old_stats+i, stats, sizeof(struct device_stats));

			return EXIT_SUCCESS;
		}
	}

	free(line);
	fclose(file);
	return EXIT_FAILURE;
}

int iface_get_ipv4_presence(const char* if_name, char** msg) {
	int ret;
	char* cmd, *line = NULL;
	size_t len = 0;
	FILE* output;

	asprintf(&cmd, "ip -4 addr show dev %s 2>&1", if_name);
	output = popen(cmd, "r");
	free(cmd);

	if (output == NULL) {
		asprintf(msg, "%s: failed to execute a command.", __func__);
		return EXIT_FAILURE;
	}

	if (getline(&line, &len, output) == -1) {
		ret = 0;
	} else {
		ret = 1;
	}

	free(line);
	pclose(output);
	return ret;
}

char* iface_get_ipv4_enabled(const char* if_name, char** msg) {
	char* bootprot, *ret;

	bootprot = read_ifcfg_var(if_name, "BOOTPROTO");

#ifdef REDHAT
	if (bootprot == NULL || strcmp(bootprot, "none") == 0) {
		/* none seems to be the default */
		ret = strdup("true");
	} else {
		ret = strdup("false");
	}
#endif
#ifdef SUSE
	if (bootprot == NULL || strcmp(bootprot, "static") == 0) {
		/* static is the default */
		ret = strdup("true");
	} else {
		/* all the others are definitely not static */
		ret = strdup("false");
	}
#endif

	free(bootprot);
	return ret;
}

char* iface_get_ipv4_forwarding(const char* if_name, char** msg) {
	char* procval, *ret;

	if ((procval = read_from_proc_net(1, if_name, "forwarding")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	if (strcmp(procval, "0") == 0) {
		ret = strdup("false");
	} else {
		ret = strdup("true");
	}

	free(procval);
	return ret;
}

char* iface_get_ipv4_mtu(const char* if_name, char** msg) {
	char* ret;

	if ((ret = read_from_sys_net(if_name, "mtu")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/sys/class/net/...\".", __func__);
		return NULL;
	}

	return ret;
}

int iface_get_ipv4_ipaddrs(const char* if_name, struct ip_addrs* ips, char** msg) {
	char* cmd, *line = NULL, *origin, *ip, *prefix;
	FILE* output;
	size_t len = 0;

	asprintf(&cmd, "ip -4 addr show dev %s 2>&1", if_name);
	output = popen(cmd, "r");
	free(cmd);

	if (output == NULL) {
		asprintf(msg, "%s: failed to execute a command.", __func__);
		return EXIT_FAILURE;
	}

	origin = read_ifcfg_var(if_name, "BOOTPROTO");
#ifdef REDHAT
	if (origin == NULL || strcmp(origin, "none") == 0)
#endif
#ifdef SUSE
	if (origin == NULL || strcmp(origin, "static") == 0)
#endif
	{
		/* static is the default */
		free(origin);
		origin = strdup("static");
	} else if (strncmp(origin, "dhcp", 4) == 0) {
		free(origin);
		origin = strdup("dhcp");
	} else {
		free(origin);
		origin = strdup("other");
	}

	while (getline(&line, &len, output) != -1) {
		if ((ip = strstr(line, "inet")) == NULL) {
			continue;
		}

		ip += 5;
		prefix = strchr(ip, '/')+1;
		*strchr(ip, '/') = '\0';
		*strchr(prefix, ' ') = '\0';

		/* add a new IP */
		if (ips->count == 0) {
			ips->ip = malloc(sizeof(char*));
			ips->prefix_or_mac = malloc(sizeof(char*));
			ips->origin = malloc(sizeof(char*));
		} else {
			ips->ip = realloc(ips->ip, (ips->count+1)*sizeof(char*));
			ips->prefix_or_mac = realloc(ips->prefix_or_mac, (ips->count+1)*sizeof(char*));
			ips->origin = realloc(ips->origin, (ips->count+1)*sizeof(char*));
		}

		ips->ip[ips->count] = strdup(ip);
		ips->prefix_or_mac[ips->count] = strdup(prefix);
		if (strncmp(ip, "169.254", 7) == 0) {
			ips->origin[ips->count] = strdup("random");
		} else {
			ips->origin[ips->count] = strdup(origin);
		}
		++ips->count;
	}

	free(origin);
	free(line);
	pclose(output);
	return EXIT_SUCCESS;
}

int iface_get_ipv4_neighs(const char* if_name, struct ip_addrs* ips, struct ip_addrs* neighs, char** msg) {
	int i;
	char* cmd, *line = NULL, *ip, *mac;
	FILE* output;
	size_t len = 0;

	asprintf(&cmd, "ip -4 neigh show dev %s 2>&1", if_name);
	output = popen(cmd, "r");
	free(cmd);

	if (output == NULL) {
		asprintf(msg, "%s: failed to execute a command.", __func__);
		return EXIT_FAILURE;
	}

	while (getline(&line, &len, output) != -1) {
		ip = strtok(line, " \n");
		mac = strtok(NULL, " \n");
		if (strcmp(mac, "lladdr") == 0) {
			mac = strtok(NULL, " \n");
		} else {
			/* FAILED neighbor, ignore */
			continue;
		}

		/* add a new IP */
		if (ips->count == 0) {
			ips->ip = malloc(sizeof(char*));
			ips->prefix_or_mac = malloc(sizeof(char*));
			ips->origin = malloc(sizeof(char*));
		} else {
			ips->ip = realloc(ips->ip, (ips->count+1)*sizeof(char*));
			ips->prefix_or_mac = realloc(ips->prefix_or_mac, (ips->count+1)*sizeof(char*));
			ips->origin = realloc(ips->origin, (ips->count+1)*sizeof(char*));
		}

		ips->ip[ips->count] = strdup(ip);
		ips->prefix_or_mac[ips->count] = strdup(mac);
		ips->origin[ips->count] = NULL;
		for (i = 0; i < neighs->count; ++i) {
			if (strcmp(ip, neighs->ip[i]) == 0 && strcmp(mac, neighs->prefix_or_mac[i]) == 0) {
				ips->origin[ips->count] = strdup("static");
			}
		}
		if (ips->origin[ips->count] == NULL) {
			ips->origin[ips->count] = strdup("dynamic");
		}
		++ips->count;
	}

	free(line);
	pclose(output);
	return EXIT_SUCCESS;
}

int iface_get_ipv6_presence(const char* if_name, char** msg) {
	int ret;
	char* procval;

	if ((procval = read_from_proc_net(0, if_name, "disable_ipv6")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return -1;
	}

	if (strcmp(procval, "0") == 0) {
		ret = 1;
	} else {
		ret = 0;
	}

	free(procval);
	return ret;
}

char* iface_get_ipv6_forwarding(const char* if_name, char** msg) {
	char* procval, *ret;

	if ((procval = read_from_proc_net(0, if_name, "forwarding")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	if (strcmp(procval, "0") == 0) {
		ret = strdup("false");
	} else {
		ret = strdup("true");
	}

	free(procval);
	return ret;
}

char* iface_get_ipv6_mtu(const char* if_name, char** msg) {
	char* ret;

	if ((ret = read_from_proc_net(0, if_name, "mtu")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	return ret;
}

int iface_get_ipv6_ipaddrs(const char* if_name, struct ip_addrs* ips, char** msg) {
	char* cmd, *line = NULL, *origin, *ip, *prefix, *rest;
	FILE* output;
	size_t len = 0;

	asprintf(&cmd, "ip -6 addr show dev %s 2>&1", if_name);
	output = popen(cmd, "r");
	free(cmd);

	if (output == NULL) {
		asprintf(msg, "%s: failed to execute a command.", __func__);
		return EXIT_FAILURE;
	}

	origin = read_ifcfg_var(if_name, "BOOTPROTO");
#ifdef REDHAT
	if (origin == NULL || strcmp(origin, "none") == 0)
#endif
#ifdef SUSE
	if (origin == NULL || strcmp(origin, "static") == 0)
#endif
	{
		/* static is the default */
		free(origin);
		origin = strdup("static");
	} else if (strncmp(origin, "dhcp", 4) == 0) {
		free(origin);
		origin = strdup("dhcp");
	} else {
		free(origin);
		origin = strdup("other");
	}

	while (getline(&line, &len, output) != -1) {
		if ((ip = strstr(line, "inet6")) == NULL) {
			continue;
		}

		ip += 6;
		prefix = strchr(ip, '/')+1;
		rest = strchr(prefix, ' ')+1;
		*strchr(ip, '/') = '\0';
		*strchr(prefix, ' ') = '\0';

		/* add a new IP */
		if (ips->count == 0) {
			ips->ip = malloc(sizeof(char*));
			ips->prefix_or_mac = malloc(sizeof(char*));
			ips->origin = malloc(sizeof(char*));
			ips->status_or_state = malloc(sizeof(char*));
		} else {
			ips->ip = realloc(ips->ip, (ips->count+1)*sizeof(char*));
			ips->prefix_or_mac = realloc(ips->prefix_or_mac, (ips->count+1)*sizeof(char*));
			ips->origin = realloc(ips->origin, (ips->count+1)*sizeof(char*));
			ips->status_or_state = realloc(ips->status_or_state, (ips->count+1)*sizeof(char*));
		}

		ips->ip[ips->count] = strdup(ip);
		ips->prefix_or_mac[ips->count] = strdup(prefix);
		if (strncmp(ip, "fe80:", 5) == 0 && strstr(ip, "ff:fe") != NULL) {
			ips->origin[ips->count] = strdup("link-layer");
		} else if (strstr(rest, "temporary") != NULL || strstr(rest, "dynamic") != NULL) {
			ips->origin[ips->count] = strdup("random");
		} else {
			ips->origin[ips->count] = strdup(origin);
		}
		if (strstr(rest, "deprecated") != NULL) {
			ips->status_or_state[ips->count] = strdup("deprecated");
		} else if (strstr(rest, "tentative") != NULL) {
			ips->status_or_state[ips->count] = strdup("tentative");
		} else if (strstr(rest, "dadfailed") != NULL) {
			ips->status_or_state[ips->count] = strdup("invalid");
		} else if (strstr(rest, "primary") != NULL) {
			ips->status_or_state[ips->count] = strdup("preferred");
		} else {
			ips->status_or_state[ips->count] = strdup("unknown");
		}
		++ips->count;
	}

	free(origin);
	free(line);
	pclose(output);
	return EXIT_SUCCESS;
}

int iface_get_ipv6_neighs(const char* if_name, struct ip_addrs* ips, struct ip_addrs* neighs, char** msg) {
	int i;
	char* cmd, *line = NULL, *ip, *mac, *ptr;
	FILE* output;
	size_t len = 0;

	asprintf(&cmd, "ip -6 neigh show dev %s 2>&1", if_name);
	output = popen(cmd, "r");
	free(cmd);

	if (output == NULL) {
		asprintf(msg, "%s: failed to execute a command.", __func__);
		return EXIT_FAILURE;
	}

	while (getline(&line, &len, output) != -1) {
		ip = strtok(line, " \n");
		ptr = strtok(NULL, " \n");
		if (strcmp(ptr, "lladdr") == 0) {
			mac = strtok(NULL, " \n");
			ptr = strtok(NULL, " \n");
		} else {
			/* FAILED neighbor, ignore */
			continue;
		}

		/* add a new IP */
		if (ips->count == 0) {
			ips->ip = malloc(sizeof(char*));
			ips->prefix_or_mac = malloc(sizeof(char*));
			ips->status_or_state = malloc(sizeof(char*));
			ips->origin = malloc(sizeof(char*));
			ips->is_router = malloc(sizeof(char));
		} else {
			ips->ip = realloc(ips->ip, (ips->count+1)*sizeof(char*));
			ips->prefix_or_mac = realloc(ips->prefix_or_mac, (ips->count+1)*sizeof(char*));
			ips->status_or_state = realloc(ips->status_or_state, (ips->count+1)*sizeof(char*));
			ips->origin = realloc(ips->origin, (ips->count+1)*sizeof(char*));
			ips->is_router = realloc(ips->is_router, (ips->count+1)*sizeof(char));
		}

		ips->ip[ips->count] = strdup(ip);
		ips->prefix_or_mac[ips->count] = strdup(mac);
		if (strcmp(ptr, "router") == 0) {
			ips->is_router[ips->count] = 1;
			ptr = strtok(NULL, " \n");
		} else {
			ips->is_router[ips->count] = 0;
		}
		if (strcmp(ptr, "REACHABLE") == 0 || strcmp(ptr, "NOARP") == 0 || strcmp(ptr, "PERMANENT") == 0) {
			ips->status_or_state[ips->count] = strdup("reachable");
		} else if (strcmp(ptr, "STALE") == 0) {
			ips->status_or_state[ips->count] = strdup("stale");
		} else if (strcmp(ptr, "DELAY") == 0) {
			ips->status_or_state[ips->count] = strdup("delay");
		} else if (strcmp(ptr, "PROBE") == 0) {
			ips->status_or_state[ips->count] = strdup("probe");
		} else {
			ips->status_or_state[ips->count] = strdup("incomplete");
		}
		ips->origin[ips->count] = NULL;
		for (i = 0; i < neighs->count; ++i) {
			if (strcmp(ip, neighs->ip[i]) == 0 && strcmp(mac, neighs->prefix_or_mac[i]) == 0) {
				ips->origin[ips->count] = strdup("static");
			}
		}
		if (ips->origin[ips->count] == NULL) {
			ips->origin[ips->count] = strdup("dynamic");
		}
		++ips->count;
	}

	free(line);
	pclose(output);
	return EXIT_SUCCESS;
}

char* iface_get_enabled(const char* if_name, char** msg) {
	char* cmd, *line = NULL, *ptr = NULL;
	FILE* output;
	size_t len = 0;

	asprintf(&cmd, "ip link show %s 2>&1", if_name);
	output = popen(cmd, "r");
	free(cmd);

	if (output == NULL) {
		asprintf(msg, "%s: failed to execute a command.", __func__);
		return NULL;
	}

	if (getline(&line, &len, output) != -1 && (ptr = strstr(line, "state")) != NULL) {
		ptr += 6;
		*strchr(ptr, ' ') = '\0';
		if (strcmp(ptr, "UP") == 0) {
			ptr = strdup("true");
		} else if (strcmp(ptr, "DOWN") == 0) {
			ptr = strdup("false");
		} else if (strcmp(ptr, "UNKNOWN") == 0 && strncmp(if_name, "lo", 2) == 0) {
			ptr = strdup("true");
		} else {
			asprintf(msg, "%s: unknown interface %s state \"%s\".", __func__, if_name, ptr);
			ptr = NULL;
		}
	} else {
		asprintf(msg, "%s: could not retrieve interface %s state.", __func__, if_name);
	}

	free(line);
	pclose(output);
	return ptr;
}

char* iface_get_ipv6_dup_addr_det(const char* if_name, char** msg) {
	char *ret;

	if ((ret = read_from_proc_net(0, if_name, "dad_transmits")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	return ret;
}

char* iface_get_ipv6_creat_glob_addr(const char* if_name, char** msg) {
	char* glob_addr, *ret;

	if ((glob_addr = read_from_proc_net(0, if_name, "autoconf")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	if (strcmp(glob_addr, "0") == 0) {
		ret = strdup("false");
	} else {
		ret = strdup("true");
	}
	free(glob_addr);

	return ret;
}

char* iface_get_ipv6_creat_temp_addr(const char* if_name, char** msg) {
	char* temp_addr, *ret;

	if ((temp_addr = read_from_proc_net(0, if_name, "use_tempaddr")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	if (strcmp(temp_addr, "0") == 0) {
		ret = strdup("false");
	} else {
		ret = strdup("true");
	}
	free(temp_addr);

	return ret;
}

char* iface_get_ipv6_temp_val_lft(const char* if_name, char** msg) {
	char *ret;

	if ((ret = read_from_proc_net(0, if_name, "temp_valid_lft")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	return ret;
}

char* iface_get_ipv6_temp_pref_lft(const char* if_name, char** msg) {
	char *ret;

	if ((ret = read_from_proc_net(0, if_name, "temp_prefered_lft")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	return ret;
}
