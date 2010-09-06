/*
 * $Id$
 *
 * Copyright (c) 2008, 2009, 2010
 *      Sten Spans <sten@blinkenlights.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "common.h"
#include "util.h"
#include <netdb.h>
#include <paths.h>
#include <sysexits.h>
#include <sys/wait.h>
#ifdef HAVE_KENV_H
#include <kenv.h>
#endif /* HAVE_KENV_H */

#ifdef HAVE_SYSFS
#define SYSFS_CLASS_DMI		"/sys/class/dmi/id"
#define SYSFS_HW_REVISION	SYSFS_CLASS_DMI "/product_version"
#define SYSFS_FW_REVISION	SYSFS_CLASS_DMI "/bios_version"
#define SYSFS_SERIAL_NO		SYSFS_CLASS_DMI "/product_serial"
#define SYSFS_MANUFACTURER	SYSFS_CLASS_DMI "/sys_vendor"
#define SYSFS_MODEL_NAME	SYSFS_CLASS_DMI "/product_name"
#endif

#ifdef HAVE_PROC_SYS_NET
#define PROCFS_FORWARD_IPV4	"/proc/sys/net/ipv4/conf/all/forwarding"
#define PROCFS_FORWARD_IPV6	"/proc/sys/net/ipv6/conf/all/forwarding"
#endif

void sysinfo_forwarding(struct sysinfo *);

void sysinfo_fetch(struct sysinfo *sysinfo) {

    int i, ret;
    char *descr = NULL, *release, *endptr;
    struct hostent *hp;
    size_t len = LLDP_INVENTORY_SIZE + 1;

#ifdef CTL_HW
    int mib[2];
#endif

    // use lsb_release to fetch the Linux distro description
#ifdef __linux__
    int pipes[2], null, status;
    char * const cmd[] = { "lsb_release", "-s", "-d", NULL };
    pid_t pid;
    FILE *fd;
    char buf[512], *bufp;

    if (pipe(pipes) == -1)
	my_fatale("sysinfo pipe failed");

    pid = fork();

    // quit on failure
    if (pid == -1)
	my_fatale("sysinfo fork failed");

    // this is the child
    if (pid == 0) {
	if ((null = open(_PATH_DEVNULL, O_RDWR)) == -1)
	    exit(EX_OSERR);

	dup2(null, STDIN_FILENO);
	dup2(null, STDERR_FILENO);
	dup2(pipes[1], STDOUT_FILENO);
	close(pipes[1]);
	close(pipes[0]);

	if (execvp(cmd[0], cmd) == -1)
	    exit(EX_OSERR);
    }

    // this is the parent
    close(pipes[1]);
    if ((fd = fdopen(pipes[0], "r")) == NULL)
	my_fatale("sysinfo fdopen failed");

    while (fgets(buf, 512, fd)) {
	if (descr)
	    continue;

	bufp = buf;

	// remove newline
	buf[strcspn(buf, "\n")] = '\0';
	// remove redhat-style quoting
	if ((buf[0] == '"') && buf[strlen(buf) -1] == '"') {
	    buf[strlen(buf) -1] = '\0'; 
	    bufp++;
	}

	if (asprintf(&descr, "%s ", bufp) == -1)
	    my_fatal("asprintf failed");
    }
    fclose(fd);

    // dump received data if lsb_release failed
    if ((waitpid(pid, &status, 0) != pid) ||
        !WIFEXITED(status) || (WEXITSTATUS(status) != EX_OK)) {
	if (descr) {
	    free(descr);
	    descr = NULL;
	}
    }
#endif

    // sysinfo.uts
    if (uname(&sysinfo->uts) == -1)
	my_fatale("can't fetch uname");

    ret = snprintf(sysinfo->uts_str, sizeof(sysinfo->uts_str),
	    "%s%s %s %s %s", (descr)? descr: "",
	    sysinfo->uts.sysname, sysinfo->uts.release,
	    sysinfo->uts.version, sysinfo->uts.machine);
    if (ret <= 0)
	my_fatale("can't create uts string");

    if (descr) {
	ret = snprintf(sysinfo->platform, sizeof(sysinfo->platform),
		"%s%s %s", descr, sysinfo->uts.sysname, sysinfo->uts.machine);
	if (ret <= 0)
	    my_fatale("can't create platform string");
	free(descr);
    } else {
	ret = snprintf(sysinfo->platform, sizeof(sysinfo->platform),
		"%s %s %s", sysinfo->uts.sysname, sysinfo->uts.release,
		sysinfo->uts.machine);
	if (ret <= 0)
	    my_fatale("can't create platform string");
    }

    i = 0;
    endptr = release = sysinfo->uts.release;
    while ((*release != '\0') && ( i < 3)){
	sysinfo->uts_rel[i] = (uint8_t)strtol(release, &endptr, 10);

	// found one
	if (release != endptr)
	    i++;
	
	release = endptr;
	if (*release != '\0')
	    release++;
    }

    if ((hp = gethostbyname(sysinfo->uts.nodename)) == NULL)
	my_fatal("cant resolve hostname: %s", hstrerror(h_errno));
    strlcpy(sysinfo->hostname, hp->h_name, sizeof(sysinfo->hostname));

    strlcpy(sysinfo->sw_revision, sysinfo->uts.release, len);

#ifdef HAVE_SYSFS
    read_line(SYSFS_HW_REVISION, sysinfo->hw_revision, len);
    read_line(SYSFS_FW_REVISION, sysinfo->fw_revision, len);
    read_line(SYSFS_SERIAL_NO, sysinfo->serial_number, len);
    read_line(SYSFS_MANUFACTURER, sysinfo->manufacturer, len);
    read_line(SYSFS_MODEL_NAME, sysinfo->model_name, len);
#endif

    // OpenBSD really
#ifdef CTL_HW
    mib[0] = CTL_HW;

#ifdef HW_VERSION
    mib[1] = HW_VERSION;
    len = LLDP_INVENTORY_SIZE + 1;
    sysctl(mib, 2, sysinfo->hw_revision, &len, NULL, 0);
#endif
#ifdef HW_SERIALNO
    mib[1] = HW_SERIALNO;
    len = LLDP_INVENTORY_SIZE + 1;
    sysctl(mib, 2, sysinfo->serial_number, &len, NULL, 0);
#endif
#ifdef HW_VENDOR
    mib[1] = HW_VENDOR;
    len = LLDP_INVENTORY_SIZE + 1;
    sysctl(mib, 2, sysinfo->manufacturer, &len, NULL, 0);
#endif
#ifdef HW_PRODUCT
    mib[1] = HW_PRODUCT;
    len = LLDP_INVENTORY_SIZE + 1;
    sysctl(mib, 2, sysinfo->model_name, &len, NULL, 0);
#endif
#endif /* CTL_HW */

    // FreeBSD
#ifdef HAVE_KENV_H
    len = LLDP_INVENTORY_SIZE + 1;
    kenv(KENV_GET, "smbios.system.version", sysinfo->hw_revision, len);
    kenv(KENV_GET, "smbios.bios.version", sysinfo->fw_revision, len);
    kenv(KENV_GET, "smbios.system.serial", sysinfo->serial_number, len);
    kenv(KENV_GET, "smbios.system.maker", sysinfo->manufacturer, len);
    kenv(KENV_GET, "smbios.system.product", sysinfo->model_name, len);
#endif /* HAVE_KENV_H */

    // default to CAP_HOST
    sysinfo->cap = CAP_HOST;
    sysinfo->cap_active = CAP_HOST;

    // check for forwarding
    sysinfo_forwarding(sysinfo);
}


// detect forwarding capability
void sysinfo_forwarding(struct sysinfo *sysinfo) {

#ifdef HAVE_PROC_SYS_NET
    char line[256];
#endif

#ifdef CTL_NET
    int mib[4], n;
    size_t len;

    len = sizeof(n);

    mib[0] = CTL_NET;
#endif

#ifdef HAVE_PROC_SYS_NET
    if (read_line(PROCFS_FORWARD_IPV4, line, sizeof(line))) {
	sysinfo->cap |= CAP_ROUTER; 

        if (atoi(line) == 1) {
	    sysinfo->cap_active |= CAP_ROUTER; 
	    return;
	}
    }

    if (read_line(PROCFS_FORWARD_IPV6, line, sizeof(line))) {
	sysinfo->cap |= CAP_ROUTER; 

        if (atoi(line) == 1) {
	    sysinfo->cap_active |= CAP_ROUTER; 
	    return;
	}
    }
#endif

#ifdef CTL_NET
    mib[1] = PF_INET;
    mib[2] = IPPROTO_IP;
    mib[3] = IPCTL_FORWARDING;

    if (sysctl(mib, 4, &n, &len, NULL, 0) != -1) {
	sysinfo->cap |= CAP_ROUTER; 
	if (n == 1) {
	    sysinfo->cap_active |= CAP_ROUTER; 
	    return;
	}
    }

    mib[1] = PF_INET6;
    mib[2] = IPPROTO_IPV6;
    mib[3] = IPV6CTL_FORWARDING;

    if (sysctl(mib, 4, &n, &len, NULL, 0) != -1) {
	sysinfo->cap |= CAP_ROUTER; 
	if (n == 1) {
	    sysinfo->cap_active |= CAP_ROUTER; 
	    return;
	}
    }
#endif
}

