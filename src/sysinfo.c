/*
 $Id$
*/

#include "main.h"
#include "util.h"
#include <unistd.h>
#include <netdb.h>
#include <sys/sysctl.h>

#ifdef HAVE_SYSFS
#define SYSFS_CLASS_DMI		"/sys/class/dmi/id"
#define SYSFS_HW_REVISION	SYSFS_CLASS_DMI "/product_version"
#define SYSFS_FW_REVISION	SYSFS_CLASS_DMI "/bios_version"
#define SYSFS_SERIAL_NO		SYSFS_CLASS_DMI "/product_serial"
#define SYSFS_MANUFACTURER	SYSFS_CLASS_DMI "/sys_vendor"
#define SYSFS_MODEL_NAME	SYSFS_CLASS_DMI "/product_name"
#endif

int sysinfo_fetch(struct sysinfo *sysinfo) {

    struct hostent *hp;
    size_t len = LLDP_INVENTORY_SIZE + 1;

#ifdef CTL_HW
    int mib[2];
    mib[0] = CTL_HW;
#endif

    // sysinfo.uts
    if (uname(&sysinfo->uts) == -1) {
	my_log(CRIT, "can't fetch uname: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    snprintf(sysinfo->uts_str, sizeof(sysinfo->uts_str), "%s %s %s %s",
	sysinfo->uts.sysname, sysinfo->uts.release,
	sysinfo->uts.version, sysinfo->uts.machine);

    if (strlen(sysinfo->uts_str) == 0) {
	my_log(CRIT, "can't create uts string: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    if ((hp = gethostbyname(sysinfo->uts.nodename)) == NULL) {
	my_log(CRIT, "cant resolve hostname: %s", hstrerror(h_errno));
	exit(EXIT_FAILURE);
    }
    strlcpy(sysinfo->hostname, hp->h_name, sizeof(sysinfo->hostname));
    free(hp);

    strlcpy(sysinfo->sw_revision, sysinfo->uts.release, len);

#ifdef HAVE_SYSFS
    read_line(SYSFS_HW_REVISION, sysinfo->hw_revision, len);
    read_line(SYSFS_FW_REVISION, sysinfo->fw_revision, len);
    read_line(SYSFS_SERIAL_NO, sysinfo->serial_number, len);
    read_line(SYSFS_MANUFACTURER, sysinfo->manufacturer, len);
    read_line(SYSFS_MODEL_NAME, sysinfo->model_name, len);
#endif

#ifdef CTL_HW
#ifdef HW_VERSION
    mib[1] = HW_VERSION;
    sysctl(mib, 2, sysinfo->hw_revision, &len, NULL, 0);
#endif
#ifdef HW_SERIALNO
    mib[1] = HW_SERIALNO;
    sysctl(mib, 2, sysinfo->serial_number, &len, NULL, 0);
#endif
#ifdef HW_VENDOR
    mib[1] = HW_VENDOR;
    sysctl(mib, 2, sysinfo->manufacturer, &len, NULL, 0);
#endif
#ifdef HW_PRODUCT
    mib[1] = HW_PRODUCT;
    sysctl(mib, 2, sysinfo->model_name, &len, NULL, 0);
#endif
#endif

    return(0);
}

