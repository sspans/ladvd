/*
 $Id$
*/

#include "main.h"
#include "util.h"
#include <unistd.h>
#include <netdb.h>

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

    // sysinfo.uts
    if (uname(&sysinfo->uts) == -1) {
	my_log(0, "can't fetch uname: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    asprintf(&sysinfo->uts_str, "%s %s %s %s",
	sysinfo->uts.sysname, sysinfo->uts.release,
	sysinfo->uts.version, sysinfo->uts.machine);
    if (sysinfo->uts_str == NULL) {
	my_log(0, "can't create uts string: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    if ((hp = gethostbyname(sysinfo->uts.nodename)) == NULL) {
	my_log(0, "cant resolve hostname: %s", hstrerror(h_errno));
	exit(EXIT_FAILURE);
    }
    sysinfo->hostname = hp->h_name;

    strncpy(sysinfo->sw_revision, sysinfo->uts.version, LLDP_INVENTORY_SIZE);

#ifdef HAVE_SYSFS
    read_line(SYSFS_HW_REVISION, sysinfo->hw_revision, LLDP_INVENTORY_SIZE);
    read_line(SYSFS_FW_REVISION, sysinfo->fw_revision, LLDP_INVENTORY_SIZE);
    read_line(SYSFS_SERIAL_NO, sysinfo->serial_number, LLDP_INVENTORY_SIZE);
    read_line(SYSFS_MANUFACTURER, sysinfo->manufacturer, LLDP_INVENTORY_SIZE);
    read_line(SYSFS_MODEL_NAME, sysinfo->model_name, LLDP_INVENTORY_SIZE);
#endif

    return(0);
}

