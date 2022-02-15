/*
 * Simple Software Raid - Linux header file
 */

#ifndef SSR_H_
#define SSR_H_	1

#define SSR_MAJOR	241
#define SSR_FIRST_MINOR		0
#define SSR_NUM_MINORS	1

#define PHYSICAL_DISK1_NAME		"/dev/vdb"
#define PHYSICAL_DISK2_NAME		"/dev/vdc"

/* sector size */
#define KERNEL_SECTOR_SIZE	512

/* physical partition size - 95 MB (more than this results in error) */
#define LOGICAL_DISK_NAME	"ssr"
#define LOGICAL_DISK_SIZE	(95 * 1024 * 1024)
#define LOGICAL_DISK_SECTORS	((LOGICAL_DISK_SIZE) / (KERNEL_SECTOR_SIZE))

/* sync data */
#define SSR_IOCTL_SYNC	1

/* sector trans base */
#define SECTOR_TRANS	1024
#define CRC_PAGE_ARRAY	LOGICAL_DISK_SIZE / (KERNEL_SECTOR_SIZE * SECTOR_TRANS)
#define CRC_IN_BIO	8
#define CRC_PAGE_NEED_ALIGN(cnt)     (((8 * (cnt)) / 1024) + 1)
#define CRC_SECTOR(sec)	((sec) / SECTOR_TRANS) + LOGICAL_DISK_SECTORS + 1
#endif
