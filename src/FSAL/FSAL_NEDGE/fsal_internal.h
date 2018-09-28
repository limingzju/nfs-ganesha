/**
 *
 * \file    fsal_internal.h
 * \date    $Date: 2006/01/24 13:45:37 $
 * \brief   Extern definitions for variables that are
 *          defined in fsal_internal.c.
 *
 */

#include  "fsal.h"
#include <ccowfsio.h>

/* linkage to the exports and handle ops initializers
 */

void nedge_export_ops_init(struct export_ops *ops);
void nedge_handle_ops_init(struct fsal_obj_ops *ops);

void NEDGEFSAL_VFS_RDLock();
void NEDGEFSAL_VFS_RDLock();
void NEDGEFSAL_VFS_Unlock();

typedef struct nedge_file_handle {
	/** Object inode */
	uint64_t inode;
	uint64_t export_id;

} nedge_file_handle_t;

/* defined the set of attributes supported with POSIX */
#define NEDGE_SUPPORTED_ATTRIBUTES ((const attrmask_t) (ATTRS_POSIX))

static inline size_t nedge_sizeof_handle(struct nedge_file_handle *hdl)
{
	return (size_t) sizeof(struct nedge_file_handle);
}

int FNEDGE_ERRMAP(int err);

/* the following variables must not be defined in fsal_internal.c */
#ifndef FSAL_INTERNAL_C

/* static filesystem info.
 * read access only.
 */
extern struct fsal_staticfsinfo_t global_fs_info;

#endif
