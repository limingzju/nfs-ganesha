#include "config.h"

#include <assert.h>
#include "fsal.h"
#include "fsal_internal.h"
#include "FSAL/access_check.h"
#include "fsal_convert.h"
#include <unistd.h>
#include <fcntl.h>
#include "FSAL/fsal_commonlib.h"
#include "nedge_methods.h"
#include <stdbool.h>

int
nedge_fsal_up(void *args, inode_t inode, uint64_t ccow_fsio_up_flags)
{
	struct nedge_fsal_up_args *up_args = (struct nedge_fsal_up_args *) args;
	struct nedge_fsal_export *export = up_args->export;
	const struct fsal_up_vector *event_func = export->export.up_ops;
	struct nedge_file_handle fh;
	struct gsh_buffdesc key;
	int err = 0;
	fsal_status_t fsal_status;

	fh.inode = inode;
	fh.export_id = export->export_id;

	key.addr = &fh;
	key.len = nedge_sizeof_handle(&fh);

	/* [TBD] Revisit when we create clustered FSIO. */
	fsal_status = event_func->invalidate(event_func,
                                 &key,
                                 FSAL_UP_INVALIDATE_CACHE);


	if (FSAL_IS_ERROR(fsal_status))
		err = fsal_status.major;

	return err;
}

