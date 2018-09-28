#include "config.h"
#include <fcntl.h>
#include "fsal.h"
#include "FSAL/fsal_commonlib.h"
#include "fsal_convert.h"
#include "pnfs_utils.h"
#include "nfs_exports.h"
#include "sal_data.h"
#include "fsal_internal.h"
#include "nedge_methods.h"
#include "FSAL/access_check.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>

fsal_status_t
nedge_open_my_fd(struct nedge_fsal_obj_handle *objhandle,
    fsal_openflags_t openflags, int posix_flags, struct nedge_fd *my_fd)
{
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct nedge_fsal_export *export;
	int err;

	export = container_of(op_ctx->fsal_export, struct nedge_fsal_export,
	    export);

	LogFullDebug(COMPONENT_FSAL,
	    "my_fd->fd = %p openflags = %x, posix_flags = %x", my_fd->file,
	    openflags, posix_flags);

	assert(my_fd->file == NULL && my_fd->openflags == FSAL_O_CLOSED
	    && openflags != 0);

	LogFullDebug(COMPONENT_FSAL, "openflags = %x, posix_flags = %x",
	    openflags, posix_flags);

	err = FNEDGE_ERRMAP(ccow_fsio_openi(export->ci, h2inode(objhandle),
	    &my_fd->file, posix_flags));
	if (err) {
		my_fd->file = NULL;
		status = fsalstat(posix2fsal_error(err), err);
		goto out;
	}

	my_fd->openflags = openflags;

out:
	return status;
}

fsal_status_t
nedge_close_my_fd(struct nedge_fd * my_fd)
{
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	int rc = 0;

	if (my_fd->file && my_fd->openflags != FSAL_O_CLOSED) {
		rc = FNEDGE_ERRMAP(ccow_fsio_close(my_fd->file));
		if (rc != 0) {
			status = fsalstat(posix2fsal_error(rc), rc);
			LogCrit(COMPONENT_FSAL,
			    "Error : close returns with %s", strerror(rc));
		}
	} else {
		/* support_ex case, so ganesha global fd count isn't decremented */
		status = fsalstat(ERR_FSAL_NOT_OPENED, 0);
	}

	my_fd->file = NULL;
	my_fd->openflags = FSAL_O_CLOSED;

	return status;
}

fsal_status_t
nedge_close(struct fsal_obj_handle *obj_hdl)
{
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct nedge_fsal_obj_handle *handle;

	handle = container_of(obj_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);

	assert(obj_hdl->type == REGULAR_FILE);

	/*
	 * Take write lock on object to protect file descriptor.
	 * * This can block over an I/O operation.
	 */
	PTHREAD_RWLOCK_wrlock(&obj_hdl->obj_lock);

	status = nedge_close_my_fd(&handle->globalfd);

	PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);

	return status;
}

fsal_status_t
nedge_open_func(struct fsal_obj_handle * obj_hdl, fsal_openflags_t openflags,
    struct fsal_fd * fd)
{
	struct nedge_fsal_obj_handle *myself;
	int posix_flags = 0;

	myself = container_of(obj_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);

	fsal2posix_openflags(openflags, &posix_flags);

	return nedge_open_my_fd(myself, openflags, posix_flags,
	    (struct nedge_fd *) fd);
}

fsal_status_t
nedge_close_func(struct fsal_obj_handle *obj_hdl, struct fsal_fd *fd)
{
	return nedge_close_my_fd((struct nedge_fd *) fd);
}

fsal_status_t
find_fd(struct nedge_fd *my_fd, struct fsal_obj_handle *obj_hdl, bool bypass,
    struct state_t *state, fsal_openflags_t openflags, bool * has_lock,
    bool * closefd, bool open_for_locks)
{
	struct nedge_fsal_obj_handle *myself;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	struct nedge_fd tmp_fd = { 0 }, *tmp2_fd = &tmp_fd;
	bool reusing_open_state_fd = false;

	myself = container_of(obj_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);

	/*
	 * Handle only regular files
	 */
	if (obj_hdl->type != REGULAR_FILE)
		return fsalstat(posix2fsal_error(EINVAL), EINVAL);

	status = fsal_find_fd((struct fsal_fd **) &tmp2_fd, obj_hdl,
	    (struct fsal_fd *) &myself->globalfd, &myself->share, bypass,
	    state, openflags, nedge_open_func, nedge_close_func, has_lock,
	    closefd, open_for_locks, &reusing_open_state_fd);

	my_fd->file = tmp2_fd->file;
	my_fd->openflags = tmp2_fd->openflags;
	return status;
}

/**
 * @brief Merge a duplicate handle with an original handle
 *
 * This function is used if an upper layer detects that a duplicate
 * object handle has been created. It allows the FSAL to merge anything
 * from the duplicate back into the original.
 *
 * The caller must release the object (the caller may have to close
 * files if the merge is unsuccessful).
 *
 * @param[in]  orig_hdl  Original handle
 * @param[in]  dupe_hdl Handle to merge into original
 *
 * @return FSAL status.
 *
 */

fsal_status_t
nedge_merge(struct fsal_obj_handle * orig_hdl,
    struct fsal_obj_handle * dupe_hdl)
{
	struct nedge_fsal_obj_handle *orig, *dupe;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };

	if (orig_hdl->type == REGULAR_FILE && dupe_hdl->type == REGULAR_FILE) {
		/*
		 * We need to merge the share reservations on this file.
		 * * This could result in ERR_FSAL_SHARE_DENIED.
		 */

		orig = container_of(orig_hdl, struct nedge_fsal_obj_handle,
		    obj_handle);
		dupe = container_of(dupe_hdl, struct nedge_fsal_obj_handle,
		    obj_handle);

		/*
		 * This can block over an I/O operation.
		 */
		PTHREAD_RWLOCK_wrlock(&orig_hdl->obj_lock);

		status = merge_share(&orig->share, &dupe->share);

		PTHREAD_RWLOCK_unlock(&orig_hdl->obj_lock);
	}

	return status;
}

static int
nedge_create(struct nedge_fsal_obj_handle *parenthandle, const char *name,
    mode_t unix_mode, int uid, int gid, inode_t *inode, struct stat *sb,
    ccow_fsio_file_t **file, int p_flags)
{
	int retval;

	retval = FNEDGE_ERRMAP(ccow_fsio_touch(parenthandle->ci,
	    h2inode(parenthandle), (char *)name, unix_mode, uid, gid, inode));
	if (retval != 0 && retval != EEXIST)
		return (retval);

	retval = FNEDGE_ERRMAP(ccow_fsio_get_file_stat(parenthandle->ci,
	    *inode, sb));
	if (retval != 0)
		return (retval);

	retval = FNEDGE_ERRMAP(ccow_fsio_openi(parenthandle->ci, *inode, file,
	    p_flags));
	if (retval != 0)
		return (retval);

	retval = FNEDGE_ERRMAP(ccow_fsio_close(*file));

	return (retval);
}

fsal_status_t
nedge_open2(struct fsal_obj_handle *obj_hdl, struct state_t *state,
    fsal_openflags_t openflags, enum fsal_create_mode createmode,
    const char *name, struct attrlist *attrib_set, fsal_verifier_t verifier,
    struct fsal_obj_handle **new_obj, struct attrlist *attrs_out,
    bool * caller_perm_check)
{
	struct nedge_fsal_obj_handle *myself, *parenthandle = NULL;
	struct nedge_fsal_export *export;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	int p_flags = 0, retval = 0;
	struct nedge_fd *my_fd = NULL, tmp_fd = { 0 };
	struct stat sb = { 0 }, stat;
	bool truncated, created = false;
	struct gsh_buffdesc fh_desc;
	ccow_fsio_file_t *file = NULL;
	nedge_file_handle_t fh;
	mode_t  unix_mode;
	inode_t inode;

	export = container_of(op_ctx->fsal_export, struct nedge_fsal_export,
	    export);
	if (state != NULL)
		my_fd = (struct nedge_fd *) (state + 1);

	fsal2posix_openflags(openflags, &p_flags);

	truncated = (p_flags & O_TRUNC) != 0;

	if (createmode >= FSAL_EXCLUSIVE) {
		/*
		 * Now fixup attrs for verifier if exclusive create
		 */
		set_common_verifier(attrib_set, verifier);
	}

	if (name == NULL) {
		/*
		 * This is an open by handle
		 */

		myself = container_of(obj_hdl, struct nedge_fsal_obj_handle,
		    obj_handle);

		if (state != NULL) {
			/*
			 * Prepare to take the share reservation, but only if we
			 * are called with a valid state (if state is NULL the
			 * caller is a stateless create such as NFS v3 CREATE).
			 */

			/*
			 * This can block over an I/O operation.
			 */
			PTHREAD_RWLOCK_wrlock(&obj_hdl->obj_lock);

			/*
			 * Check share reservation conflicts.
			 */
			status = check_share_conflict(&myself->share, openflags,
			    false);

			if (FSAL_IS_ERROR(status)) {
				PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);
				return status;
			}

			/*
			 * Take the share reservation now by updating the
			 * * counters.
			 */
			update_share_counters(&myself->share, FSAL_O_CLOSED,
			    openflags);

			PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);
		} else {
			/*
			 * We need to use the global fd to continue, and take
			 * * the lock to protect it.
			 */
			my_fd = &myself->globalfd;
			PTHREAD_RWLOCK_wrlock(&obj_hdl->obj_lock);
		}

		/*
		 * truncate is set in p_flags
		 */
		status = nedge_open_my_fd(myself, openflags, p_flags, &tmp_fd);

		if (FSAL_IS_ERROR(status)) {
			if (state == NULL) {
				/*
				 * Release the lock taken above, and return
				 * * since there is nothing to undo.
				 */
				PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);
				goto out;
			} else {
				/*
				 * Error - need to release the share
				 */
				goto undo_share;
			}
		}

		my_fd->file = tmp_fd.file;
		my_fd->openflags = tmp_fd.openflags;

		if (createmode >= FSAL_EXCLUSIVE || truncated) {
			/*
			 * Fetch the attributes to check against the
			 * * verifier in case of exclusive open/create.
			 */

			retval = FNEDGE_ERRMAP(ccow_fsio_get_file_stat(
			    myself->ci, h2inode(myself), &stat));

			if (retval == 0) {
				LogFullDebug(COMPONENT_FSAL,
				    "New size = %" PRIx64, stat.st_size);
			} else {
				status = fsalstat(posix2fsal_error(retval),
				    retval);
			}

			/*
			 * Now check verifier for exclusive, but not for
			 * * FSAL_EXCLUSIVE_9P.
			 */
			if (!FSAL_IS_ERROR(status) &&
			    createmode >= FSAL_EXCLUSIVE &&
			    createmode != FSAL_EXCLUSIVE_9P &&
			    !check_verifier_stat(&stat, verifier)) {
				/*
				 * Verifier didn't match, return EEXIST
				 */
				status = fsalstat(posix2fsal_error(EEXIST),
				    EEXIST);
			}
		}

		if (state == NULL) {
			/*
			 * If no state, release the lock taken above and return
			 * * status. If success, we haven't done any permission
			 * * check so ask the caller to do so.
			 */
			PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);
			*caller_perm_check = !FSAL_IS_ERROR(status);
			return status;
		}

		if (!FSAL_IS_ERROR(status)) {
			/*
			 * Return success. We haven't done any permission
			 * * check so ask the caller to do so.
			 */
			*caller_perm_check = true;
			return status;
		}

		(void) nedge_close_my_fd(my_fd);
undo_share:

		/*
		 * Can only get here with state not NULL and an error
		 */

		/*
		 * On error we need to release our share reservation
		 * * and undo the update of the share counters.
		 * * This can block over an I/O operation.
		 */
		PTHREAD_RWLOCK_wrlock(&obj_hdl->obj_lock);

		update_share_counters(&myself->share, openflags, FSAL_O_CLOSED);

		PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);

		return status;
	}

	/* case name_not_null */
	/*
	 * In this path where we are opening by name, we can't check share
	 * * reservation yet since we don't have an object_handle yet. If we
	 * * indeed create the object handle (there is no race with another
	 * * open by name), then there CAN NOT be a share conflict, otherwise
	 * * the share conflict will be resolved when the object handles are
	 * * merged.
	 */

	if (createmode != FSAL_NO_CREATE) {
		/*
		 * Now add in O_CREAT and O_EXCL.
		 */
		p_flags |= O_CREAT;

		/*
		 * And if we are at least FSAL_GUARDED, do an O_EXCL create.
		 */
		if (createmode >= FSAL_GUARDED)
			p_flags |= O_EXCL;

		/*
		 * Fetch the mode attribute to use.
		 */
		unix_mode = fsal2unix_mode(attrib_set->mode) &
		    ~op_ctx->fsal_export->exp_ops.fs_umask(op_ctx->
		    fsal_export);

		/*
		 * Don't set the mode if we later set the attributes
		 */
		FSAL_UNSET_MASK(attrib_set->valid_mask, ATTR_MODE);
	}

	if (createmode == FSAL_UNCHECKED && (attrib_set->valid_mask != 0)) {
		/*
		 * If we have FSAL_UNCHECKED and want to set more attributes
		 * * than the mode, we attempt an O_EXCL create first, if that
		 * * succeeds, then we will be allowed to set the additional
		 * * attributes, otherwise, we don't know we created the file
		 * * and this can NOT set the attributes.
		 */
		p_flags |= O_EXCL;
	}

	/*
	 * obtain parent directory handle
	 */
	parenthandle = container_of(obj_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);


	if (createmode == FSAL_NO_CREATE) {
		/*
		 * lookup if the object exists
		 */
		status = (obj_hdl)->obj_ops->lookup(obj_hdl, name, new_obj,
		    attrs_out);

		if (FSAL_IS_ERROR(status)) {
			*new_obj = NULL;
			goto direrr;
		}

		myself = container_of(*new_obj, struct nedge_fsal_obj_handle,
		    obj_handle);

		/*
		 * The open is not done with the caller's credentials so ask
		 * * the caller to perform a permission check.
		 */
		*caller_perm_check = true;
		goto open;
	}

	retval = nedge_create(parenthandle, name, unix_mode,
	    op_ctx->creds->caller_uid, op_ctx->creds->caller_gid, &inode, &sb,
	    &file, p_flags);

	if (file == NULL && retval == EEXIST &&
	    createmode == FSAL_UNCHECKED) {
		/*
		 * We tried to create O_EXCL to set attributes and failed.
		 * Remove O_EXCL and retry, also remember not to set attributes.
		 * We still try O_CREAT again just in case file disappears out
		 * from under us.
		 *
		 * Note that because we have dropped O_EXCL, later on we will
		 * not assume we created the file, and thus will not set
		 * additional attributes. We don't need to separately track
		 * the condition of not wanting to set attributes.
		 * XXX: O_EXCL ignored in libccowfsio yet.
		 */
		p_flags &= ~O_EXCL;
		retval = nedge_create(parenthandle, name, unix_mode,
		    op_ctx->creds->caller_uid, op_ctx->creds->caller_gid,
		    &inode, &sb, &file, p_flags);
	}

	if (retval != 0) {
		status = fsalstat(posix2fsal_error(retval), retval);
		LogWarn(COMPONENT_FSAL, "Fail to open '%s' file", name);
		goto out;
	}

	if (file== NULL) {
		status = fsalstat(posix2fsal_error(retval), retval);
		goto out;
	}

	/*
	 * Remember if we were responsible for creating the file.
	 * Note that in an UNCHECKED retry we MIGHT have re-created the
	 * file and won't remember that. Oh well, so in that rare case we
	 * leak a partially created file if we have a subsequent error in here.
	 * Also notify caller to do permission check if we DID NOT create the
	 * file. Note it IS possible in the case of a race between an UNCHECKED
	 * open and an external unlink, we did create the file, but we will
	 * still force a permission check. That permission check might fail
	 * if the file created after the unlink has a mode that doesn't allow
	 * the caller/creator to open the file (on the other hand, one hopes
	 * a non-exclusive open doesn't set a mode that doesn't allow read/write
	 * since the application clearly expects that another process may have
	 * created the file). This failure case really isn't too awful since
	 * it would just look to the caller like someone else had created the
	 * file with a mode that prevented the open this caller was attempting.
	 */
	created = (p_flags & O_EXCL) != 0;
	*caller_perm_check = !created;

	/*
	 * Since the file is created, remove O_CREAT/O_EXCL flags
	 */
	p_flags &= ~(O_EXCL | O_CREAT);

	fh_desc.len = sizeof(struct gsh_buffdesc);
	fh.inode = inode;
	fh.export_id = export->export_id;
	fh_desc.addr = &fh;
	status = nedge_create_handle(op_ctx->fsal_export, &fh_desc, new_obj,
	    NULL);

	myself = container_of(*new_obj, struct nedge_fsal_obj_handle,
	    obj_handle);
	/*
	 * If we didn't have a state above, use the global fd. At this point,
	 * * since we just created the global fd, no one else can have a
	 * * reference to it, and thus we can mamnipulate unlocked which is
	 * * handy since we can then call setattr2 which WILL take the lock
	 * * without a double locking deadlock.
	 */
	if (my_fd == NULL)
		my_fd = &myself->globalfd;

open:
	/*
	 * now open it
	 */
	status = nedge_open_my_fd(myself, openflags, p_flags, my_fd);

	if (FSAL_IS_ERROR(status))
		goto direrr;

	*new_obj = &myself->obj_handle;

	if (created && attrib_set->valid_mask != 0) {
		/*
		 * Set attributes using our newly opened file descriptor as the
		 * * share_fd if there are any left to set (mode and truncate
		 * * have already been handled).
		 * *
		 * * Note that we only set the attributes if we were responsible
		 * * for creating the file and we have attributes to set.
		 */
		status = (*new_obj)->obj_ops->setattr2(*new_obj, false, state,
		    attrib_set);

		if (FSAL_IS_ERROR(status)) {
			/*
			 * Release the handle we just allocated.
			 */
			(*new_obj)->obj_ops->release(*new_obj);
			/*
			 * We released handle at this point
			 */
			*new_obj = NULL;
			goto fileerr;
		}

		if (attrs_out != NULL) {
			status = (*new_obj)->obj_ops->getattrs(*new_obj,
			    attrs_out);
			if (FSAL_IS_ERROR(status)
			    && (attrs_out->request_mask & ATTR_RDATTR_ERR) ==
			    0) {
				/*
				 * Get attributes failed and caller expected
				 * * to get the attributes. Otherwise continue
				 * * with attrs_out indicating ATTR_RDATTR_ERR.
				 */
				goto fileerr;
			}
		}
	} else if (attrs_out != NULL) {
		/*
		 * Since we haven't set any attributes other than what was set
		 * * on create (if we even created), just use the stat results
		 * * we used to create the fsal_obj_handle.
		 */
		posix2fsal_attributes_all(&sb, attrs_out);
	}


	if (state != NULL) {
		/*
		 * Prepare to take the share reservation, but only if we are
		 * * called with a valid state (if state is NULL the caller is
		 * * a stateless create such as NFS v3 CREATE).
		 */

		/*
		 * This can block over an I/O operation.
		 */
		PTHREAD_RWLOCK_wrlock(&(*new_obj)->obj_lock);

		/*
		 * Take the share reservation now by updating the counters.
		 */
		update_share_counters(&myself->share, FSAL_O_CLOSED, openflags);

		PTHREAD_RWLOCK_unlock(&(*new_obj)->obj_lock);
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);


fileerr:
	nedge_close_my_fd(my_fd);

direrr:
	/*
	 * Delete the file if we actually created it.
	 */
	if (created)
		(*new_obj)->obj_ops->unlink(&parenthandle->obj_handle, NULL,
		    name);

	return fsalstat(posix2fsal_error(retval), retval);

out:
	return status;
}

fsal_status_t
nedge_reopen2(struct fsal_obj_handle *obj_hdl, struct state_t *state,
    fsal_openflags_t openflags)
{
	struct nedge_fd fd = { 0 }, *my_fd = &fd, *my_share_fd = NULL;
	struct nedge_fsal_obj_handle *myself;
	fsal_openflags_t old_openflags;
	fsal_status_t status = { 0, 0 };
	int     posix_flags = 0;

	my_share_fd = (struct nedge_fd *) (state + 1);

	fsal2posix_openflags(openflags, &posix_flags);

	memset(my_fd, 0, sizeof(*my_fd));

	myself = container_of(obj_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);

	/*
	 * This can block over an I/O operation.
	 */
	PTHREAD_RWLOCK_wrlock(&obj_hdl->obj_lock);

	old_openflags = my_share_fd->openflags;

	/*
	 * We can conflict with old share, so go ahead and check now.
	 */
	status = check_share_conflict(&myself->share, openflags, false);

	if (FSAL_IS_ERROR(status)) {
		PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);
		return status;
	}

	/*
	 * Set up the new share so we can drop the lock and not have a
	 * * conflicting share be asserted, updating the share counters.
	 */
	update_share_counters(&myself->share, old_openflags, openflags);

	PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);

	status = nedge_open_my_fd(myself, openflags, posix_flags, my_fd);

	if (!FSAL_IS_ERROR(status)) {
		/*
		 * Close the existing file descriptor and copy the new
		 * * one over.
		 */
		nedge_close_my_fd(my_share_fd);
		*my_share_fd = fd;
	} else {
		/*
		 * We had a failure on open - we need to revert the share.
		 * * This can block over an I/O operation.
		 */
		PTHREAD_RWLOCK_wrlock(&obj_hdl->obj_lock);

		update_share_counters(&myself->share, openflags,
		    old_openflags);

		PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);
	}

	return status;
}

fsal_status_t
nedge_read2(struct fsal_obj_handle *obj_hdl, bool bypass,
    struct state_t *state, uint64_t seek_descriptor, size_t buffer_size,
    void *buffer, size_t * read_amount, bool * end_of_file,
    struct io_info *info)
{
	bool has_lock, closefd;
	struct nedge_fd my_fd = { 0 };
	ssize_t nb_read;
	fsal_status_t status;
	int eof, retval = 0;

	has_lock = closefd = false;

	if (info != NULL) {
		/*
		 * Currently we don't support READ_PLUS
		 */
		return fsalstat(ERR_FSAL_NOTSUPP, 0);
	}

	/*
	 * Get a usable file descriptor
	 */
	status = find_fd(&my_fd, obj_hdl, bypass, state, FSAL_O_READ, &has_lock,
	    &closefd, false);

	if (FSAL_IS_ERROR(status))
		goto out;

	retval = FNEDGE_ERRMAP(ccow_fsio_read(my_fd.file, seek_descriptor,
	    buffer_size, buffer, &nb_read, &eof));
	/* ganesha EOF is bool (1 byte). */
	*end_of_file = (bool)eof;

	if (retval != 0)
		status = fsalstat(posix2fsal_error(retval), retval);
	if (seek_descriptor == -1 || nb_read == -1) {
		goto out;
	}

	*read_amount = nb_read;

out:
	if (closefd)
		nedge_close_my_fd(&my_fd);

	if (has_lock)
		PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);

	return status;

}

fsal_status_t
nedge_write2(struct fsal_obj_handle *obj_hdl, bool bypass,
    struct state_t *state, uint64_t seek_descriptor, size_t buffer_size,
    void *buffer, size_t *write_amount, bool *fsal_stable,
    struct io_info *info)
{
	bool has_lock, closefd;
	struct nedge_fd my_fd = { 0 };
	fsal_openflags_t openflags;
	ssize_t nb_written;
	fsal_status_t status;
	int retval = 0;

	has_lock = closefd = false;
	openflags = FSAL_O_WRITE;

	if (info != NULL) {
		/*
		 * Currently we don't support WRITE_PLUS
		 */
		return fsalstat(ERR_FSAL_NOTSUPP, 0);
	}
	/*
	 * Get a usable file descriptor
	 */
	status = find_fd(&my_fd, obj_hdl, bypass, state, openflags, &has_lock,
	    &closefd, false);

	if (FSAL_IS_ERROR(status))
		goto out;

	retval = FNEDGE_ERRMAP(ccow_fsio_write(my_fd.file, seek_descriptor,
	    buffer_size, buffer, &nb_written));

	if (retval != 0) {
		status = fsalstat(posix2fsal_error(retval), retval);
		goto out;
	}

	if (*fsal_stable) {
		retval = FNEDGE_ERRMAP(ccow_fsio_flush(my_fd.file));
		if (retval != 0) {
			/** fsal_stable is in-out parameter.
			 *	Update it if commit fails.
			 */
			*fsal_stable = 0;
			status = fsalstat(posix2fsal_error(retval), retval);

			/** Fall through as commit failed but write is success.
			 *	Let client recover the way it wants.
			 */
		}
	}
	*write_amount = nb_written;

out:
	if (closefd)
		nedge_close_my_fd(&my_fd);

	if (has_lock)
		PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);

	return status;
}

fsal_status_t
nedge_commit2(struct fsal_obj_handle *obj_hdl, off_t offset, size_t len)
{
	struct nedge_fd tmp_fd = { 0 }, *out_fd = &tmp_fd;
	struct nedge_fsal_obj_handle *myself = NULL;
	bool has_lock, closefd;
	fsal_status_t status;
	int retval;

	has_lock = closefd = false;

	myself = container_of(obj_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);

	/*
	 * Make sure file is open in appropriate mode.
	 * * Do not check share reservation.
	 */
	status = fsal_reopen_obj(obj_hdl, false, false, FSAL_O_WRITE,
	    (struct fsal_fd *) &myself->globalfd, &myself->share,
	    nedge_open_func, nedge_close_func, (struct fsal_fd **) &out_fd,
	    &has_lock, &closefd);

	if (!FSAL_IS_ERROR(status)) {
		retval = FNEDGE_ERRMAP(ccow_fsio_flush(out_fd->file));
		if (retval != 0)
			status = fsalstat(posix2fsal_error(retval), retval);
	}

	if (closefd)
		nedge_close_my_fd(out_fd);

	if (has_lock)
		PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);

	return status;
}

fsal_status_t
nedge_lock_op2(struct fsal_obj_handle *obj_hdl, struct state_t *state,
    void *p_owner, fsal_lock_op_t lock_op, fsal_lock_param_t * request_lock,
    fsal_lock_param_t * conflicting_lock)
{
	LogFullDebug(COMPONENT_FSAL,
		     "Locking: op:%d type:%d start:%" PRIu64 " length:%"
		     PRIu64 " ",
		     lock_op, request_lock->lock_type, request_lock->lock_start,
		     request_lock->lock_length);
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

fsal_status_t
nedge_close2(struct fsal_obj_handle *obj_hdl, struct state_t *state)
{
	struct nedge_fd *my_fd = (struct nedge_fd *) (state + 1);
	struct nedge_fsal_obj_handle *myself = NULL;

	myself = container_of(obj_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);

	if (state->state_type == STATE_TYPE_SHARE ||
	    state->state_type == STATE_TYPE_NLM_SHARE ||
	    state->state_type == STATE_TYPE_9P_FID) {
		/*
		 * This is a share state, we must update the share counters
		 */

		/*
		 * This can block over an I/O operation.
		 */
		PTHREAD_RWLOCK_wrlock(&obj_hdl->obj_lock);

		update_share_counters(&myself->share, my_fd->openflags,
		    FSAL_O_CLOSED);

		PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);
	}

	return nedge_close_my_fd(my_fd);
}

fsal_status_t
nedge_setattr2(struct fsal_obj_handle *obj_hdl, bool bypass,
    struct state_t *state, struct attrlist *attrib_set)
{
	bool has_lock, closefd;
	struct nedge_fsal_obj_handle *myself;
	struct nedge_fsal_export *export;
	struct nedge_fd my_fd = {0};
	struct stat stat;
	fsal_openflags_t openflags;
	fsal_status_t status = {0, 0};
	struct timespec timestamp;
	int retval;

	openflags = FSAL_O_ANY;

	has_lock = closefd = false;
	export = container_of(op_ctx->fsal_export, struct nedge_fsal_export,
	    export);

	/** @todo: Handle special file symblic links etc */
	/* apply umask, if mode attribute is to be changed */
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MODE))
		attrib_set->mode &=
		    ~op_ctx->fsal_export->exp_ops.fs_umask(op_ctx->fsal_export);

	myself = container_of(obj_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);

	retval = FNEDGE_ERRMAP(ccow_fsio_get_file_stat(export->ci,
	    h2inode(myself), &stat));
	if (retval != 0) {
		LogDebug(COMPONENT_FSAL, " ");
		status = fsalstat(posix2fsal_error(retval), retval);
		goto out;
	}

	/* Test if size is being set, make sure file is regular and if so,
	 * require a read/write file descriptor.
	 */
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_SIZE)) {
		if (obj_hdl->type != REGULAR_FILE)
			return fsalstat(ERR_FSAL_INVAL, EINVAL);
		openflags = FSAL_O_RDWR;
	}

	/** TRUNCATE **/
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_SIZE) &&
	    (obj_hdl->type == REGULAR_FILE)) {
		/* Get a usable file descriptor. Share conflict is only
		 * possible if size is being set. For special files,
		 * handle via handle.
		 */
		status = find_fd(&my_fd, obj_hdl, bypass, state, openflags,
				 &has_lock, &closefd, false);

		if (FSAL_IS_ERROR(status))
			goto out;

		stat.st_size = attrib_set->filesize;
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_CREATION)) {
		stat.st_ctim = attrib_set->ctime;
	}
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_CTIME)) {
		stat.st_ctim = attrib_set->ctime;
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MODE))
		stat.st_mode = attrib_set->mode;
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_OWNER))
		stat.st_uid = attrib_set->owner;
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_GROUP))
		stat.st_gid = attrib_set->group;
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_ATIME))
		stat.st_atim = attrib_set->atime;

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_ATIME_SERVER)) {

		retval = clock_gettime(CLOCK_REALTIME, &timestamp);
		if (retval != 0) {
			status = fsalstat(posix2fsal_error(retval), retval);
			goto out;
		}
		stat.st_atim = timestamp;
	}

	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MTIME)) {
		stat.st_mtim = attrib_set->mtime;
	}
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MTIME_SERVER)) {

		retval = clock_gettime(CLOCK_REALTIME, &timestamp);
		if (retval != 0) {
			status = fsalstat(posix2fsal_error(retval), retval);
			goto out;
		}
		stat.st_mtim = timestamp;
	}

	retval = FNEDGE_ERRMAP(ccow_fsio_set_file_stat(export->ci,
	    h2inode(myself), &stat));
	if (retval != 0) {
		LogDebug(COMPONENT_FSAL, " ");
		status = fsalstat(posix2fsal_error(retval), retval);
		goto out;
	}

	if (FSAL_IS_ERROR(status)) {
		LogDebug(COMPONENT_FSAL,
			 "setting ACL failed");
		goto out;
	}

 out:
	if (FSAL_IS_ERROR(status)) {
		LogCrit(COMPONENT_FSAL,
			 "setattrs failed with error %s",
			 strerror(status.minor));
	}

	if (closefd)
		nedge_close_my_fd(&my_fd);

	if (has_lock)
		PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);

	return status;
}

struct state_t *
nedge_alloc_state(struct fsal_export *exp_hdl, enum state_type state_type,
    struct state_t *related_state)
{
	struct nedge_fd *my_fd;
	struct state_t *state;

	state = init_state(gsh_calloc(1, sizeof(struct state_t) +
	    sizeof(struct nedge_fd)), exp_hdl, state_type, related_state);

	my_fd = (struct nedge_fd *)(state + 1);

	my_fd->file = NULL;
	my_fd->openflags = FSAL_O_CLOSED;

	return state;
}

