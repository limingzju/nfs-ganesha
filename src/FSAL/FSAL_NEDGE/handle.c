/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Panasas Inc., 2011
 * Author: Jim Lieb jlieb@panasas.com
 *
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * -------------
 */

/* handle.c
 * NEDGE (file|dir) handle object
 */

#include "config.h"

#include "fsal.h"
#include <libgen.h>		/* used for 'dirname' */
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <mntent.h>
#include "gsh_list.h"
#include "fsal_internal.h"
#include "fsal_convert.h"
#include "FSAL/fsal_config.h"
#include "FSAL/fsal_commonlib.h"
#include <stdbool.h>

#include "nedge_methods.h"

#define	ERROUT(err, ...)				\
	if ((err) != 0) {				\
		*rerr = (err);				\
		LogDebug(COMPONENT_FSAL, __VA_ARGS__);	\
		goto err;				\
	}

static int update_stat_on_attrs(struct attrlist *attrs, struct stat *stat);

/* nedge_alloc_handle
 * allocate and fill in a handle
 * this uses malloc/free for the time being.
 */
static struct nedge_fsal_obj_handle *
nedge_alloc_handle(struct nedge_file_handle *fh, struct stat *stat,
    const char *link_content, struct fsal_export *exp_hdl)
{
	struct nedge_fsal_obj_handle *hdl;
	struct nedge_fsal_export *exp;
	size_t len;

	LogDebug(COMPONENT_FSAL, " ");
	hdl = gsh_calloc(1, sizeof(struct nedge_fsal_obj_handle) +
			 sizeof(struct nedge_file_handle));
	if (hdl == NULL)
		return (NULL);

	memset(hdl, 0, (sizeof(struct nedge_fsal_obj_handle) +
		sizeof(struct nedge_file_handle)));
	hdl->handle = (struct nedge_file_handle *)&hdl[1];

	exp = container_of(exp_hdl, struct nedge_fsal_export, export);
	LogDebug(COMPONENT_FSAL, "Set CI to %p for %ju @ %s", exp->ci,
	    stat->st_ino, exp->fullpath);
	hdl->ci = exp->ci;
	hdl->export_id = exp->export_id;
	if (fh != NULL) {
		memcpy(hdl->handle, fh, sizeof(struct nedge_file_handle));
	}

	switch (stat->st_mode & S_IFMT) {
	case S_IFLNK:
	case S_IFREG:
	case S_IFDIR:
		break;
	default:
		LogDebug(COMPONENT_FSAL, "Broken st_mode = 0%o", stat->st_mode);
		stat->st_mode = S_IFREG | 0600;
	}

	hdl->obj_handle.type = posix2fsal_type(stat->st_mode);

	if ((hdl->obj_handle.type == SYMBOLIC_LINK) &&
	    (link_content != NULL)) {
		len = strlen(link_content) + 1;

		hdl->u.symlink.link_content = gsh_malloc(len);
		if (hdl->u.symlink.link_content == NULL)
			goto spcerr;
		memcpy(hdl->u.symlink.link_content, link_content, len);
		hdl->u.symlink.link_size = len;
	}

	LogDebug(COMPONENT_FSAL, " ");
	fsal_obj_handle_init(&hdl->obj_handle, exp_hdl,
	    posix2fsal_type(stat->st_mode));
	LogDebug(COMPONENT_FSAL, " ");
	hdl->obj_handle.fsid = posix2fsal_fsid(stat->st_dev);
	hdl->obj_handle.fileid = stat->st_ino;
	hdl->obj_handle.obj_ops = &hdl->obj_ops;
	LogDebug(COMPONENT_FSAL, " ");

	nedge_handle_ops_init(&hdl->obj_ops);
	return (hdl);

 spcerr:
	LogDebug(COMPONENT_FSAL, " ");
	PTHREAD_RWLOCK_unlock(&hdl->obj_handle.obj_lock);
	PTHREAD_RWLOCK_destroy(&hdl->obj_handle.obj_lock);
	LogDebug(COMPONENT_FSAL, " ");
	if (hdl->obj_handle.type == SYMBOLIC_LINK) {
		if (hdl->u.symlink.link_content != NULL)
			gsh_free(hdl->u.symlink.link_content);
	}
	gsh_free(hdl);		/* elvis has left the building */
	return (NULL);
}

/* lookup
 * deprecated NULL parent && NULL path implies root handle
 */

static fsal_status_t
nedge_lookup(struct fsal_obj_handle *parent, const char *path,
    struct fsal_obj_handle **handle, struct attrlist *attrs_out)
{
	struct nedge_fsal_obj_handle *parent_hdl, *hdl;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	struct stat stat;
	int retval = 0;
	inode_t inode;

	LogDebug(COMPONENT_FSAL, "path=%s", path);
	if (!path)
		return fsalstat(ERR_FSAL_FAULT, 0);
	parent_hdl = container_of(parent, struct nedge_fsal_obj_handle,
	    obj_handle);
	if (parent_hdl == NULL)
		return fsalstat(ERR_FSAL_FAULT, 0);

	LogDebug(COMPONENT_FSAL, "path=%s @%ju", path, h2inode(parent_hdl));

	LogDebug(COMPONENT_FSAL, " ");
	if (!fsal_obj_handle_is(parent, DIRECTORY)) {
		LogCrit(COMPONENT_FSAL,
			"Parent handle is not a directory. hdl = 0x%p", parent);
		return fsalstat(ERR_FSAL_NOTDIR, 0);
	}

	/* >> Call your filesystem lookup function here << */
	/* >> Be carefull you don't traverse junction nor follow symlinks << */

	retval = FNEDGE_ERRMAP(ccow_fsio_lookup(parent_hdl->ci,
	    h2inode(parent_hdl), (char *)path, &inode));
	if (retval != 0)
		goto errout;

	retval = FNEDGE_ERRMAP(ccow_fsio_get_file_stat(parent_hdl->ci, inode,
	    &stat));
	if (retval != 0)
		goto errout;
	LogDebug(COMPONENT_FSAL, "inode %lu", stat.st_ino);

	/* allocate an obj_handle and fill it up */
	hdl = nedge_alloc_handle(NULL, &stat, NULL, op_ctx->fsal_export);
	if (hdl != NULL) {
		*handle = &hdl->obj_handle;

		hdl->handle->inode = inode;
		hdl->handle->export_id = parent_hdl->export_id;
	} else {
		fsal_error = ERR_FSAL_NOMEM;
		*handle = NULL;	/* poison it */
		goto errout1;
	}

	if (attrs_out != NULL) {
		posix2fsal_attributes_all(&stat, attrs_out);
	}

	LogDebug(COMPONENT_FSAL, " ");
	return fsalstat(ERR_FSAL_NO_ERROR, 0);


 errout:
	fsal_error = posix2fsal_error(retval);
errout1:
	LogDebug(COMPONENT_FSAL, " ");
	return fsalstat(fsal_error, retval);
}

/* lookup_path
 * should not be used for "/" only is exported */

fsal_status_t
nedge_lookup_path(struct fsal_export *exp_hdl, const char *path,
    struct fsal_obj_handle **handle, struct attrlist *attrs_out)
{
	struct nedge_fsal_obj_handle *hdl;
	struct nedge_fsal_export *exp;
	struct nedge_file_handle fh;
	struct stat stat;
	int rc;

	rc = 0;
	LogDebug(COMPONENT_FSAL, " path = %s", path);
	*handle = NULL;	/* poison it */

	exp = container_of(exp_hdl, struct nedge_fsal_export, export);
	if (exp == NULL)
		return fsalstat(ERR_FSAL_FAULT, 0);

	if (strlen(path) != strlen(exp->fullpath) ||
	    strcmp(path, exp->fullpath) != 0)
		return fsalstat(ERR_FSAL_INVAL, 0);

	fh.inode = CCOW_FSIO_ROOT_INODE;     /* inode number */
	fh.export_id = exp->export_id;     /* inode number */

	rc = FNEDGE_ERRMAP(ccow_fsio_get_file_stat(exp->ci,
	    CCOW_FSIO_ROOT_INODE, &stat));
	if (rc == ENOENT) {
		/* Empty bucket yet. */
		stat.st_mode = S_IFDIR | 0755;
		stat.st_uid = stat.st_gid = 0;
		stat.st_ino = CCOW_FSIO_ROOT_INODE;
		rc = 0;
	}

	if (attrs_out != NULL) {
		posix2fsal_attributes_all(&stat, attrs_out);
	}

	hdl = nedge_alloc_handle(&fh, &stat, NULL, exp_hdl);
	if (hdl != NULL) {
		LogDebug(COMPONENT_FSAL, " path = %s - DONE", path);
		*handle = &hdl->obj_handle;
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}

	LogDebug(COMPONENT_FSAL, " path = %s - FAILED", path);
	return fsalstat(ERR_FSAL_NOMEM, 0);
}

static fsal_status_t
nedge_mkdir(struct fsal_obj_handle *dir_hdl, const char *name,
    struct attrlist *attrib, struct fsal_obj_handle **handle,
    struct attrlist *attrs_out)
{
	struct nedge_fsal_obj_handle *hdl, *myself;
	struct nedge_file_handle fh;
	struct timespec timestamp;
	struct stat stat;
	uint64_t inode;
	int err;

	LogDebug(COMPONENT_FSAL, " ");
	myself = container_of(dir_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);

	err = FNEDGE_ERRMAP(ccow_fsio_mkdir(myself->ci, h2inode(myself),
	    (char *)name, fsal2unix_mode(attrib->mode),
	    op_ctx->creds->caller_uid, op_ctx->creds->caller_gid, &inode));
	if (err != 0)
		goto errout;

	err = FNEDGE_ERRMAP(ccow_fsio_get_file_stat(myself->ci, inode, &stat));
	if (err != 0)
		goto errout;
	err = update_stat_on_attrs(attrib, &stat);
	if (err != 0)
		goto errout;
	err = clock_gettime(CLOCK_REALTIME, &timestamp);
	if (err != 0)
		goto errout;
	stat.st_atim = stat.st_ctim = stat.st_mtim = timestamp;
	err = FNEDGE_ERRMAP(ccow_fsio_set_file_stat(myself->ci, inode, &stat));
	if (err != 0)
		goto errout;

	fh.inode = inode;
	fh.export_id = myself->export_id;
	hdl = nedge_alloc_handle(&fh, &stat, NULL, op_ctx->fsal_export);
	if (hdl != NULL) {
		if (attrs_out != NULL) {
			posix2fsal_attributes_all(&stat, attrs_out);
		}

		LogDebug(COMPONENT_FSAL, "%s @%ju DONE", name, h2inode(myself));
		*handle = &hdl->obj_handle;
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}
	err = ENOMEM;

errout:
	LogDebug(COMPONENT_FSAL, "err = %d", err);
	return fsalstat(posix2fsal_error(err), err);
}

static fsal_status_t
nedge_makenode(struct fsal_obj_handle *dir_hdl, const char *name,
    object_file_type_t nodetype, struct attrlist *attrib,
    struct fsal_obj_handle **handle, struct attrlist *attrs_out)
{
	LogDebug(COMPONENT_FSAL, " ");
	return fsalstat(ERR_FSAL_NOTSUPP, 0);
}

/** makesymlink
 *  Note that we do not set mode bits on symlinks for Linux/POSIX
 *  They are not really settable in the kernel and are not checked
 *  anyway (default is 0777) because open uses that target's mode
 */

static fsal_status_t
nedge_makesymlink(struct fsal_obj_handle *dir_hdl, const char *name,
    const char *link_path, struct attrlist *attrib,
    struct fsal_obj_handle **handle, struct attrlist *attrs_out)
{
	struct nedge_fsal_obj_handle *hdl, *myself;
	struct nedge_file_handle fh;
	struct timespec timestamp;
	struct stat stat;
	uint64_t inode;
	int err;

	LogDebug(COMPONENT_FSAL, " ");
	myself = container_of(dir_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);

	err = FNEDGE_ERRMAP(ccow_fsio_mksymlink(myself->ci, h2inode(myself),
	    (char *)name, fsal2unix_mode(attrib->mode),
	    op_ctx->creds->caller_uid, op_ctx->creds->caller_gid, &inode,
	    (char *)link_path));
	if (err != 0)
		goto errout;

	err = FNEDGE_ERRMAP(ccow_fsio_get_file_stat(myself->ci, inode, &stat));
	if (err != 0)
		goto errout;
	err = update_stat_on_attrs(attrib, &stat);
	if (err != 0)
		goto errout;
	err = clock_gettime(CLOCK_REALTIME, &timestamp);
	if (err != 0)
		goto errout;
	stat.st_atim = stat.st_ctim = stat.st_mtim = timestamp;
	err = FNEDGE_ERRMAP(ccow_fsio_set_file_stat(myself->ci, inode, &stat));
	if (err != 0)
		goto errout;

	fh.inode = inode;
	fh.export_id = myself->export_id;
	hdl = nedge_alloc_handle(&fh, &stat, NULL, op_ctx->fsal_export);
	if (hdl != NULL) {
		if (attrs_out != NULL) {
			posix2fsal_attributes_all(&stat, attrs_out);
		}

		*handle = &hdl->obj_handle;
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}
	err = ENOMEM;

errout:
	LogDebug(COMPONENT_FSAL, "err = %d", err);
	return fsalstat(posix2fsal_error(err), err);
}

static fsal_status_t
nedge_readsymlink(struct fsal_obj_handle *obj_hdl,
    struct gsh_buffdesc *link_content, bool refresh)
{
	struct nedge_fsal_obj_handle *myself = NULL;
	char *link;
	int retval = 0;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;

	LogDebug(COMPONENT_FSAL, " ");
	if (obj_hdl->type != SYMBOLIC_LINK) {
		fsal_error = ERR_FSAL_FAULT;
		goto out;
	}
	myself = container_of(obj_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);
	LogDebug(COMPONENT_FSAL, "%ju", h2inode(myself));

	retval = FNEDGE_ERRMAP(ccow_fsio_readsymlink(myself->ci,
	    h2inode(myself), (char **)&link));
	LogDebug(COMPONENT_FSAL, " ");
	if (retval) {
		fsal_error = posix2fsal_error(retval);
		link_content->addr = NULL;
		link_content->len = 0;
		goto out;
	}

	link_content->len = strlen(link) + 1;
	link_content->addr = gsh_strdup(link);

	ccow_fsio_free(myself->ci, link);

	LogDebug(COMPONENT_FSAL, "LINK %s, SIZE %ju", link, link_content->len);
	if (link_content->addr == NULL)
		return fsalstat(ERR_FSAL_NOMEM, 0);
 out:
	return fsalstat(fsal_error, retval);
}

static fsal_status_t
nedge_linkfile(struct fsal_obj_handle *obj_hdl,
    struct fsal_obj_handle *destdir_hdl, const char *name)
{
	struct nedge_fsal_obj_handle *myself, *destdir;
	int retval = 0;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;

	LogDebug(COMPONENT_FSAL, " ");
	if (!op_ctx->fsal_export->exp_ops.
	    fs_supports(op_ctx->fsal_export, fso_link_support)) {
		fsal_error = ERR_FSAL_NOTSUPP;
		goto out;
	}
	myself = container_of(obj_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);
	LogDebug(COMPONENT_FSAL, "%ju", h2inode(myself));

	destdir = container_of(destdir_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);
	LogDebug(COMPONENT_FSAL, "destdir %ju", h2inode(destdir));

	retval = FNEDGE_ERRMAP(ccow_fsio_link(myself->ci, h2inode(destdir),
	    (char *)name, h2inode(myself)));
	if (retval)
		fsal_error = posix2fsal_error(retval);
 out:
	return fsalstat(fsal_error, retval);
}

/**
 * read_dirents
 * read the directory and call through the callback function for
 * each entry.
 * @param dir_hdl [IN] the directory to read
 * @param entry_cnt [IN] limit of entries. 0 implies no limit
 * @param whence [IN] where to start (next)
 * @param dir_state [IN] pass thru of state to callback
 * @param cb [IN] callback function
 * @param eof [OUT] eof marker true == end of dir
 */

struct nedge_readdir_cb4_data {
	struct fsal_obj_handle *dir_hdl;
	attrmask_t attrmask;
	fsal_readdir_cb cb;
	void *dir_state;
	bool *eof;
};

int
nedge_readdir_cb4(inode_t parent, fsio_dir_entry *dir_entry, uint64_t count,
    void *ptr)
{
	struct nedge_fsal_obj_handle *myself;
	struct nedge_readdir_cb4_data *dat;
	struct fsal_obj_handle *obj;
	fsal_status_t fsal_status;
	struct attrlist attrs;
	uint64_t i;
	int err;

	dat = (struct nedge_readdir_cb4_data *)ptr;

	myself = container_of(dat->dir_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);


	LogDebug(COMPONENT_FSAL, " entry count=%ld eof: %d", count, *dat->eof);

	for (i=0; i< count; i++) {
		if (dir_entry[i].name[0] == '.' &&
		    (dir_entry[i].name[1] == '\0' ||
		    (dir_entry[i].name[1] == '.' &&
		     dir_entry[i].name[2] == '\0')))
			continue;

		LogDebug(COMPONENT_FSAL, " entry=%s i=%ld", dir_entry[i].name, i);
		fsal_prepare_attrs(&attrs, dat->attrmask);

		LogAttrlist(COMPONENT_FSAL, NIV_FULL_DEBUG, "attrs ", &attrs,
		    false);

		fsal_status = nedge_lookup(dat->dir_hdl, dir_entry[i].name,
		    &obj, &attrs);
		if (FSAL_IS_ERROR(fsal_status)) {
			LogDebug(COMPONENT_FSAL,
			    " entry=%s. Error: on nedge_lookup",
			    dir_entry[i].name);
			fsal_release_attrs(&attrs);
			/* continue to rest of entries */
			continue;
		}

		LogAttrlist(COMPONENT_FSAL, NIV_FULL_DEBUG, "attrs ", &attrs,
		    false);
		/* callback to cache inode */
		err = dat->cb(dir_entry[i].name, obj, &attrs, dat->dir_state,
		    (fsal_cookie_t) dir_entry[i].inode);

		fsal_release_attrs(&attrs);

		LogDebug(COMPONENT_FSAL, "cb cache inode %lu, err:%d", dir_entry[i].inode, err);

		int e = ccow_fsio_add_list_cache(myself->ci, parent,
						dir_entry[i].inode, dir_entry[i].name);
		LogDebug(COMPONENT_FSAL, "fsio cache list entry %lu, err:%d", dir_entry[i].inode, e);


		if (err >= DIR_TERMINATE) {
			LogDebug(COMPONENT_FSAL, "Terminate dir on inode: %lu, err:%d, eof: %d",
				dir_entry[i].inode, err, *dat->eof);
			return 1;
		}
	}

	return 0;
}

static fsal_status_t
nedge_readdir(struct fsal_obj_handle *dir_hdl, fsal_cookie_t *whence,
    void *dir_state, fsal_readdir_cb cb, attrmask_t attrmask, bool *eof)
{
	struct nedge_fsal_obj_handle *myself;
	struct nedge_readdir_cb4_data dat;
	int retval;

	LogDebug(COMPONENT_FSAL, " ");
	myself = container_of(dir_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);

	char start[1024];

	dat.cb = cb;
	dat.dir_hdl = dir_hdl;
	dat.dir_state = dir_state;
	dat.attrmask = attrmask;
	dat.eof = eof;

	if (whence == NULL) {
		strcpy(start, "");
	} else {
		if (*whence <= CCOW_FSIO_ROOT_INODE) {
			strcpy(start, "");
		} else {
			int res = ccow_fsio_find_list(myself->ci, h2inode(myself), *whence, start, 1024);
			if (res == -ENOENT) {
				strcpy(start, "");
			} else if (res < 0) {
				LogDebug(COMPONENT_FSAL, "%ju %lu find err=%d", h2inode(myself), *whence, res);
				retval = FNEDGE_ERRMAP(-res);
				return fsalstat(posix2fsal_error(retval), retval);
			} else if (res == 0) {  // Miss, save inode in cache
				int err = ccow_fsio_add_list_cache(myself->ci, h2inode(myself), *whence, start);
				LogDebug(COMPONENT_FSAL, "%ju %lu inode miss, save it in cache err=%d", h2inode(myself), *whence, err);
				if (err) {
					if (err < 0) err = -err;
					retval = FNEDGE_ERRMAP(err);
					return fsalstat(posix2fsal_error(retval), retval);
				}
			} else { // res > 0
				LogDebug(COMPONENT_FSAL, "%ju %lu inode found in cache", h2inode(myself), *whence);
			}
		}
	}

	LogDebug(COMPONENT_FSAL, "%ju from=%s", h2inode(myself), start);

	retval = FNEDGE_ERRMAP(ccow_fsio_readdir_cb4(myself->ci,
	    h2inode(myself), nedge_readdir_cb4, start, (void *)&dat, eof));

	LogDebug(COMPONENT_FSAL, " ");
	return fsalstat(posix2fsal_error(retval), retval);
}

static fsal_status_t
nedge_rename(struct fsal_obj_handle *obj_hdl,
    struct fsal_obj_handle *olddir_hdl, const char *old_name,
    struct fsal_obj_handle *newdir_hdl, const char *new_name)
{
	struct nedge_fsal_obj_handle *olddir, *newdir;
	int retval;

	LogDebug(COMPONENT_FSAL, " ");
	olddir = container_of(olddir_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);
	LogDebug(COMPONENT_FSAL, "olddir %ju", h2inode(olddir));

	newdir = container_of(newdir_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);
	LogDebug(COMPONENT_FSAL, "newdir %ju", h2inode(newdir));

	retval = FNEDGE_ERRMAP(ccow_fsio_move(olddir->ci, h2inode(olddir),
	    (char *)old_name, h2inode(newdir), (char *)new_name));

	return fsalstat(posix2fsal_error(retval), retval);
}

/* FIXME: attributes are now merged into fsal_obj_handle.  This
 * spreads everywhere these methods are used.  eventually deprecate
 * everywhere except where we explicitly want to to refresh them.
 * NOTE: this is done under protection of the attributes rwlock in the
 * cache entry.
 */

static fsal_status_t
nedge_getattrs(struct fsal_obj_handle *obj_hdl, struct attrlist *attrs_out)
{
	struct nedge_fsal_obj_handle *myself;
	struct stat stat;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval;

	LogDebug(COMPONENT_FSAL, " ");

	myself = container_of(obj_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);
	LogDebug(COMPONENT_FSAL, " ");

	retval = FNEDGE_ERRMAP(ccow_fsio_get_file_stat(myself->ci,
	    h2inode(myself), &stat));
	if (h2inode(myself) == CCOW_FSIO_ROOT_INODE && retval != 0) {
		retval = 0;
		stat.st_ino = CCOW_FSIO_ROOT_INODE;
		stat.st_mode = S_IFDIR | 0755;
		stat.st_size = 0;
	}
	LogDebug(COMPONENT_FSAL, " retval=%d, inode=%ju, mode=%8o",
	    retval, h2inode(myself), stat.st_mode);

	if (h2inode(myself) == CCOW_FSIO_ROOT_INODE) {
		stat.st_mode = S_IFDIR | 0755;
	}

	if (retval == 0) {
		posix2fsal_attributes_all(&stat, attrs_out);
	} else {
		if (attrs_out->request_mask & ATTR_RDATTR_ERR) {
			/* Caller asked for error to be visible. */
			attrs_out->valid_mask = ATTR_RDATTR_ERR;
		}
		if (retval == ENOENT)
			fsal_error = ERR_FSAL_STALE;
		else
			fsal_error = posix2fsal_error(retval);
	}

	return fsalstat(fsal_error, retval);
}

static int
update_stat_on_attrs(struct attrlist *attrs, struct stat *stat)
{
	struct timespec timestamp;
	int retval;

	if (FSAL_TEST_MASK(attrs->valid_mask, ATTR_MODE)) {
		stat->st_mode = (stat->st_mode & S_IFMT) |
		    fsal2unix_mode(attrs->mode);
	}
	if (FSAL_TEST_MASK(attrs->valid_mask, ATTR_OWNER)) {
		stat->st_uid = attrs->owner;
	}
	if (FSAL_TEST_MASK(attrs->valid_mask, ATTR_GROUP)) {
		stat->st_gid = attrs->group;
	}
	if (FSAL_TEST_MASK(attrs->valid_mask, ATTR_SIZE)) {
		stat->st_size = attrs->filesize;
	}
	if (FSAL_TEST_MASK(attrs->valid_mask, ATTR_CREATION)) {
		stat->st_ctime = attrs->ctime.tv_sec;
	}
	if (FSAL_TEST_MASK(attrs->valid_mask, ATTR_CTIME)) {
		stat->st_ctime = attrs->ctime.tv_sec;
	}
	if (FSAL_TEST_MASK(attrs->valid_mask, ATTR_ATIME)) {
		stat->st_atime = attrs->atime.tv_sec;
	}
	if (FSAL_TEST_MASK(attrs->valid_mask, ATTR_ATIME_SERVER)) {
		retval = clock_gettime(CLOCK_REALTIME, &timestamp);
		if (retval != 0)
			return (EIO);
		stat->st_atim = timestamp;
	}
	if (FSAL_TEST_MASK(attrs->valid_mask, ATTR_MTIME)) {
		stat->st_mtime = attrs->mtime.tv_sec;
	}
	if (FSAL_TEST_MASK(attrs->valid_mask, ATTR_MTIME_SERVER)) {
		retval = clock_gettime(CLOCK_REALTIME, &timestamp);
		if (retval != 0)
			return (EIO);
		stat->st_mtim = timestamp;
	}

	return (0);
}

/* file_unlink
 * unlink the named file in the directory
 */
static fsal_status_t
nedge_unlink(struct fsal_obj_handle *dir_hdl, struct fsal_obj_handle *obj_hdl,
    const char *name)
{
	struct nedge_fsal_obj_handle *myself;
	int retval;

	LogDebug(COMPONENT_FSAL, " ");

	myself = container_of(dir_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);
	LogDebug(COMPONENT_FSAL, "%ju", h2inode(myself));

	/* XXX check for presence of file and get its type */
	retval = FNEDGE_ERRMAP(ccow_fsio_delete(myself->ci, h2inode(myself),
	    (char *)name));

	return fsalstat(posix2fsal_error(retval), retval);
}

/* handle_to_wire
 * fill in the opaque f/s file handle part.
 * we zero the buffer to length first.  This MAY already be done above
 * at which point, remove memset here because the caller is zeroing
 * the whole struct.
 * Invariant that must be maintained:
 * host_to_key(wire_to_host(handle_to_wire(obj_hdl))) = handle_to_key(obj_hdl)
 * For nedge, "handle-key" is same as host-handle,
 * so host_to_key() is the default method
 */

static fsal_status_t
nedge_handle_to_wire(const struct fsal_obj_handle *obj_hdl,
    fsal_digesttype_t output_type, struct gsh_buffdesc *fh_desc)
{
	const struct nedge_fsal_obj_handle *obj;
	struct nedge_file_handle *fh;
	size_t fh_size;

	LogDebug(COMPONENT_FSAL, " ");
	/* sanity checks */
	if (!fh_desc)
		return fsalstat(ERR_FSAL_FAULT, 0);
	obj = container_of(obj_hdl, const struct nedge_fsal_obj_handle,
	    obj_handle);
	LogDebug(COMPONENT_FSAL, "inode=%ju [%ju] (%p)",
		h2inode(obj), obj->export_id, obj->ci);
	fh = obj->handle;
	LogDebug(COMPONENT_FSAL, "inode=%ju [%ju]",
		fh->inode, fh->export_id);

	switch (output_type) {
	case FSAL_DIGEST_NFSV3:
	case FSAL_DIGEST_NFSV4:
		fh_size = nedge_sizeof_handle(fh);
		if (fh_desc->len < fh_size)
			goto errout;
		memcpy(fh_desc->addr, fh, fh_size);
		break;
	default:
		return fsalstat(ERR_FSAL_SERVERFAULT, 0);
	}
	fh_desc->len = fh_size;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);

 errout:
	LogMajor(COMPONENT_FSAL,
		 "Space too small for handle.  need %lu, have %lu", fh_size,
		 fh_desc->len);
	return fsalstat(ERR_FSAL_TOOSMALL, 0);
}

/**
 * handle_to_key
 * return a handle descriptor into the handle in this object handle
 * @TODO reminder.  make sure things like hash keys don't point here
 * after the handle is released.
 * Invariant that must be maintained:
 * host_to_key(wire_to_host(handle_to_wire(obj_hdl))) = handle_to_key(obj_hdl)
 */

static void
nedge_handle_to_key(struct fsal_obj_handle *obj_hdl,
    struct gsh_buffdesc *fh_desc)
{
	struct nedge_fsal_obj_handle *obj;

	LogDebug(COMPONENT_FSAL, " ");
	obj = container_of(obj_hdl, struct nedge_fsal_obj_handle, obj_handle);
	LogDebug(COMPONENT_FSAL, "inode=%ju (%p)", h2inode(obj), obj->ci);
	LogDebug(COMPONENT_FSAL, "inode=%ju [%ju]",
		obj->handle->inode, obj->handle->export_id);
	fh_desc->addr = obj->handle;
	fh_desc->len = nedge_sizeof_handle(obj->handle);
}

/*
 * release
 * release our export first so they know we are gone
 */

static void
release(struct fsal_obj_handle *obj_hdl)
{
	struct nedge_fsal_obj_handle *obj;
	object_file_type_t type = obj_hdl->type;

	LogDebug(COMPONENT_FSAL, " ");
	obj = container_of(obj_hdl, struct nedge_fsal_obj_handle,
	    obj_handle);
	LogDebug(COMPONENT_FSAL, "%ju", h2inode(obj));

	if (type == REGULAR_FILE &&
	    obj->u.file.openflags != FSAL_O_CLOSED) {
		fsal_status_t st = nedge_close(obj_hdl);
		if (FSAL_IS_ERROR(st)) {
			LogCrit(COMPONENT_FSAL,
				"Could not close, error %s(%d)",
				strerror(st.minor), st.minor);
		}
	}

	if (type == SYMBOLIC_LINK) {
		if (obj->u.symlink.link_content != NULL) {
			gsh_free(obj->u.symlink.link_content);
			obj->u.symlink.link_content = NULL;
		}
	}
}

void
nedge_handle_ops_init(struct fsal_obj_ops *ops)
{
	LogDebug(COMPONENT_FSAL, " ");
	fsal_default_obj_ops_init(ops);
	ops->release = release;
	ops->lookup = nedge_lookup;
	ops->readdir = nedge_readdir;
	ops->mkdir = nedge_mkdir;
	ops->mknode = nedge_makenode;
	ops->symlink = nedge_makesymlink;
	ops->readlink = nedge_readsymlink;
	ops->getattrs = nedge_getattrs;
	ops->link = nedge_linkfile;
	ops->rename = nedge_rename;
	ops->unlink = nedge_unlink;
	ops->handle_to_wire = nedge_handle_to_wire;
	ops->handle_to_key = nedge_handle_to_key;

	ops->close = nedge_close;

	/* fops with OpenTracking (multi-fd) enabled */
	ops->open2 = nedge_open2;
	ops->reopen2 = nedge_reopen2;
	ops->read2 = nedge_read2;
	ops->write2 = nedge_write2;
	ops->commit2 = nedge_commit2;
	ops->lock_op2 = nedge_lock_op2;
	ops->setattr2 = nedge_setattr2;
	ops->close2 = nedge_close2;
}

/* export methods that create object handles
 */

/* create_handle
 * Does what original FSAL_ExpandHandle did (sort of)
 * returns a ref counted handle to be later used in cache_inode etc.
 * NOTE! you must release this thing when done with it!
 * BEWARE! Thanks to some holes in the *AT syscalls implementation,
 * we cannot get an fd on an AF_UNIX socket.  Sorry, it just doesn't...
 * we could if we had the handle of the dir it is in, but this method
 * is for getting handles off the wire for cache entries that have LRU'd.
 * Ideas and/or clever hacks are welcome...
 */

fsal_status_t
nedge_create_handle(struct fsal_export *exp_hdl, struct gsh_buffdesc *hdl_desc,
    struct fsal_obj_handle **handle, struct attrlist *attrs_out)
{
	struct nedge_fsal_obj_handle *hdl;
	struct nedge_fsal_export *exp;
	struct nedge_file_handle fh;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	char *link_content = NULL;
	struct stat stat;
	int retval = 0;
	LogDebug(COMPONENT_FSAL, " hdl_desc = %p", hdl_desc);

	exp = container_of(exp_hdl, struct nedge_fsal_export, export);

	LogDebug(COMPONENT_FSAL, " ");
	*handle = NULL;		/* poison it first */
	link_content = NULL;
	if (hdl_desc->len > sizeof(struct nedge_file_handle))
		return fsalstat(ERR_FSAL_FAULT, 0);

	memcpy(&fh, hdl_desc->addr, hdl_desc->len);  /* struct aligned copy */

	LogDebug(COMPONENT_FSAL, "for inode %ju [%ju]", fh.inode,
	    fh.export_id);

	retval = FNEDGE_ERRMAP(ccow_fsio_get_file_stat(exp->ci, fh.inode,
	    &stat));
	if (retval == ENOENT) {
		LogDebug(COMPONENT_FSAL, "EOF");
		goto out;
	}
	if (retval != 0) {
		if (retval != EBUSY)
			retval = EIO;
		goto out;
	}

	if (S_ISLNK(stat.st_mode)) {
		LogDebug(COMPONENT_FSAL, "SYMLINK ");
		retval = FNEDGE_ERRMAP(ccow_fsio_readsymlink(exp->ci, fh.inode,
		    (char **)&link_content));
		if (retval)
			return fsalstat(posix2fsal_error(retval), retval);
	}
	hdl = nedge_alloc_handle(&fh, &stat, link_content, exp_hdl);
	ccow_fsio_free(exp->ci, link_content);
	if (hdl == NULL) {
		fsal_error = ERR_FSAL_NOMEM;
		return fsalstat(fsal_error, 0);
	}
	*handle = &hdl->obj_handle;

	if (attrs_out != NULL) {
		posix2fsal_attributes_all(&stat, attrs_out);
	}

	LogDebug(COMPONENT_FSAL, " ");
	return fsalstat(fsal_error, 0);
out:
	if (retval == ENOENT)
		return fsalstat(ERR_FSAL_STALE, retval);

	return fsalstat(posix2fsal_error(retval), retval);
}
