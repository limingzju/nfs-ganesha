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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * -------------
 */

/* export.c
 * NEDGE FSAL export object
 */

#include "config.h"

#include "fsal.h"
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include "gsh_list.h"
#include "fsal_internal.h"
#include "fsal_convert.h"
#include "FSAL/fsal_commonlib.h"
#include "FSAL/fsal_config.h"
#include "nedge_methods.h"
#include "nfs_exports.h"
#include "export_mgr.h"
#include "mdcache.h"

/*
 * helpers to/from other NEDGE objects
 */

struct fsal_staticfsinfo_t *nedge_staticinfo(struct fsal_module *hdl);

/*
 * export object methods.
 */

static void release(struct fsal_export *exp_hdl)
{
	struct nedge_fsal_export *export;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	export = container_of(exp_hdl, struct nedge_fsal_export, export);

	LogDebug(COMPONENT_FSAL, " export fullpath = %s", export->fullpath);
	ccow_fsio_delete_export(export->ci);
	gsh_free(export->up_args);
	gsh_free(export->fullpath);
	ccow_fsio_ci_free(export->ci);

	fsal_detach_export(exp_hdl->fsal, &exp_hdl->exports);
	free_export_ops(exp_hdl);

	gsh_free(export);		/* elvis has left the building */
}

static fsal_status_t get_dynamic_info(struct fsal_export *exp_hdl,
				      struct fsal_obj_handle *obj_hdl,
				      fsal_dynamicfsinfo_t *infop)
{
	struct nedge_fsal_export *export;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;

	if (!infop) {
		fsal_error = ERR_FSAL_FAULT;
		goto out;
	}
	export = container_of(exp_hdl, struct nedge_fsal_export, export);
	LogDebug(COMPONENT_FSAL,"%s:%d: %p", __FILE__, __LINE__, export);

	if (retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto out;
	}

	ccow_fsio_fsinfo(export->ci, (fsio_fsinfo_t *)infop);

	infop->time_delta.tv_sec = 1;
	infop->time_delta.tv_nsec = 0;

out:
	return fsalstat(fsal_error, retval);
}

static bool fs_supports(struct fsal_export *exp_hdl,
			fsal_fsinfo_options_t option)
{
	struct fsal_staticfsinfo_t *info;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	info = nedge_staticinfo(exp_hdl->fsal);
	return fsal_supports(info, option);
}

static uint64_t fs_maxfilesize(struct fsal_export *exp_hdl)
{
	struct fsal_staticfsinfo_t *info;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	info = nedge_staticinfo(exp_hdl->fsal);
	return fsal_maxfilesize(info);
}

static uint32_t fs_maxread(struct fsal_export *exp_hdl)
{
	struct fsal_staticfsinfo_t *info;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	info = nedge_staticinfo(exp_hdl->fsal);
	return fsal_maxread(info);
}

static uint32_t fs_maxwrite(struct fsal_export *exp_hdl)
{
	struct fsal_staticfsinfo_t *info;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	info = nedge_staticinfo(exp_hdl->fsal);
	return fsal_maxwrite(info);
}

static uint32_t fs_maxlink(struct fsal_export *exp_hdl)
{
	struct fsal_staticfsinfo_t *info;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	info = nedge_staticinfo(exp_hdl->fsal);
	return fsal_maxlink(info);
}

static uint32_t fs_maxnamelen(struct fsal_export *exp_hdl)
{
	struct fsal_staticfsinfo_t *info;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	info = nedge_staticinfo(exp_hdl->fsal);
	return fsal_maxnamelen(info);
}

static uint32_t fs_maxpathlen(struct fsal_export *exp_hdl)
{
	struct fsal_staticfsinfo_t *info;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	info = nedge_staticinfo(exp_hdl->fsal);
	return fsal_maxpathlen(info);
}

static fsal_aclsupp_t fs_acl_support(struct fsal_export *exp_hdl)
{
	struct fsal_staticfsinfo_t *info;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	info = nedge_staticinfo(exp_hdl->fsal);
	return fsal_acl_support(info);
}

static attrmask_t fs_supported_attrs(struct fsal_export *exp_hdl)
{
	struct fsal_staticfsinfo_t *info;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	info = nedge_staticinfo(exp_hdl->fsal);
	return fsal_supported_attrs(info);
}

static uint32_t fs_umask(struct fsal_export *exp_hdl)
{
	struct fsal_staticfsinfo_t *info;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	info = nedge_staticinfo(exp_hdl->fsal);
	return fsal_umask(info);
}

/* extract a file handle from a buffer.
 * do verification checks and flag any and all suspicious bits.
 * Return an updated fh_desc into whatever was passed.  The most
 * common behavior, done here is to just reset the length.  There
 * is the option to also adjust the start pointer.
 * Invariant that must be maintained:
 * host_to_key(wire_to_host(handle_to_wire(obj_hdl))) = handle_to_key(obj_hdl)
 */

static fsal_status_t nedge_wire_to_host(struct fsal_export *exp_hdl,
					 fsal_digesttype_t in_type,
					 struct gsh_buffdesc *fh_desc,
					 int flags)
{

	LogDebug(COMPONENT_FSAL," ");

	/* sanity checks */
	if (!fh_desc || !fh_desc->addr) {
		LogDebug(COMPONENT_FSAL," sanity checks fail.");
		return fsalstat(ERR_FSAL_FAULT, 0);
	}

	LogDebug(COMPONENT_FSAL," fh_desc = %p, fh_desc->addr = %p, len = %ju",
	    fh_desc, fh_desc->addr, fh_desc->len);

	switch (in_type) {
		/* Digested Handles */
	case FSAL_DIGEST_NFSV3:
	case FSAL_DIGEST_NFSV4:
		/* wire handles */
		fh_desc->len = sizeof(struct nedge_file_handle);
		break;
	default:
		LogDebug(COMPONENT_FSAL," Wrong in_type(%d); fh_desc = %p, "
		    "fh_desc->addr = %p, len = %ju", in_type,
		    fh_desc, fh_desc->addr, fh_desc->len);
		return fsalstat(ERR_FSAL_SERVERFAULT, 0);
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/* nedge_export_ops_init
 * overwrite vector entries with the methods that we support
 */

void nedge_export_ops_init(struct export_ops *ops)
{
	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	ops->release = release;
	ops->lookup_path = nedge_lookup_path;
	ops->wire_to_host = nedge_wire_to_host;
	ops->create_handle = nedge_create_handle;
	ops->get_fs_dynamic_info = get_dynamic_info;
	ops->fs_supports = fs_supports;
	ops->fs_maxfilesize = fs_maxfilesize;
	ops->fs_maxread = fs_maxread;
	ops->fs_maxwrite = fs_maxwrite;
	ops->fs_maxlink = fs_maxlink;
	ops->fs_maxnamelen = fs_maxnamelen;
	ops->fs_maxpathlen = fs_maxpathlen;
	ops->fs_acl_support = fs_acl_support;
	ops->fs_supported_attrs = fs_supported_attrs;
	ops->fs_umask = fs_umask;
	ops->alloc_state = nedge_alloc_state;
}

static struct config_item export_params[] = {
	CONF_ITEM_NOOP("name"),
	CONF_ITEM_PATH("ccow_config", 1, 256, "/opt/nedge/etc/ccow/ccow.json",
	    nedge_fsal_export, ccow_config),
	CONF_MAND_STR("uri", 6, 256, "test/cltest/NFS-bucket",
	    nedge_fsal_export, uri),
	CONFIG_EOL
};

static struct config_block export_param = {
	.dbus_interface_name = "org.ganesha.nfsd.config.fsal.nedge-export",
	.blk_desc.name = "FSAL",
	.blk_desc.type = CONFIG_BLOCK,
	.blk_desc.u.blk.init = noop_conf_init,
	.blk_desc.u.blk.params = export_params,
	.blk_desc.u.blk.commit = noop_conf_commit
};

/* create_export
 * Create an export point and return a handle to it to be kept
 * in the export list.
 * First lookup the fsal, then create the export and then put the fsal back.
 * returns the export with one reference taken.
 */
fsal_status_t nedge_create_export(struct fsal_module *fsal_hdl,
				void *parse_node,
				struct config_error_type *err_type,
				const struct fsal_up_vector *up_ops)
{
	struct nedge_fsal_export *export;
	fsal_errors_t fsal_error;
	struct stat stat;
	inode_t inode;
	int retval;
	struct nedge_fsal_up_args *up_args = NULL;

	export = NULL;
	retval = 0;
	fsal_error = ERR_FSAL_INVAL;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	export = gsh_calloc(1, sizeof(struct nedge_fsal_export));
	if (export == NULL) {
		LogMajor(COMPONENT_FSAL,
			 "nedge_fsal_create: out of memory for object");
		return fsalstat(posix2fsal_error(errno), errno);
	}

	up_args = gsh_calloc(1, sizeof(struct nedge_fsal_up_args));
	if (up_args == NULL) {
		LogMajor(COMPONENT_FSAL,
		    "nedge_fsal_create: out of memory for object");
		return fsalstat(posix2fsal_error(errno), errno);
	}
	up_args->export = export;
	up_args->fsal_hdl = fsal_hdl;
	export->up_args = up_args;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	fsal_export_init(&export->export);

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	nedge_export_ops_init(&export->export.exp_ops);
	export->export.up_ops = up_ops;
	export->export_id = op_ctx->ctx_export->export_id;

	LogDebug(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	retval = load_config_from_node(parse_node, &export_param, export, true,
	    err_type);
	if (retval != 0) {
		goto errout;
	}

	LogEvent(COMPONENT_FSAL,"CCOW config file \"%s\"", export->ccow_config);
	LogEvent(COMPONENT_FSAL,"Backet URI \"%s\"", export->uri);
	export->fullpath = gsh_strdup(op_ctx->ctx_export->fullpath);
	export->ci = ccow_fsio_ci_alloc();

	retval = FNEDGE_ERRMAP(ccow_fsio_create_export(export->ci, export->uri,
	    export->ccow_config, 4096, nedge_fsal_up, (void *)up_args));
	if (retval != 0) {
		LogEvent(COMPONENT_FSAL,"ccow_fsio_init return \"%d\"", retval);
		retval = EINVAL;
		goto errout;
	}

	retval = FNEDGE_ERRMAP(ccow_fsio_get_file_stat(export->ci,
	    CCOW_FSIO_ROOT_INODE, &stat));
	if (retval == ENOENT) {
		/*
		 * XXX We have to get default params (mode, uid, gid, etc) or
		 * policy on what to do if no file attr for inode
		 * CCOW_FSIO_ROOT_INODE.
		 */
		stat.st_ino = CCOW_FSIO_ROOT_INODE;
		stat.st_size = stat.st_gid = stat.st_uid = 0;
		stat.st_mode = S_IFDIR | 0755;
		ccow_fsio_mkdir(export->ci, CCOW_FSIO_ROOT_INODE,
		    ".nedge.nfs.test", stat.st_mode, stat.st_uid, stat.st_gid,
		    &inode);
		ccow_fsio_delete(export->ci, CCOW_FSIO_ROOT_INODE,
		    ".nedge.nfs.test");
		ccow_fsio_set_file_stat(export->ci, CCOW_FSIO_ROOT_INODE,
		    &stat);
		retval = FNEDGE_ERRMAP(ccow_fsio_get_file_stat(export->ci,
		    CCOW_FSIO_ROOT_INODE, &stat));
	}
	if (retval != 0) {
		LogEvent(COMPONENT_FSAL,"ccow_fsio_get_file_stat return \"%d\"",
		    retval);
		retval = EINVAL;
		goto errout;
	}

	LogEvent(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	retval = fsal_attach_export(fsal_hdl, &export->export.exports);
	if (retval != 0)
		goto err_locked;	/* seriously bad */
	export->export.fsal = fsal_hdl;

	op_ctx->fsal_export = &export->export;

	LogEvent(COMPONENT_FSAL,"%s:%d:", __FILE__, __LINE__);
	return fsalstat(ERR_FSAL_NO_ERROR, 0);

err_locked:
	if (export->export.fsal != NULL)
		fsal_detach_export(fsal_hdl, &export->export.exports);
errout:
	if (export->fullpath != NULL)
		gsh_free(export->fullpath);
	if (export->ci != NULL)
		ccow_fsio_ci_free(export->ci);
	if (export->up_args != NULL)
		gsh_free(export->up_args);
	if (export != NULL)
		gsh_free(export);	/* elvis has left the building */
	return fsalstat(fsal_error, retval);
}

