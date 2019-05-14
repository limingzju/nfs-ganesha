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

/* main.c
 * Module core functions
 */

#include "config.h"

#include "fsal.h"
#include <fcntl.h>
#include <libgen.h>		/* used for 'dirname' */
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <ccowfsio.h>
#include "gsh_list.h"
#include "fsal_internal.h"
#include "FSAL/fsal_init.h"

#include <ccowfsio.h>
/* NEDGE FSAL module private storage
 */

struct nedge_fsal_module {
	struct fsal_module fsal;
	struct fsal_staticfsinfo_t fs_info;
	ci_t *ci;
	char *ccow_config;
	char *uri;
};

const char myname[] = "NEDGE";

/* filesystem info for your filesystem */
static struct fsal_staticfsinfo_t default_nedge_info = {
	.maxfilesize = INT64_MAX,
	.maxlink = _POSIX_LINK_MAX,
	.maxnamelen = MAXNAMLEN,
	.maxpathlen = MAXPATHLEN,
	.no_trunc = true,
	.chown_restricted = true,
	.case_insensitive = false,
	.case_preserving = true,
	.link_support = false,
	.symlink_support = true,
	.lock_support = true,
	.lock_support_async_block = false,
	.named_attr = true,
	.unique_handles = true,
	.acl_support = FSAL_ACLSUPPORT_ALLOW | FSAL_ACLSUPPORT_DENY,
	.cansettime = true,
	.homogenous = true,
	.supported_attrs = NEDGE_SUPPORTED_ATTRIBUTES,
	.maxread = FSAL_MAXIOSIZE,
	.maxwrite = FSAL_MAXIOSIZE,
	.umask = 0,
	.auth_exportpath_xdev = false,
	.link_supports_permission_checks = true,
	.whence_is_name = false
};

static struct config_item nedge_params[] = {
	CONF_ITEM_BOOL("link_support", false,
		       fsal_staticfsinfo_t, link_support),
	CONF_ITEM_BOOL("symlink_support", true,
		       fsal_staticfsinfo_t, symlink_support),
	CONF_ITEM_BOOL("cansettime", true,
		       fsal_staticfsinfo_t, cansettime),
	CONF_ITEM_UI32("maxread", 512, FSAL_MAXIOSIZE, FSAL_MAXIOSIZE,
		       fsal_staticfsinfo_t, maxread),
	CONF_ITEM_UI32("maxwrite", 512, FSAL_MAXIOSIZE, FSAL_MAXIOSIZE,
		       fsal_staticfsinfo_t, maxwrite),
	CONF_ITEM_MODE("umask", 0,
		       fsal_staticfsinfo_t, umask),
	CONF_ITEM_BOOL("auth_xdev_export", false,
		       fsal_staticfsinfo_t, auth_exportpath_xdev),
	CONFIG_EOL
};

struct config_block nedge_param = {
	.dbus_interface_name = "org.ganesha.nfsd.config.fsal.nedge",
	.blk_desc.name = "NEDGE",
	.blk_desc.type = CONFIG_BLOCK,
	.blk_desc.u.blk.init = noop_conf_init,
	.blk_desc.u.blk.params = nedge_params,
	.blk_desc.u.blk.commit = noop_conf_commit
};

/* private helper for export object
 */

struct fsal_staticfsinfo_t *nedge_staticinfo(struct fsal_module *hdl)
{
	struct nedge_fsal_module *myself;

	LogDebug(COMPONENT_FSAL,"%s:%d: %s", __FILE__, __LINE__, __func__);
	myself = container_of(hdl, struct nedge_fsal_module, fsal);
	return &myself->fs_info;
}

/* Module methods
 */

/* init_config
 * must be called with a reference taken (via lookup_fsal)
 */

static fsal_status_t init_config(struct fsal_module *fsal_hdl,
				     config_file_t config_struct,
				     struct config_error_type *err_type)
{
	struct nedge_fsal_module *nedge_me =
	    container_of(fsal_hdl, struct nedge_fsal_module, fsal);

	LogDebug(COMPONENT_FSAL,"%s:%d: %s", __FILE__, __LINE__, __func__);
	nedge_me->fs_info = default_nedge_info;	/* copy the consts */
	(void) load_config_from_parse(config_struct,
				      &nedge_param,
				      &nedge_me->fs_info,
				      true,
				      err_type);
	display_fsinfo(&nedge_me->fsal);
	LogFullDebug(COMPONENT_FSAL,
		     "Supported attributes constant = 0x%" PRIx64,
		     (uint64_t) NEDGE_SUPPORTED_ATTRIBUTES);
	LogFullDebug(COMPONENT_FSAL,
		     "Supported attributes default = 0x%" PRIx64,
		     default_nedge_info.supported_attrs);
	LogDebug(COMPONENT_FSAL,
		 "FSAL INIT: Supported attributes mask = 0x%" PRIx64,
		 nedge_me->fs_info.supported_attrs);
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/* Internal NEDGE method linkage to export object
 */

fsal_status_t nedge_create_export(struct fsal_module *fsal_hdl,
				void *parse_node,
				struct config_error_type *err_type,
				const struct fsal_up_vector *up_ops);

/* Module initialization.
 * Called by dlopen() to register the module
 * keep a private pointer to me in myself
 */

/* my module private storage
 */

static struct nedge_fsal_module NEDGE;

MODULE_INIT void
nedge_load(void)
{
	int retval;
	struct fsal_module *myself = &NEDGE.fsal;

	LogDebug(COMPONENT_FSAL,"%s:%d: %s", __FILE__, __LINE__, __func__);

	retval = register_fsal(myself, myname,
			       FSAL_MAJOR_VERSION,
			       FSAL_MINOR_VERSION,
			       FSAL_ID_NO_PNFS);
	if (retval != 0) {
		fprintf(stderr, "NEDGE module failed to register");
		return;
	}
	myself->m_ops.create_export = nedge_create_export;
	myself->m_ops.init_config = init_config;

	ccow_fsio_init();
}

MODULE_FINI void
nedge_unload(void)
{
	int retval;

	LogDebug(COMPONENT_FSAL,"%s:%d: %s", __FILE__, __LINE__, __func__);

	ccow_fsio_term();

	retval = unregister_fsal(&NEDGE.fsal);
	if (retval != 0) {
		fprintf(stderr, "NEDGE module failed to unregister");
		return;
	}
}

int
FNEDGE_ERRMAP(int err)
{
	err = (err > 0)?err:-err;
	switch (err) {
	case ENOSPC:
		return (EBUSY);
	case EINVAL:
		return (EAGAIN);
	}
	return (err);
}
