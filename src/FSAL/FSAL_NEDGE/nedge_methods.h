#include <ccowfsio.h>

/* NEDGE methods for handles
 */

void nedge_handle_ops_init(struct fsal_obj_ops *ops);

/* private helpers from export
 */

ci_t * nedge_get_root_pvfs(struct fsal_export *exp_hdl);

/* method proto linkage to handle.c for export
 */

fsal_status_t nedge_lookup_path(struct fsal_export *exp_hdl, const char *path,
    struct fsal_obj_handle **handle, struct attrlist *attrs_out);

fsal_status_t nedge_create_handle(struct fsal_export *exp_hdl,
    struct gsh_buffdesc *hdl_desc, struct fsal_obj_handle **handle,
    struct attrlist *attrs_out);

struct nedge_fsal_up_args {
    struct fsal_module *fsal_hdl;
    struct nedge_fsal_export *export;
};

int nedge_fsal_up(void *args, inode_t inode, uint64_t ccow_fsio_up_flags);

/*
 * NEDGE internal export
 */
struct nedge_fsal_export {
	struct fsal_export export;
	uint64_t export_id;
	char *uri;
	char *ccow_config;
	char *fullpath;
	int chunkSize;
	ci_t *ci;
    struct nedge_fsal_up_args *up_args;
};

struct nedge_fd {
	fsal_openflags_t openflags;
	ccow_fsio_file_t *file;
	struct fsal_share share;
};

struct nedge_fsal_obj_handle {
	struct fsal_obj_handle obj_handle;
	struct fsal_obj_ops obj_ops;
	struct attrlist attributes;
	struct nedge_file_handle *handle;
	uint64_t export_id;
	ci_t *ci;
	struct nedge_fd globalfd;
	struct fsal_share share;
	union {
		struct {
			struct fsal_share share;
			fsal_openflags_t openflags;
			ccow_fsio_file_t *file;
		} file;
		struct {
			unsigned char *link_content;
			int link_size;
		} symlink;
	} u;
};

#define	h2inode(hdl)	((hdl)->handle->inode)
#define filemode(attr, ctx) (fsal2unix_mode((attr)->mode) & \
    ~(ctx)->fsal_export->exp_ops.fs_umask((ctx)->fsal_export))

	/* I/O management */
fsal_status_t nedge_close(struct fsal_obj_handle *obj_hdl);
fsal_status_t nedge_merge(struct fsal_obj_handle *orig_hdl,
    struct fsal_obj_handle *dupe_hdl);
fsal_status_t nedge_open2(struct fsal_obj_handle *obj_hdl,
    struct state_t *state, fsal_openflags_t openflags,
    enum fsal_create_mode createmode, const char *name,
    struct attrlist *attrib_set, fsal_verifier_t verifier,
    struct fsal_obj_handle **new_obj, struct attrlist *attrs_out,
    bool * caller_perm_check);
fsal_status_t nedge_reopen2(struct fsal_obj_handle *obj_hdl,
    struct state_t *state, fsal_openflags_t openflags);
void nedge_read2(struct fsal_obj_handle *obj_hdl, bool bypass, fsal_async_cb done_cb,
    struct fsal_io_arg *read_arg, void *caller_arg);
void nedge_write2(struct fsal_obj_handle *obj_hdl, bool bypass, fsal_async_cb done_cb,
    struct fsal_io_arg *write_arg, void *caller_arg);
fsal_status_t nedge_commit2(struct fsal_obj_handle *obj_hdl, off_t offset,
    size_t len);
fsal_status_t nedge_lock_op2(struct fsal_obj_handle *obj_hdl,
    struct state_t *state, void *p_owner, fsal_lock_op_t lock_op,
    fsal_lock_param_t * request_lock, fsal_lock_param_t * conflicting_lock);
fsal_status_t nedge_close2(struct fsal_obj_handle *obj_hdl,
    struct state_t *state);
fsal_status_t nedge_setattr2(struct fsal_obj_handle *obj_hdl, bool bypass,
    struct state_t *state, struct attrlist *attrib_set);
struct state_t *nedge_alloc_state(struct fsal_export *exp_hdl,
    enum state_type state_type, struct state_t *related_state);

/* extended attributes management */
fsal_status_t nedge_list_ext_attrs(struct fsal_obj_handle *obj_hdl,
    unsigned int cookie, fsal_xattrent_t *xattrs_tab,
    unsigned int xattrs_tabsize, unsigned int *p_nb_returned, int *end_of_list);
fsal_status_t nedge_getextattr_id_by_name(struct fsal_obj_handle *obj_hdl,
    const char *xattr_name, unsigned int *pxattr_id);
fsal_status_t nedge_getextattr_value_by_name(struct fsal_obj_handle *obj_hdl,
    const char *xattr_name, caddr_t buffer_addr, size_t buffer_size,
    size_t *p_output_size);
fsal_status_t nedge_getextattr_value_by_id(struct fsal_obj_handle *obj_hdl,
    unsigned int xattr_id, caddr_t buffer_addr, size_t buffer_size,
    size_t *p_output_size);
fsal_status_t nedge_setextattr_value(struct fsal_obj_handle *obj_hdl,
    const char *xattr_name, caddr_t buffer_addr, size_t buffer_size,
    int create);
fsal_status_t nedge_setextattr_value_by_id(struct fsal_obj_handle *obj_hdl,
    unsigned int xattr_id, caddr_t buffer_addr, size_t buffer_size);
fsal_status_t nedge_getextattr_attrs(struct fsal_obj_handle *obj_hdl,
    unsigned int xattr_id, struct attrlist *p_attrs);
fsal_status_t nedge_remove_extattr_by_id(struct fsal_obj_handle *obj_hdl,
    unsigned int xattr_id);
fsal_status_t nedge_remove_extattr_by_name(struct fsal_obj_handle *obj_hdl,
    const char *xattr_name);
fsal_status_t nedge_lock_op(struct fsal_obj_handle *obj_hdl, void *p_owner,
    fsal_lock_op_t lock_op, fsal_lock_param_t *request_lock,
    fsal_lock_param_t *conflicting_lock);
