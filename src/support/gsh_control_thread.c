#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <pthread.h>

#include "fsal_api.h"
#include "nfs_core.h"
#include "nfs_exports.h"

#define EPOLL_ARRAY_SIZE   64
#define	CLIENT_SEND_BUFFER_SZ	0x10000 /* 64k */
#define	GSH_CONTROL_SOCKET_PORT	20000
#define	SKIPSPACES(s) do { while(*s && isspace(*s)) s++; } while(0)
#define	MATCH(v, s)	\
    (strcasestr(v, #s) == v && (isspace(v[strlen(#s)]) || v[strlen(#s)] == '\0'))

pthread_t gsh_control_thrid;

struct client;

struct client {
	struct client *next;
	int fd, rp, wp, buflen;
#define	CLIENT_STATUS_DISCONNECT	1
	int status;
	char rbuf[PATH_MAX];
	char *buf;
};

static int gsh_control_addexport(char *, char *, char *);
static int gsh_control_removeexport(uint16_t);
static int gsh_control_exportlist(struct client *);

int gsh_control_thread_shutdown;

/* Simple SLL. */
static struct client *
CLIENT_LIST_PREPEND(struct client **q, int fd)
{
	struct client *e;

	e = gsh_calloc(1, sizeof(struct client));
	e->buf = (char *)gsh_malloc(CLIENT_SEND_BUFFER_SZ);
	e->fd = fd;
	e->buflen = CLIENT_SEND_BUFFER_SZ;
	if (*q != NULL)
		e->next = *q;
	*q = e;

	return (e);
}

static struct client *
CLIENT_LIST_FIND(struct client *q, int fd)
{
	struct client * c;

	for (c = q; c != NULL; c = c->next) {
		if (c->fd == fd)
			return (c);
	}

	return (NULL);
}

static void
CLIENT_LIST_DESTROY(struct client *q)
{
	struct client * c, *tmp;

	for (c = q; c != NULL;) {
		tmp = c->next;
		shutdown(c->fd, SHUT_RDWR);
		close(c->fd);
		if (c->buf)
			gsh_free(c->buf);
		gsh_free(c);
		c = tmp;
	}
}

static void
CLIENT_LIST_REMOVE(struct client **q, struct client *e)
{
	struct client * c;

	if (*q == NULL || e == NULL)
		return;

	/* Most frequent way. */
	if ((*q)->next == NULL && *q == e) {
		*q = NULL;
		goto done;
	}

	for (c = *q; c != NULL; c = c->next) {
		if (c->next == e) {
			c->next = e->next; /* Same as c->next->next. */
			goto done;
		}
	}

	/* Not found. */
	return;
done:
	shutdown(e->fd, SHUT_RDWR);
	close(e->fd);
	gsh_free(e->buf);
	gsh_free(e);
}

void
stripcrlf(char *s)
{
	char *d;

	d = strchr(s, '\r');
	if (d == NULL)
		d = strchr(s, '\n');
	if (d == NULL)
		return;
	*d = '\0';
}

int
parsecmd(struct client *e)
{
	char *cmd, *d, err[255], *export, export_expr[255];
	unsigned int exportId;

	cmd = e->rbuf;
	stripcrlf(cmd);

	*e->buf = '\0';
	e->wp = 0;
	e->rp = 0;
	SKIPSPACES(cmd);
	if (MATCH(cmd, EXPORT)) {
		/* Skip EXPORT\s+ */
		cmd += 6; SKIPSPACES(cmd);
		if (MATCH(cmd, ADD)) {
			/* Skip ADD\s+ */
			cmd += strlen("ADD"); SKIPSPACES(cmd);
			export = cmd;
			d = strchr(cmd, ' ');
			if (*export == '\0' || d == NULL) {
				sprintf(e->buf,
				    "ERR: FORMAT: EXPORT ADD 1 path\n");
				goto failed;
			}
			*d = '\0'; d++; SKIPSPACES(d);
			cmd = d;
			exportId = strtoul(export, &d, 10);
			if ((d - export) < strlen(export) || strlen(cmd) == 0) {
				sprintf(e->buf,
				    "ERR: FORMAT: EXPORT ADD 1 path\n");
				goto failed;
			}
			snprintf(export_expr, 255, "EXPORT(Export_ID=%d)",
			    exportId);
			if (gsh_control_addexport(cmd, export_expr, err) ==
			    false) {
				sprintf(e->buf, "ERR: Add export (%d, \"%s\") "
				    "failed. %s\n", exportId, cmd, err);
			} else {
				sprintf(e->buf, "OK: Add export (%d, \"%s\")\n",
				    exportId, cmd);
			}
		} else if (MATCH(cmd, REMOVE)) {
			/* Skip REMOVE\s+ */
			cmd += strlen("REMOVE"); SKIPSPACES(cmd);
			export = cmd;
			if (strlen(export) <= 0) {
				sprintf(e->buf,
				    "ERR: FORMAT: EXPORT REMOVE 1\n");
				goto failed;
			}
			exportId = strtoul(export, &d, 10);
			if ((d - export) < strlen(export)) {
				sprintf(e->buf,
				    "ERR: FORMAT: EXPORT REMOVE 1\n");
				goto failed;
			}
			if (gsh_control_removeexport(exportId) == ENOENT) {
				sprintf(e->buf, "ERR: No such export %d\n",
				    exportId);
			} else {
				sprintf(e->buf, "OK: export %d removed\n",
				    exportId);
			}
		} else if (MATCH(cmd, LIST)) {
			gsh_control_exportlist(e);
		} else {
			sprintf(e->buf,
			    "ERR: Unknown EXPORT subcommand \"%s\"\n", cmd);
		}
	} else if (MATCH(cmd, QUIT)) {
		sprintf(e->buf, "OK: Bye\n");
		e->status |= CLIENT_STATUS_DISCONNECT; /* Done. */
	} else if (MATCH(cmd, HELP)) {
		sprintf(e->buf, "OK:\n"
		    "EXPORT ADD 1 /etc/ganesha/export_1.txt\t(1 - Export_Id, "
			"/etc/ganesha/export_1.txt - part of config file "
			"describing export with Id = 1.)\n"
		    "EXPORT REMOVE 1\t\t\t\t(1 - Export_Id to remove.)\n"
		    "EXPORT LIST\t\t\t\t(Display list of exports in format: "
			"\"Id<Tab>ExportPath<Tab>FSAL_Name\". "
			"List ends with \".\" line.)\n"
		    "QUIT\t\t\t\t\t(Close connection)\n"
		    "HELP\t\t\t\t\t(Display this help)\n"
		    ".\n"
		);
	} else {
		sprintf(e->buf, "ERR: Unknown command \"%s\"\n", cmd);
	}
failed:
	*e->rbuf = '\0';

	return (0);
}

void *
gsh_control_thread(void *arg)
{
	int csock, efd, fd, i, rval, sock;
	struct epoll_event ev, epoll_events[EPOLL_ARRAY_SIZE];
	struct sockaddr_in bindaddr, peeraddr;
	struct client *clients, *client;
	unsigned short port;
	struct hostent *he;
	socklen_t salen;
	uint32_t events;
	ssize_t rc;
	char *bindhost;

	bindhost = nfs_param.core_param.control_socket_bind_addr;
	clients = NULL;
	salen = sizeof(peeraddr);
	port = nfs_param.core_param.control_socket_port;

	if ((he = gethostbyname(bindhost)) == NULL) {
		LogCrit(COMPONENT_EXPORT,
		    "Could not get address for hostname %s: %m", bindhost);
		return (NULL);
	}

	efd = epoll_create(1);
	if (efd < 0) {
		LogCrit(COMPONENT_EXPORT, "Could not create the epoll fd: %m");
		return (NULL);
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		LogCrit(COMPONENT_EXPORT, "Could not create new sock: %m");
		return (NULL);
	}

	if (fcntl(sock, F_SETFL, O_NONBLOCK)) {
		LogCrit(COMPONENT_EXPORT,
		    "Could not make the socket non-blocking: %m");
		close(sock);
		return (NULL);
	}

	i = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i))) {
		LogCrit(COMPONENT_EXPORT,
		    "Could not set socket %d option for reusability: %m", sock);
		close(sock);
		return (NULL);
	}

	memcpy(&bindaddr.sin_addr, he->h_addr_list[0], he->h_length);
	bindaddr.sin_family= AF_INET;
	bindaddr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *) &bindaddr,
	    sizeof(struct sockaddr_in)) < 0) {
		LogCrit(COMPONENT_EXPORT, "Could not bind socket %d to "
		    "address 'INADDR_ANY' and port %u: %m", sock, port);
		close(sock);
		return (NULL);
	}

	LogEvent(COMPONENT_INIT, "Bind control socket to %s:%d",bindhost,
	    port);

	if (listen(sock, SOMAXCONN)) {
		LogCrit(COMPONENT_EXPORT,
		    "Could not start listening on server socket %d: %m", sock);
		goto cleanup;
	}

	ev.events = EPOLLIN;
	ev.data.u64 = 0LL;
	ev.data.fd = sock;

	if (epoll_ctl(efd, EPOLL_CTL_ADD, sock, &ev) < 0) {
		LogCrit(COMPONENT_EXPORT,
		    "Couldn't add server socket %d to epoll set: %m", sock);
		goto cleanup;
	}

	for (;;) {

		while ((rval = epoll_wait(efd, epoll_events, EPOLL_ARRAY_SIZE,
		    100)) < 0) {
			if ((rval < 0) && (errno != EINTR)) {
				goto cleanup;
			}
		}

		for (i = 0; i < rval; i++) {
			events = epoll_events[i].events;
			fd = epoll_events[i].data.fd;

			if (events & (EPOLLERR|EPOLLHUP|EPOLLRDHUP)) {
				if (fd == sock) {
					goto cleanup;
				}
				CLIENT_LIST_REMOVE(&clients,
				    CLIENT_LIST_FIND(clients, fd));
				continue;
			}

			if (events & EPOLLIN) {
				/* Server socket. */
				if (fd == sock) {
					while ((csock = accept(sock,
					    (struct sockaddr *) &peeraddr,
					    &salen)) < 0) {
						if ((csock < 0) &&
						    (errno != EINTR)) {
							LogCrit(
							    COMPONENT_EXPORT,
							    "Accept on socket "
							    "%d failed: %m",
							    sock);
							goto cleanup;
						}
					}

					/* ACK event. */
					ev.events = EPOLLIN;
					ev.data.u64 = 0LL;
					ev.data.fd = csock;

					if (epoll_ctl(efd, EPOLL_CTL_ADD,
						    csock, &ev) < 0) {
						LogCrit(COMPONENT_EXPORT,
						    "Couldn't add client socket"
						    " %d to epoll set: %m",
						    csock);
						goto cleanup;
					}

					CLIENT_LIST_PREPEND(&clients, csock);
					continue;
				}

				client = CLIENT_LIST_FIND(clients, fd);
				if (client == NULL) {
					goto cleanup;
				}

				/* Client socket. */
				while ((rc = recv(fd, client->rbuf + client->rp,
						    PATH_MAX - client->rp, 0)) <
				    0) {
					if ((rc < 0) && (errno != EINTR)) {
						CLIENT_LIST_REMOVE(&clients,
						    client);
						continue;
					}
				}

				if (rc == 0) {
					CLIENT_LIST_REMOVE(&clients, client);
					continue;
				}

				if (rc > 0) {
					client->rp += rc;
					if (client->rp > PATH_MAX) {
						/* Error in request. */
						client->rp = 0;
						*client->rbuf = '\0';
					}
					client->buf[client->rp] = '\0';
					if (strchr(client->rbuf, '\n') != NULL)
						parsecmd(client);

					/* ACK event. */
					ev.events = EPOLLIN | EPOLLOUT;
					ev.data.u64 = 0LL;
					ev.data.fd = fd;

					if (epoll_ctl(efd, EPOLL_CTL_MOD, fd,
						    &ev) < 0) {
						LogCrit(COMPONENT_EXPORT,
						    "Couldn't modify client "
						    "socket %d in epoll set: %m",
						    fd);
						goto cleanup;
					}
				}

			}

			if ((events & EPOLLOUT) && (fd != sock)) {
				client = CLIENT_LIST_FIND(clients, fd);
				if (client == NULL) {
					goto cleanup;
				}

				while ((rc = send(fd, client->buf,
						    strlen(client->buf), 0)) <
				    0) {
					if ((rc < 0) && (errno != EINTR)) {
						LogCrit(COMPONENT_EXPORT,
						    "Send to socket %d failed:"
						    " %m", fd);
						CLIENT_LIST_REMOVE(&clients,
						    client);
						continue;
					}
				}

				if (rc == 0) {
					LogCrit(COMPONENT_EXPORT,
					    "Closing socket with sock %d", fd);
					CLIENT_LIST_REMOVE(&clients, client);
					continue;
				}

				if (rc > 0) {
					client->wp += rc;

					/* ACK event. */
					ev.events = EPOLLIN;
					ev.data.u64 = 0LL;
					ev.data.fd = fd;

					if (epoll_ctl(efd, EPOLL_CTL_MOD, fd,
						    &ev) < 0) {
						LogCrit(COMPONENT_EXPORT,
						    "Couldn't modify client "
						    "socket %d in epoll set: %m",
						    fd);
						goto cleanup;
					}
					if (client->status &
					    CLIENT_STATUS_DISCONNECT)
						CLIENT_LIST_REMOVE(&clients,
						    client);
				}
			}
		}
		if (gsh_control_thread_shutdown)
			goto cleanup;
	}

cleanup:
	CLIENT_LIST_DESTROY(clients);
	LogEvent(COMPONENT_MAIN, "Shutdown control socket handler");
	shutdown(sock, SHUT_RDWR);
	close(sock);
	close(efd);

	return (NULL);
}

static int
gsh_control_addexport(char *exportFilePath, char *export_expr, char *error)
{
	int rc, exp_cnt = 0;
	bool status = true;
	config_file_t config_struct = NULL;
	struct config_node_list *config_list, *lp, *lp_next;
	struct config_error_type err_type;
	char *err_detail = NULL;

	LogInfo(COMPONENT_EXPORT, "Adding export from file: %s with %s",
		exportFilePath, export_expr);

	/* Create a memstream for parser+processing error messages */
	if (!init_error_type(&err_type))
		goto out;

	config_struct = config_ParseFile(exportFilePath, &err_type);
	if (!config_error_is_harmless(&err_type)) {
		err_detail = err_type_str(&err_type);
		LogCrit(COMPONENT_EXPORT,
			"Error while parsing %s", exportFilePath);
		sprintf(error, "Error while parsing %s: %s", exportFilePath,
		    err_detail);
		status = false;
		goto out;
	}

	rc = find_config_nodes(config_struct, export_expr, &config_list,
	    &err_type);
	if (rc != 0) {
		LogCrit(COMPONENT_EXPORT,
			"Error finding exports: %s because %s",
			export_expr, strerror(rc));
		sprintf(error, "Error finding exports: %s because %s",
			export_expr, strerror(rc));
		status = false;
		goto out;
	}

	/* Load export entries from list */
	for (lp = config_list; lp != NULL; lp = lp_next) {
		lp_next = lp->next;
		if (status) {
			rc = load_config_from_node(lp->tree_node,
			    &add_export_param, NULL, false, &err_type);
			if (rc == 0 || config_error_is_harmless(&err_type))
				exp_cnt++;
			else if (!err_type.exists)
				status = false;
		}
		gsh_free(lp);
	}

	if (status) {
		if (exp_cnt > 0) {
			LogInfo(COMPONENT_EXPORT, "%d exports added", exp_cnt);
			sprintf(error, "%d exports added", exp_cnt);
		} else if (err_type.exists) {
			LogWarn(COMPONENT_EXPORT,
			    "Selected entries in %s already active!!!",
			    exportFilePath);
			sprintf(error,
			    "Selected entries in %s already active!!!",
			    exportFilePath);
			status = false;
		} else {
			LogWarn(COMPONENT_EXPORT,
			    "No usable export entry found in %s!!!",
			    exportFilePath);
			sprintf(error, "No usable export entry found in %s!!!",
			    exportFilePath);
			status = false;
		}
		goto out;
	} else {
		err_detail = err_type_str(&err_type);
		LogCrit(COMPONENT_EXPORT,
		    "%d export entries in %s added because %s errors", exp_cnt,
		    exportFilePath, err_detail != NULL ? err_detail : "unknown");
		sprintf(error,
		    "%d export entries in %s added because %s errors", exp_cnt,
		    exportFilePath, err_detail != NULL ? err_detail : "unknown");
	}

out:
	if (err_detail != NULL)
		free(err_detail);
	config_Free(config_struct);
	return status;
}

static int
gsh_control_removeexport(uint16_t export_id)
{
	struct gsh_export * export;

	if (export_id == 0)
		return (ENOENT);

	export = get_gsh_export(export_id);
	if (export == NULL)
		return (ENOENT);

	unexport(export);
	LogInfo(COMPONENT_EXPORT, "Removed export with id %d",
	    export->export_id);

	put_gsh_export(export);

	return (0);
}

static bool
gsh_export_cb(struct gsh_export *export, void *state)
{
	struct client *client;
	int len;

	client = (struct client *)state;
	len = strlen(client->buf) + snprintf(NULL, 0, "%d\t%s\t%s\n",
	    export->export_id, export->fullpath,
	    export->fsal_export->fsal->name) + 1;

	if (client->buflen < len ) {
		client->buflen = len;
		client->buf = gsh_realloc(client->buf, client->buflen);
		if (client->buf == NULL)
			return (false);
	}
	sprintf(client->buf + strlen(client->buf), "%d\t%s\t%s\n",
	    export->export_id, export->fullpath,
	    export->fsal_export->fsal->name);

	return (true);
}

static int
gsh_control_exportlist(struct client *client)
{

	sprintf(client->buf, "OK: exports list:\n");
	foreach_gsh_export(gsh_export_cb, false, (void *)client);
	sprintf(client->buf + strlen(client->buf), ".\n");

	return (0);
}

