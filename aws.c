// SPDX-License-Identifier: BSD-3-Clause
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sendfile.h>
#include <sys/eventfd.h>
#include <libaio.h>
#include <errno.h>

#include "aws.h"
#include "utils/util.h"
#include "utils/debug.h"
#include "utils/sock_util.h"
#include "utils/w_epoll.h"

/* server socket file descriptor */
static int listenfd;

/* epoll file descriptor */
static int epollfd;

static int aws_on_path_cb(http_parser *p, const char *buf, size_t len)
{
	struct connection *conn = (struct connection *)p->data;

	memcpy(conn->request_path, buf, len);
	conn->request_path[len] = '\0';
	conn->have_path = 1;

	return 0;
}

static void connection_prepare_send_reply_header(struct connection *conn)
{
	char buffer[BUFSIZ] = "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n";

	conn->send_len = snprintf(conn->send_buffer, sizeof(conn->send_buffer), buffer, conn->file_size);
}

static void connection_prepare_send_404(struct connection *conn)
{
	char buffer[BUFSIZ] = "HTTP/1.1 404 Not Found\r\nContent-Length: %ld\r\n\r\n";

	conn->send_len = snprintf(conn->send_buffer, sizeof(conn->send_buffer), buffer, conn->file_size);
}

static enum resource_type connection_get_resource_type(struct connection *conn)
{
	if (strncmp(conn->filename, "./static", strlen("./static")) == 0)
		return RESOURCE_TYPE_STATIC;
	else if (strncmp(conn->filename, "./dynamic", strlen("./dynamic")) == 0)
		return RESOURCE_TYPE_DYNAMIC;
	else
		return RESOURCE_TYPE_NONE;
}



struct connection *connection_create(int sockfd)
{
	struct connection *conn = malloc(sizeof(*conn));

	DIE(conn == NULL, "malloc");

	conn->sockfd = sockfd;
	conn->request_parser.data = conn;

	return conn;
}


void connection_remove(struct connection *conn)
{
	close(conn->sockfd);
	conn->state = STATE_CONNECTION_CLOSED;
	free(conn);
}

void handle_new_connection(void)
{
static int sockfd;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	struct connection *conn;
	int rc;


	sockfd = accept(listenfd, (SSA *) &addr, &addrlen);
	DIE(sockfd < 0, "accept");

	fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);

	conn = connection_create(sockfd);

	rc = w_epoll_add_ptr_in(epollfd, sockfd, conn);
	DIE(rc < 0, "w_epoll_add_in");

	http_parser_init(&conn->request_parser, HTTP_REQUEST);
}

void receive_data(struct connection *conn)
{
	int bytes_recv;

	conn->recv_len = 0;

	while (1) {
		bytes_recv = recv(conn->sockfd, conn->recv_buffer + conn->recv_len, BUFSIZ - conn->recv_len, 0);

		if (bytes_recv == -1)
			break;

		conn->recv_len += bytes_recv;

		if (bytes_recv == 0)
			break;
	}

	conn->state = STATE_REQUEST_RECEIVED;
}

int connection_open_file(struct connection *conn)
{
	parse_header(conn);

	snprintf(conn->filename, BUFSIZ + 1, "%s%s", ".", conn->request_path);

	conn->fd = open(conn->filename, O_RDONLY);

	if (conn->fd != -1) {
		struct stat status;

		stat(conn->filename, &status);
		conn->file_size = status.st_size;
		return 0;
	}

	return -1;
}

int parse_header(struct connection *conn)
{
	http_parser_settings settings_on_path = {
		.on_message_begin = 0,
		.on_header_field = 0,
		.on_header_value = 0,
		.on_path = aws_on_path_cb,
		.on_url = 0,
		.on_fragment = 0,
		.on_query_string = 0,
		.on_body = 0,
		.on_headers_complete = 0,
		.on_message_complete = 0
	};
	http_parser_execute(&conn->request_parser, &settings_on_path, conn->recv_buffer, conn->recv_len);
	return 0;
}

enum connection_state connection_send_static(struct connection *conn)
{
	int bytes;
	long off = 0;

	for (; conn->file_size > 0;) {
		bytes = sendfile(conn->sockfd, conn->fd, &off, conn->file_size);
		if (bytes != -1)
			conn->file_size -= bytes;
	}


	return STATE_DATA_SENT;
}

int connection_send_data(struct connection *conn)
{
	// dlog(LOG_DEBUG, "sENDING data\n");
	int bytes_to_send, total;

	total = 0;

	for (total = 0; conn->send_len > 0; total += bytes_to_send) {
		bytes_to_send = send(conn->sockfd, conn->send_buffer + total, conn->send_len, 0);
		if (bytes_to_send == -1)
			return -1;

		conn->send_len -= bytes_to_send;
	}

	return total;
}


int connection_send_dynamic(struct connection *conn)
{
	struct iocb *iocb_ptr = &conn->iocb;

	conn->piocb[0] = iocb_ptr;

	if (io_setup(1, &conn->ctx) < 0)
		return -1;


	int offset = 0;
	int read_write_size = 0;
	struct io_event event;

	for (; conn->file_size > 0; conn->file_size -= read_write_size, offset += read_write_size) {
		read_write_size = (conn->file_size > BUFSIZ) ? BUFSIZ : conn->file_size;

		char buff[BUFSIZ] = {0};

		io_prep_pread(iocb_ptr, conn->fd, buff, read_write_size, offset);
		if (io_submit(conn->ctx, 1, conn->piocb) < 0) {
			io_destroy(conn->ctx);
			return -1;
		}

		if (io_getevents(conn->ctx, 1, 1, &event, NULL) < 0) {
			io_destroy(conn->ctx);
			return -1;
		}

		io_prep_pwrite(iocb_ptr, conn->sockfd, buff, read_write_size, 0);
		if (io_submit(conn->ctx, 1, conn->piocb) < 0) {
			io_destroy(conn->ctx);
			return -1;
		}

		if (io_getevents(conn->ctx, 1, 1, &event, NULL) < 0) {
			io_destroy(conn->ctx);
			return -1;
		}
	}

	return 0;
}



void handle_input(struct connection *conn)
{
	if (conn->state == STATE_INITIAL)
		receive_data(conn);

	if (conn->state == STATE_REQUEST_RECEIVED) {
		if (connection_open_file(conn) == 0) {
			connection_prepare_send_reply_header(conn);
			conn->state = STATE_SENDING_HEADER;
		} else {
			connection_prepare_send_404(conn);
			conn->state = STATE_SENDING_404;
		}
	}

	DIE(w_epoll_update_ptr_out(epollfd, conn->sockfd, conn) < 0, "w_epoll_update_ptr_out");
}

void handle_output(struct connection *conn)
{
	if (conn->state == STATE_SENDING_HEADER) {
		connection_send_data(conn);
		conn->state = STATE_HEADER_SENT;
	}
	if (conn->state == STATE_HEADER_SENT) {
		conn->res_type = connection_get_resource_type(conn);
		if (conn->res_type == RESOURCE_TYPE_STATIC)
			conn->state = connection_send_static(conn);
		else if (conn->res_type == RESOURCE_TYPE_DYNAMIC)
			connection_send_dynamic(conn);
	}
	if (conn->state == STATE_DATA_SENT)
		connection_remove(conn);

	if (conn->state == STATE_SENDING_404) {
		connection_send_data(conn);
		conn->state = STATE_404_SENT;
	}
	if (conn->state == STATE_404_SENT)
		connection_remove(conn);

	if (conn->state == STATE_SENDING_DATA)
		conn->state = connection_get_resource_type(conn);
}

void handle_client(uint32_t event, struct connection *conn)
{
	if (event & EPOLLIN)
		handle_input(conn);

	if (event & EPOLLOUT)
		handle_output(conn);
}

int main(void)
{
	int rc;

	epollfd = w_epoll_create();
	DIE(epollfd < 0, "w_epoll_create");

	listenfd = tcp_create_listener(AWS_LISTEN_PORT,
		DEFAULT_LISTEN_BACKLOG);
	DIE(listenfd < 0, "tcp_create_listener");

	rc = w_epoll_add_fd_in(epollfd, listenfd);
	DIE(rc < 0, "w_epoll_add_fd_in");

	while (1) {
		struct epoll_event rev;

		rc = w_epoll_wait_infinite(epollfd, &rev);
		DIE(rc < 0, "w_epoll_wait_infinite");

		if (rev.data.fd == listenfd) {
			dlog(LOG_DEBUG, "New connection\n");
			if (rev.events & EPOLLIN)
				handle_new_connection();
		} else {
			struct connection *conn = (struct connection *)rev.data.ptr;

			handle_client(rev.events, conn);
		}
	}

	return 0;
}
