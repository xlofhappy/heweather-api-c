#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#define LOG(...) \
    do { \
        printf(__VA_ARGS__); \
        fflush(stdout); \
    } while(0)

struct ssl_session {
    int tcp_sock;
    SSL *ssl;
    SSL_CTX *ssl_ctx;
};

unsigned short g_port;
char *g_hostname;
char *g_filename;

int sock_set_nonblock(int fd)
{
    int err, flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        err = errno;
        fprintf(stderr, "fcntl get: %s\n", strerror(err));
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        err = errno;
        fprintf(stderr, "fcntl set: %s\n", strerror(err));
        return -2;
    }

    return 0;
}

int sock_conn(const char *server, unsigned short port)
{
    int ret;
    int fd = -1;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    char server_port[32];

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    snprintf(server_port, sizeof(server_port), "%u", port);
    ret = getaddrinfo(server, server_port, &hints, &result);
    if (ret) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
            continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;
        close(fd);
    }
    freeaddrinfo(result);
    if (rp == NULL) {
        fprintf(stderr, "Could not connect\n");
        return -1;
    }

    if (sock_set_nonblock(fd))
        return -1;

    return fd;
}

int ssl_handshake(struct ssl_session *session)
{
    int rc;
    int err;
    int events;
    struct pollfd pfd;

    SSL_set_connect_state(session->ssl);
    SSL_set_mode(session->ssl, SSL_MODE_AUTO_RETRY);

    events = POLLIN | POLLOUT;
    while ((rc = SSL_do_handshake(session->ssl)) != 1) {
        err = SSL_get_error(session->ssl, rc);
        if (err == SSL_ERROR_WANT_WRITE) {
            events |= POLLOUT;
            events &= ~POLLIN;
        } else if (err == SSL_ERROR_WANT_READ) {
            events |= EPOLLIN;
            events &= ~EPOLLOUT;
        } else {
            fprintf(stderr, "SSL_do_handshake: return %d error %d errno %d msg %s\n", rc, err, errno, strerror(errno));
            ERR_print_errors_fp(stderr);
            return -1;
        }

        pfd.fd = session->tcp_sock;
        pfd.events = events;
        do {
            rc = poll(&pfd, 1, 100);
        } while  (rc == 0);
    }

    return 0;
}

int ssl_conn(struct ssl_session *session, const char *server, unsigned short port)
{
    int ret;

    session->tcp_sock = sock_conn(server, port);
    if (session->tcp_sock < 0) {
        ret = -1;
        goto err_out;
    }

    session->ssl = SSL_new(session->ssl_ctx);
    if (!session->ssl) {
        ERR_print_errors_fp(stderr);
        ret = -2;
        goto err_out;
    }

    if (!SSL_set_fd(session->ssl, session->tcp_sock)) {
        ERR_print_errors_fp(stderr);
        ret = -3;
        goto err_out;
    }

    LOG("SSL:: Handshaking...\n");
    if (ssl_handshake(session)) {
        ret = -4;
        goto err_out;
    }

    LOG("SSL:: Connection established\n");
    return 0;

err_out:
    return ret;
}

void ssl_write(struct ssl_session *sess, const char *msg)
{
    int len = strlen(msg);
    int rc;

    rc = SSL_write(sess->ssl, msg, len);
    if (rc != len)
        fprintf(stderr, "SSL_write. return %d errno %d msg %s", rc, errno, strerror(errno));

    LOG("SSL:: Send %d bytes\n", len);
    LOG("SSL:: Content:\n%s\n", msg);
}

int ssl_read(struct ssl_session *sess)
{
    char buffer[1024];
    int total_len = 0;
    int read_len;
    int err;

    LOG("SSL:: Reading\n");
    LOG("\n=====================================\n\n");
    while (1) {
        read_len = SSL_read(sess->ssl, buffer, sizeof(buffer));
        if (read_len < 0) {
            err = SSL_get_error(sess->ssl, read_len);
            if (err == SSL_ERROR_WANT_READ) {
                continue;
            } else {
                LOG("SSL_read error return %d errno %d: %s\n", read_len, errno, strerror(errno));
                ERR_print_errors_fp(stderr);
                return -1;
            }
        } else if (read_len > 0) {
            total_len += read_len;
            LOG("%.*s\n", read_len, buffer);
        } else {
            err = SSL_get_error(sess->ssl, read_len);
            if (err == SSL_ERROR_ZERO_RETURN) {
                LOG("\n=====================================\n");
                LOG("SSL:: Read finished\n");
                return 0;
            }
            LOG("SSL_read error return %d errno %d: %s\n", read_len, errno, strerror(errno));
            ERR_print_errors_fp(stderr);
            return 0;
        }
    }

    return 0;
}

int epoll_set_fd(int efd, int fd, int events)
{
    int rc;
    struct epoll_event ev;

    ev.data.fd = fd;
    ev.events = events | EPOLLET;
    rc = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
    if (rc == -1) {
        LOG("epoll_ctl error. %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int get_msg_to_send(char *outbuf, int buf_len)
{
    int rc = 0;
    char *filename = g_filename;
    FILE *f;

    if ((f = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "%s(): cannot open %s\n", __func__, filename);
		return -1;
	}

    while (!feof(f)) {
        rc = fread(outbuf + rc, buf_len - rc, 1, f);
    }

    fclose(f);

    return 0;
}

void main_loop(struct ssl_session *sess)
{
    int efd;
    struct epoll_event *events;

    efd = epoll_create1(0);
    if (efd == -1) {
        LOG("epoll_create error. %s\n", strerror(errno));
        return;
    }
    
    if (epoll_set_fd(efd, sess->tcp_sock, EPOLLIN | EPOLLOUT))
        return;

    events = calloc(1, sizeof(struct epoll_event));
    if (!events)
        goto close_sock;

    while (1) {
        int i, ready;

        ready = epoll_wait(efd, events, 1, -1);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            else
                break;
        }

        for (i = 0; i < ready; i++) {
            if ((events[i].events & EPOLLERR) ||
                (events[i].events & EPOLLHUP) ||
                (!(events[i].events & (EPOLLIN | EPOLLOUT)))) {
                    fprintf(stderr, "epoll error\n");
                    continue;
            } else if (events->events & (EPOLLIN | EPOLLHUP)) {
                ssl_read(sess);
                goto free_ev;
            } else if (events->events & EPOLLOUT) {
                char msg[1024] = {};
                if (get_msg_to_send(msg, sizeof(msg)))
                    goto free_ev;
                ssl_write(sess, msg);
                SSL_shutdown(sess->ssl);
            }
        }
    }

free_ev:
    if (events)
        free(events);

close_sock:
    close(efd);
}

int ssl_init(struct ssl_session *sess)
{
    SSL_CTX *ctx;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    sess->ssl_ctx = ctx;

    return 0;
}

void ssl_destroy(struct ssl_session *sess)
{
    if (sess->ssl) {
        SSL_free(sess->ssl);
        sess->ssl = NULL;
    }
    if (sess->tcp_sock)
        close(sess->tcp_sock);
    if (sess->ssl_ctx) {
        SSL_CTX_free(sess->ssl_ctx);
        sess->ssl_ctx = NULL;
    }
}

void usage(char *prog)
{
    fprintf(stdout, "usage %s <host> <port> <file>\n", prog);
    fprintf(stdout, "example: %s free-api.heweather.net 443 aFile\n", prog);
}

int args_parse(char **args)
{
    unsigned short port;

    port = atoi(args[2]);
    if (port < 0 || port > 65536) {
        fprintf(stderr, "invalid argument: invalid server port\n");
        return 1;
    }

    if (access(args[3], F_OK)) {
        fprintf(stderr, "invalid argument: file %s not exist\n", args[3]);
        return 1;
    }
    g_port = port;
    g_hostname = args[1];
    g_filename = args[3];

    return 0;
}

void run(void)
{
    struct ssl_session session;

    if ( ssl_init(&session))  {
        return;
    }

    if ( ssl_conn(&session, g_hostname, g_port) ) {
        return;
    }

    main_loop(&session);
    ssl_destroy(&session);
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (args_parse(argv)) {
        exit(EXIT_FAILURE);
    }

    run();

    return 0;
}