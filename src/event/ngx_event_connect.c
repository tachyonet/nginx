
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <sonic_lb.h>
#include <tcp_dispatcher.h>
#include <app_connector.h>
#include <ngx_http.h> 

extern ngx_module_t  ngx_http_sonic_lb_module;


#if (NGX_HAVE_TRANSPARENT_PROXY)
static ngx_int_t ngx_event_connect_set_transparent(ngx_peer_connection_t *pc,
    ngx_socket_t s);
#endif


ngx_int_t
ngx_event_connect_peer(ngx_peer_connection_t *pc)
{
    int                rc, type, value;
#if (NGX_HAVE_IP_BIND_ADDRESS_NO_PORT || NGX_LINUX)
    in_port_t          port;
#endif
    ngx_int_t          event;
    ngx_err_t          err;
    ngx_uint_t         level;
    ngx_socket_t       s;
    ngx_event_t       *rev, *wev;
    ngx_connection_t  *c;

	ngx_http_request_t    *r;
    ngx_http_sonic_ctx_t  *ctx;
    ccb_t                 *parent_ccb, *child_ccb;
    //struct sockaddr_in    *sin;
  
	r = (ngx_http_request_t *) pc->local;

    rc = pc->get(pc, pc->data);
    if (rc != NGX_OK) {
        return rc;
    }

    type = (pc->type ? pc->type : SOCK_STREAM);

/*    s = ngx_socket(pc->sockaddr->sa_family, type, 0);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pc->log, 0, "%s socket %d",
                   (type == SOCK_STREAM) ? "stream" : "dgram", s);

    if (s == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }

*/
	s = 0 ;
    c = ngx_get_connection(s, pc->log);

    if (c == NULL) {
        /*if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }*/

        return NGX_ERROR;
    }

    c->type = type;

	c->send = sonic_lb_send_data_handler;
	c->send_chain = sonic_lb_send_chain;
	c->log_error = pc->log_error;

    rev = c->read;
    wev = c->write;

    rev->log = pc->log;
    wev->log = pc->log;

    pc->connection = c;

	c->write->ready = 1; 
	c->read->ready = 0;

	// Set this to 0 to prevent Nginx from trying to call connect() again internally
	c->write->active = 0;

    /*if (ngx_add_conn) {
        if (ngx_add_conn(c) == NGX_ERROR) {
            goto failed;
        }
    }*/
	
    //r = pc->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_sonic_lb_module);
    if (ctx == NULL || ctx->ccb == NULL) {
        return NGX_ERROR;
    }
    parent_ccb = ctx->ccb;

    int upstream_port = sonic_get_next_free_port();
	
	struct sockaddr_in *sin = (struct sockaddr_in *) pc->sockaddr;

	struct in_addr ip_src;
	inet_aton(glb_system_vars.my_ip_addr, &ip_src);
	
	child_ccb = tcp_new_conn(sin->sin_addr, ip_src, ntohs(sin->sin_port), upstream_port);
	//memcpy(child_ccb->client_mac_addr, "\x08\x00\x27\xad\x80\xc5", 6);
    if (child_ccb == NULL) {
        return NGX_ERROR;
    }

	//memcpy(child_ccb->client_mac_addr, client_mac_addr, ETHER_ADDR_LEN);

	child_ccb->is_upstream = 1;
    child_ccb->connection = c;     // Link CCB to this Nginx Connection
    child_ccb->peer_ccb = parent_ccb;  // Link Child CCB -> Parent CCB
    parent_ccb->peer_ccb = child_ccb;  // Link Parent CCB -> Child CCB
	
	if (insert_to_connection_hashmap(child_ccb)) {
		ccb_free(child_ccb);
		return -1;
	}

    c->data = child_ccb;
	return NGX_OK;
}


#if (NGX_HAVE_TRANSPARENT_PROXY)

static ngx_int_t
ngx_event_connect_set_transparent(ngx_peer_connection_t *pc, ngx_socket_t s)
{
    int  value;

    value = 1;

#if defined(SO_BINDANY)

    if (setsockopt(s, SOL_SOCKET, SO_BINDANY,
                   (const void *) &value, sizeof(int)) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                      "setsockopt(SO_BINDANY) failed");
        return NGX_ERROR;
    }

#else

    switch (pc->local->sockaddr->sa_family) {

    case AF_INET:

#if defined(IP_TRANSPARENT)

        if (setsockopt(s, IPPROTO_IP, IP_TRANSPARENT,
                       (const void *) &value, sizeof(int)) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          "setsockopt(IP_TRANSPARENT) failed");
            return NGX_ERROR;
        }

#elif defined(IP_BINDANY)

        if (setsockopt(s, IPPROTO_IP, IP_BINDANY,
                       (const void *) &value, sizeof(int)) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          "setsockopt(IP_BINDANY) failed");
            return NGX_ERROR;
        }

#endif

        break;

#if (NGX_HAVE_INET6)

    case AF_INET6:

#if defined(IPV6_TRANSPARENT)

        if (setsockopt(s, IPPROTO_IPV6, IPV6_TRANSPARENT,
                       (const void *) &value, sizeof(int)) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          "setsockopt(IPV6_TRANSPARENT) failed");
            return NGX_ERROR;
        }

#elif defined(IPV6_BINDANY)

        if (setsockopt(s, IPPROTO_IPV6, IPV6_BINDANY,
                       (const void *) &value, sizeof(int)) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          "setsockopt(IPV6_BINDANY) failed");
            return NGX_ERROR;
        }

#else

        ngx_log_error(NGX_LOG_ALERT, pc->log, 0,
                      "could not enable transparent proxying for IPv6 "
                      "on this platform");

        return NGX_ERROR;

#endif

        break;

#endif /* NGX_HAVE_INET6 */

    }

#endif /* SO_BINDANY */

    return NGX_OK;
}

#endif


ngx_int_t
ngx_event_get_peer(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}
