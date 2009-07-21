/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
** DAV extension module for Apache 2.0.*
**  - various utilities, repository-independent
*/

#include "apr_strings.h"
#include "apr_lib.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "mod_dav.h"

#include "http_request.h"
#include "http_config.h"
#include "http_vhost.h"
#include "http_log.h"
#include "http_protocol.h"

DAV_DECLARE(dav_error*) dav_new_error(apr_pool_t *p, int status,
                                      int error_id, const char *desc)
{
    int save_errno = errno;
    dav_error *err = apr_pcalloc(p, sizeof(*err));

    /* DBG3("dav_new_error: %d %d %s", status, error_id, desc ? desc : "(no desc)"); */

    err->status = status;
    err->error_id = error_id;
    err->desc = desc;
    err->save_errno = save_errno;

    return err;
}

DAV_DECLARE(dav_error*) dav_new_error_tag(apr_pool_t *p, int status,
                                          int error_id, const char *desc,
                                          const char *namespace,
                                          const char *tagname,
                                          const char *content,
                                          const char *prolog)
{
    dav_error *err = dav_new_error(p, status, error_id, desc);

    err->tagname = tagname;
    err->namespace = namespace;
    err->content = "";
    if (content) err->content = content;
    err->prolog = prolog;

    return err;
}


DAV_DECLARE(dav_error*) dav_push_error(apr_pool_t *p, int status,
                                       int error_id, const char *desc,
                                       dav_error *prev)
{
    dav_error *err = apr_pcalloc(p, sizeof(*err));

    err->status = status;
    err->error_id = error_id;
    err->desc = desc;
    err->prev = prev;

    return err;
}

DAV_DECLARE(void) dav_check_bufsize(apr_pool_t * p, dav_buffer *pbuf,
                                    apr_size_t extra_needed)
{
    /* grow the buffer if necessary */
    if (pbuf->cur_len + extra_needed > pbuf->alloc_len) {
        char *newbuf;

        pbuf->alloc_len += extra_needed + DAV_BUFFER_PAD;
        newbuf = apr_pcalloc(p, pbuf->alloc_len);
        memcpy(newbuf, pbuf->buf, pbuf->cur_len);
        pbuf->buf = newbuf;
    }
}

DAV_DECLARE(void) dav_set_bufsize(apr_pool_t * p, dav_buffer *pbuf,
                                  apr_size_t size)
{
    /* NOTE: this does not retain prior contents */

    /* NOTE: this function is used to init the first pointer, too, since
       the PAD will be larger than alloc_len (0) for zeroed structures */

    /* grow if we don't have enough for the requested size plus padding */
    if (size + DAV_BUFFER_PAD > pbuf->alloc_len) {
        /* set the new length; min of MINSIZE */
        pbuf->alloc_len = size + DAV_BUFFER_PAD;
        if (pbuf->alloc_len < DAV_BUFFER_MINSIZE)
            pbuf->alloc_len = DAV_BUFFER_MINSIZE;

        pbuf->buf = apr_pcalloc(p, pbuf->alloc_len);
    }
    pbuf->cur_len = size;
}


/* initialize a buffer and copy the specified (null-term'd) string into it */
DAV_DECLARE(void) dav_buffer_init(apr_pool_t *p, dav_buffer *pbuf,
                                  const char *str)
{
    dav_set_bufsize(p, pbuf, strlen(str));
    memcpy(pbuf->buf, str, pbuf->cur_len + 1);
}

/* append a string to the end of the buffer, adjust length */
DAV_DECLARE(void) dav_buffer_append(apr_pool_t *p, dav_buffer *pbuf,
                                    const char *str)
{
    apr_size_t len = strlen(str);

    dav_check_bufsize(p, pbuf, len + 1);
    memcpy(pbuf->buf + pbuf->cur_len, str, len + 1);
    pbuf->cur_len += len;
}

/* place a string on the end of the buffer, do NOT adjust length */
DAV_DECLARE(void) dav_buffer_place(apr_pool_t *p, dav_buffer *pbuf,
                                   const char *str)
{
    apr_size_t len = strlen(str);

    dav_check_bufsize(p, pbuf, len + 1);
    memcpy(pbuf->buf + pbuf->cur_len, str, len + 1);
}

/* place some memory on the end of a buffer; do NOT adjust length */
DAV_DECLARE(void) dav_buffer_place_mem(apr_pool_t *p, dav_buffer *pbuf,
                                       const void *mem, apr_size_t amt,
                                       apr_size_t pad)
{
    dav_check_bufsize(p, pbuf, amt + pad);
    memcpy(pbuf->buf + pbuf->cur_len, mem, amt);
}

/*
** dav_lookup_uri()
**
** Extension for ap_sub_req_lookup_uri() which can't handle absolute
** URIs properly.
**
** If NULL is returned, then an error occurred with parsing the URI or
** the URI does not match the current server.
*/
DAV_DECLARE(dav_lookup_result) dav_lookup_uri(const char *uri,
                                              request_rec * r,
                                              int must_be_absolute,
                                              int allow_cross_domain)
{
    dav_lookup_result result = { 0 };
    apr_uri_t comp;
    char *new_file;

    /* first thing to do is parse the URI into various components */
    if (apr_uri_parse(r->pool, uri, &comp) != APR_SUCCESS) {
        result.err.status = HTTP_BAD_REQUEST;
        result.err.desc = "Invalid syntax in Destination URI.";
        return result;
    }

    /* the URI must be an absoluteURI (WEBDAV S9.3) */
    if (comp.scheme == NULL && must_be_absolute) {
        result.err.status = HTTP_BAD_REQUEST;
        result.err.desc = "Destination URI must be an absolute URI.";
        return result;
    }

    /* the URI must not have a query (args) or a fragment 
    if (comp.query != NULL || comp.fragment != NULL) {
        result.err.status = HTTP_BAD_REQUEST;
        result.err.desc =
            "Destination URI contains invalid components "
            "(a query or a fragment).";
        return result;
    }
    */

#if 0
    /* scheme checking breaks if the main request is https:, disabling for now */
    /* If the scheme or port was provided, then make sure that it matches
       the scheme/port of this request. If the request must be absolute,
       then require the (explicit/implicit) scheme/port be matching.

       ### hmm. if a port wasn't provided (does the parse return port==0?),
       ### but we're on a non-standard port, then we won't detect that the
       ### URI's port implies the wrong one.
    */
    if (comp.scheme != NULL || comp.port != 0 || must_be_absolute)
    {
        /* ### not sure this works if the current request came in via https: */
        scheme = r->parsed_uri.scheme;
        if (scheme == NULL)
            scheme = ap_http_scheme(r);

        /* insert a port if the URI did not contain one */
        if (comp.port == 0)
            comp.port = apr_uri_port_of_scheme(comp.scheme);

        /* now, verify that the URI uses the same scheme as the current.
           request. the port must match our port.
        */
        port = r->connection->local_addr->port;
        if (strcasecmp(comp.scheme, scheme) != 0
#ifdef APACHE_PORT_HANDLING_IS_BUSTED
            || comp.port != port
#endif
            ) {
            result.err.status = HTTP_BAD_GATEWAY;
            result.err.desc = apr_psprintf(r->pool,
                                           "Destination URI refers to "
                                           "different scheme or port "
                                           "(%s://hostname:%d)" APR_EOL_STR
                                           "(want: %s://hostname:%d)",
                                           comp.scheme ? comp.scheme : scheme,
                                           comp.port ? comp.port : port,
                                           scheme, port);
            return result;
        }
    }
#endif

    /* we have verified the scheme, port, and general structure */

    /*
    ** Hrm.  IE5 will pass unqualified hostnames for both the
    ** Host: and Destination: headers.  This breaks the
    ** http_vhost.c::matches_aliases function.
    **
    ** For now, qualify unqualified comp.hostnames with
    ** r->server->server_hostname.
    **
    ** ### this is a big hack. Apache should provide a better way.
    ** ### maybe the admin should list the unqualified hosts in a
    ** ### <ServerAlias> block?
    if (comp.hostname != NULL
        && strrchr(comp.hostname, '.') == NULL
        && (domain = strchr(r->server->server_hostname, '.')) != NULL) {
        comp.hostname = apr_pstrcat(r->pool, comp.hostname, domain, NULL);
    }
    */

    /* now, if a hostname was provided, then verify that it represents the
       same server as the current connection. note that we just use our
       port, since we've verified the URI matches ours */
#ifdef APACHE_PORT_HANDLING_IS_BUSTED
    if (comp.hostname != NULL &&
        !ap_matches_request_vhost(r, comp.hostname, port)) {
        result.err.status = HTTP_BAD_GATEWAY;
        result.err.desc = "Destination URI refers to a different server.";
        return result;
    }
#endif
    if (!allow_cross_domain && comp.hostname != NULL && r->hostname != NULL
        && strcmp(comp.hostname, r->hostname)) {
        result.err.status = HTTP_BAD_GATEWAY;
        result.err.desc = "Destination URI refers to a different domain.";
        return result;
    }

    /* we have verified that the requested URI denotes the same server as
       the current request. Therefore, we can use ap_sub_req_lookup_uri() */

    /* reconstruct a URI as just the path */
    new_file = apr_uri_unparse(r->pool, &comp, APR_URI_UNP_OMITSITEPART);

    /*
     * Lookup the URI and return the sub-request. Note that we use the
     * same HTTP method on the destination. This allows the destination
     * to apply appropriate restrictions (e.g. readonly).
     */
    result.rnew = ap_sub_req_method_uri(r->method, new_file, r, NULL);

    return result;
}

/* ---------------------------------------------------------------
**
** XML UTILITY FUNCTIONS
*/

/* validate that the root element uses a given DAV: tagname (TRUE==valid) */
DAV_DECLARE(int) dav_validate_root(const apr_xml_doc *doc,
                                   const char *tagname)
{
    return doc->root &&
        doc->root->ns == APR_XML_NS_DAV_ID &&
        strcmp(doc->root->name, tagname) == 0;
}

/* Validate root element uses a given tagname and no check on NAMESPACE */ 
DAV_DECLARE(int) dav_validate_root_no_ns(const apr_xml_doc *doc,
                                         const char *tagname)
{
    return doc->root &&
        strcmp(doc->root->name, tagname) == 0;
}

/* find and return the (unique) child with a given DAV: tagname */
DAV_DECLARE(apr_xml_elem *) dav_find_child(const apr_xml_elem *elem,
                                           const char *tagname)
{
    apr_xml_elem *child = elem->first_child;

    for (; child; child = child->next)
        if (child->ns == APR_XML_NS_DAV_ID && !strcmp(child->name, tagname))
            return child;
    return NULL;
}

/* find and return the (unique) child with a given tagname - No check on NAMESPACE*/
DAV_DECLARE(apr_xml_elem *) dav_find_child_no_ns(const apr_xml_elem *elem,
                                                 const char *tagname)
{
    apr_xml_elem *child = elem->first_child;

    for (; child; child = child->next)
        if (!strcmp(child->name, tagname))
            return child;
    return NULL;
}

/* gather up all the CDATA into a single string */
DAV_DECLARE(const char *) dav_xml_get_cdata(const apr_xml_elem *elem, apr_pool_t *pool,
                              int strip_white)
{
    apr_size_t len = 0;
    apr_text *scan;
    const apr_xml_elem *child;
    char *cdata = NULL;
    char *s;
    apr_size_t tlen;
    const char *found_text = NULL; /* initialize to avoid gcc warning */
    int found_count = 0;

    /* die if elem is NULL */
    if(!elem) return cdata;

    for (scan = elem->first_cdata.first; scan != NULL; scan = scan->next) {
        found_text = scan->text;
        ++found_count;
        len += strlen(found_text);
    }

    for (child = elem->first_child; child != NULL; child = child->next) {
        for (scan = child->following_cdata.first;
             scan != NULL;
             scan = scan->next) {
            found_text = scan->text;
            ++found_count;
            len += strlen(found_text);
        }
    }

    /* some fast-path cases:
     * 1) zero-length cdata
     * 2) a single piece of cdata with no whitespace to strip
     */
    if (len == 0)
        return "";
    if (found_count == 1) {
        if (!strip_white
            || (!apr_isspace(*found_text)
                && !apr_isspace(found_text[len - 1])))
            return found_text;
    }

    cdata = s = apr_pcalloc(pool, len + 1);

    for (scan = elem->first_cdata.first; scan != NULL; scan = scan->next) {
        tlen = strlen(scan->text);
        memcpy(s, scan->text, tlen);
        s += tlen;
    }

    for (child = elem->first_child; child != NULL; child = child->next) {
        for (scan = child->following_cdata.first;
             scan != NULL;
             scan = scan->next) {
            tlen = strlen(scan->text);
            memcpy(s, scan->text, tlen);
            s += tlen;
        }
    }

    *s = '\0';

    if (strip_white) {
        /* trim leading whitespace */
        while (apr_isspace(*cdata))     /* assume: return false for '\0' */
            ++cdata;

        /* trim trailing whitespace */
        while (len-- > 0 && apr_isspace(cdata[len]))
            continue;
        cdata[len + 1] = '\0';
    }

    return cdata;
}

DAV_DECLARE(dav_xmlns_info *) dav_xmlns_create(apr_pool_t *pool)
{
    dav_xmlns_info *xi = apr_pcalloc(pool, sizeof(*xi));

    xi->pool = pool;
    xi->uri_prefix = apr_hash_make(pool);
    xi->prefix_uri = apr_hash_make(pool);

    return xi;
}

DAV_DECLARE(void) dav_xmlns_add(dav_xmlns_info *xi,
                                const char *prefix, const char *uri)
{
    /* this "should" not overwrite a prefix mapping */
    apr_hash_set(xi->prefix_uri, prefix, APR_HASH_KEY_STRING, uri);

    /* note: this may overwrite an existing URI->prefix mapping, but it
       doesn't matter -- any prefix is usuable to specify the URI. */
    apr_hash_set(xi->uri_prefix, uri, APR_HASH_KEY_STRING, prefix);
}

DAV_DECLARE(const char *) dav_xmlns_add_uri(dav_xmlns_info *xi,
                                            const char *uri)
{
    const char *prefix;

    if ((prefix = apr_hash_get(xi->uri_prefix, uri,
                               APR_HASH_KEY_STRING)) != NULL)
        return prefix;

    prefix = apr_psprintf(xi->pool, "g%d", xi->count++);
    dav_xmlns_add(xi, prefix, uri);
    return prefix;
}

DAV_DECLARE(const char *) dav_xmlns_get_uri(dav_xmlns_info *xi,
                                            const char *prefix)
{
    return apr_hash_get(xi->prefix_uri, prefix, APR_HASH_KEY_STRING);
}

DAV_DECLARE(const char *) dav_xmlns_get_prefix(dav_xmlns_info *xi,
                                               const char *uri)
{
    return apr_hash_get(xi->uri_prefix, uri, APR_HASH_KEY_STRING);
}

DAV_DECLARE(void) dav_xmlns_generate(dav_xmlns_info *xi,
                                     apr_text_header *phdr)
{
    apr_hash_index_t *hi = apr_hash_first(xi->pool, xi->prefix_uri);

    for (; hi != NULL; hi = apr_hash_next(hi)) {
        const void *prefix;
        void *uri;
        const char *s;

        apr_hash_this(hi, &prefix, NULL, &uri);

        s = apr_psprintf(xi->pool, " xmlns:%s=\"%s\"",
                         (const char *)prefix, (const char *)uri);
        apr_text_append(xi->pool, phdr, s);
    }
}

/* ---------------------------------------------------------------
**
** Timeout header processing
**
*/

/* dav_get_timeout:  If the Timeout: header exists, return a time_t
 *    when this lock is expected to expire.  Otherwise, return
 *    a time_t of DAV_TIMEOUT_INFINITE.
 *
 *    It's unclear if DAV clients are required to understand
 *    Seconds-xxx and Infinity time values.  We assume that they do.
 *    In addition, for now, that's all we understand, too.
 */
DAV_DECLARE(time_t) dav_get_timeout(request_rec *r)
{
    time_t now, expires = DAV_TIMEOUT_INFINITE;

    const char *timeout_const = apr_table_get(r->headers_in, "Timeout");
    const char *timeout = apr_pstrdup(r->pool, timeout_const), *val;

    if (timeout == NULL)
        return DAV_TIMEOUT_INFINITE;

    /* Use the first thing we understand, or infinity if
     * we don't understand anything.
     */

    while ((val = ap_getword_white(r->pool, &timeout)) && strlen(val)) {
        if (!strncmp(val, "Infinite", 8)) {
            return DAV_TIMEOUT_INFINITE;
        }

        if (!strncmp(val, "Second-", 7)) {
            val += 7;
            /* ### We need to handle overflow better:
             * ### timeout will be <= 2^32 - 1
             */
            expires = atol(val);
            now     = time(NULL);
            return now + expires;
        }
    }

    return DAV_TIMEOUT_INFINITE;
}

/* ---------------------------------------------------------------
**
** If Header processing
**
*/

/* add_if_resource returns a new if_header, linking it to next_ih.
 */
static dav_if_header *dav_add_if_resource(apr_pool_t *p, dav_if_header *next_ih,
                                          const char *uri, apr_size_t uri_len)
{
    dav_if_header *ih;

    if ((ih = apr_pcalloc(p, sizeof(*ih))) == NULL)
        return NULL;

    ih->uri = uri;
    ih->uri_len = uri_len;
    ih->next = next_ih;

    return ih;
}

/* add_if_state adds a condition to an if_header.
 */
static dav_error * dav_add_if_state(apr_pool_t *p, dav_if_header *ih,
                                    const char *state_token,
                                    dav_if_state_type t, int condition,
                                    const dav_hooks_locks *locks_hooks)
{
    dav_if_state_list *new_sl;

    new_sl = apr_pcalloc(p, sizeof(*new_sl));

    new_sl->condition = condition;
    new_sl->type      = t;

    if (t == dav_if_opaquelock) {
        dav_error *err;

        if ((err = (*locks_hooks->parse_locktoken)(p, state_token,
                                                   &new_sl->locktoken)) != NULL) {
            /* If the state token cannot be parsed, treat it as an
             * unknown state; this will evaluate to "false" later
             * during If header validation. */
            if (err->error_id == DAV_ERR_LOCK_UNK_STATE_TOKEN) {
                new_sl->type = dav_if_unknown;
            }
            else {
                /* ### maybe add a higher-level description */
                return err;
            }
        }
    }
    else
        new_sl->etag = state_token;

    new_sl->next = ih->state;
    ih->state = new_sl;

    return NULL;
}

/* fetch_next_token returns the substring from str+1
 * to the next occurence of char term, or \0, whichever
 * occurs first.  Leading whitespace is ignored.
 */
static char *dav_fetch_next_token(char **str, char term)
{
    char *sp;
    char *token;

    token = *str + 1;

    while (*token && (*token == ' ' || *token == '\t'))
        token++;

    if ((sp = strchr(token, term)) == NULL)
        return NULL;

    *sp = '\0';
    *str = sp;
    return token;
}

/* dav_process_if_header:
 *
 *   If NULL (no error) is returned, then **if_header points to the
 *   "If" productions structure (or NULL if "If" is not present).
 *
 *   ### this part is bogus:
 *   If an error is encountered, the error is logged.  Parent should
 *   return err->status.
 */
static dav_error * dav_process_if_header(request_rec *r, dav_if_header **p_ih)
{
    dav_error *err;
    char *str;
    char *list;
    const char *state_token;
    const char *uri = NULL;        /* scope of current production; NULL=no-tag */
    apr_size_t uri_len = 0;
    dav_if_header *ih = NULL;
    apr_uri_t parsed_uri;
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    enum {no_tagged, tagged, unknown} list_type = unknown;
    int condition;

    *p_ih = NULL;

    if ((str = apr_pstrdup(r->pool, apr_table_get(r->headers_in, "If"))) == NULL)
        return NULL;

    while (*str) {
        switch(*str) {
        case '<':
            /* Tagged-list production - following states apply to this uri */
            if (list_type == no_tagged
                || ((uri = dav_fetch_next_token(&str, '>')) == NULL)) {
                return dav_new_error(r->pool, HTTP_BAD_REQUEST,
                                     DAV_ERR_IF_TAGGED,
                                     "Invalid If-header: unclosed \"<\" or "
                                     "unexpected tagged-list production.");
            }

            /* 2518 specifies this must be an absolute URI; just take the
             * relative part for later comparison against r->uri */
            if (apr_uri_parse(r->pool, uri, &parsed_uri) != APR_SUCCESS) {
                return dav_new_error(r->pool, HTTP_BAD_REQUEST,
                                     DAV_ERR_IF_TAGGED,
                                     "Invalid URI in tagged If-header.");
            }
            /* note that parsed_uri.path is allocated; we can trash it */

            /* clean up the URI a bit */
            ap_getparents(parsed_uri.path);
            uri_len = strlen(parsed_uri.path);
            if (uri_len > 1 && parsed_uri.path[uri_len - 1] == '/')
                parsed_uri.path[--uri_len] = '\0';

            uri = parsed_uri.path;
            list_type = tagged;
            break;

        case '(':
            /* List production */

            /* If a uri has not been encountered, this is a No-Tagged-List */
            if (list_type == unknown)
                list_type = no_tagged;

            if ((list = dav_fetch_next_token(&str, ')')) == NULL) {
                return dav_new_error(r->pool, HTTP_BAD_REQUEST,
                                     DAV_ERR_IF_UNCLOSED_PAREN,
                                     "Invalid If-header: unclosed \"(\".");
            }

            if ((ih = dav_add_if_resource(r->pool, ih, uri, uri_len)) == NULL) {
                /* ### dav_add_if_resource() should return an error for us! */
                return dav_new_error(r->pool, HTTP_BAD_REQUEST,
                                     DAV_ERR_IF_PARSE,
                                     "Internal server error parsing \"If:\" "
                                     "header.");
            }

            condition = DAV_IF_COND_NORMAL;

            while (*list) {
                /* List is the entire production (in a uri scope) */

                switch (*list) {
                case '<':
                    if ((state_token = dav_fetch_next_token(&list, '>')) == NULL) {
                        /* ### add a description to this error */
                        return dav_new_error(r->pool, HTTP_BAD_REQUEST,
                                             DAV_ERR_IF_PARSE, NULL);
                    }

                    if ((err = dav_add_if_state(r->pool, ih, state_token, dav_if_opaquelock,
                                                condition, locks_hooks)) != NULL) {
                        /* ### maybe add a higher level description */
                        return err;
                    }
                    condition = DAV_IF_COND_NORMAL;
                    break;

                case '[':
                    if ((state_token = dav_fetch_next_token(&list, ']')) == NULL) {
                        /* ### add a description to this error */
                        return dav_new_error(r->pool, HTTP_BAD_REQUEST,
                                             DAV_ERR_IF_PARSE, NULL);
                    }

                    if ((err = dav_add_if_state(r->pool, ih, state_token, dav_if_etag,
                                                condition, locks_hooks)) != NULL) {
                        /* ### maybe add a higher level description */
                        return err;
                    }
                    condition = DAV_IF_COND_NORMAL;
                    break;

                case 'N':
                    if (list[1] == 'o' && list[2] == 't') {
                        if (condition != DAV_IF_COND_NORMAL) {
                            return dav_new_error(r->pool, HTTP_BAD_REQUEST,
                                                 DAV_ERR_IF_MULTIPLE_NOT,
                                                 "Invalid \"If:\" header: "
                                                 "Multiple \"not\" entries "
                                                 "for the same state.");
                        }
                        condition = DAV_IF_COND_NOT;
                    }
                    list += 2;
                    break;

                case ' ':
                case '\t':
                    break;

                default:
                    return dav_new_error(r->pool, HTTP_BAD_REQUEST,
                                         DAV_ERR_IF_UNK_CHAR,
                                         apr_psprintf(r->pool,
                                                     "Invalid \"If:\" "
                                                     "header: Unexpected "
                                                     "character encountered "
                                                     "(0x%02x, '%c').",
                                                     *list, *list));
                }

                list++;
            }
            break;

        case ' ':
        case '\t':
            break;

        default:
            return dav_new_error(r->pool, HTTP_BAD_REQUEST,
                                 DAV_ERR_IF_UNK_CHAR,
                                 apr_psprintf(r->pool,
                                             "Invalid \"If:\" header: "
                                             "Unexpected character "
                                             "encountered (0x%02x, '%c').",
                                             *str, *str));
        }

        str++;
    }

    *p_ih = ih;
    return NULL;
}

char *chomp_slash(char *str)
{
    int len = strlen(str);
    while (len > 1 && str[len - 1] == '/') {
	str[len - 1] = '\0';
	len = strlen(str);
    }
    return str;
}

#define DAV_VALIDATE_A_LOCK 0x0001
#define DAV_VALIDATE_ALL_LOCKS 0x0002

dav_error *dav_validate_ifheader_locks(request_rec *r, 
                                       const dav_hooks_locks *locks_hooks,
                                       dav_if_header *ifhdr,
                                       dav_lock *locks, int flags,
                                       dav_lock **p_offending_lock)
{
    apr_pool_t *pool = r->pool;
    dav_lock *l_i;

    for (; ifhdr; ifhdr = ifhdr->next) {
        dav_if_state_list *state_i;
        for(state_i = ifhdr->state; state_i; state_i = state_i->next) {
            if (state_i->type != dav_if_opaquelock)
                continue;

            for(l_i = locks; l_i; l_i = l_i->next) {
                if(0 != locks_hooks->compare_locktoken
                   (l_i->locktoken, state_i->locktoken))
                    continue;

                if (strcmp(r->user, l_i->auth_user) != 0) {
                    int allow = 0;
                    if (flags & DAV_VALIDATE_ALL_LOCKS) {
                        const dav_hooks_acl *acl_hooks = dav_get_acl_hooks(r);
                        const dav_principal *principal = 
                          dav_principal_make_from_request(r);
                        request_rec *new_req;
                        dav_resource *lr_res;
                        new_req = ap_sub_req_lookup_uri(l_i->lockroot, r, NULL);
                        dav_get_resource(new_req, 0, 0, &lr_res);

                        allow = (*acl_hooks->is_allow)
                          (principal, lr_res, DAV_PERMISSION_UNLOCK);
                    }

                    if (!allow) {
                        if (p_offending_lock) *p_offending_lock = l_i;
                        return dav_new_error(pool, HTTP_LOCKED, 0,
                                             "Lock owned by another user");
                    }
                }

                if (flags & DAV_VALIDATE_A_LOCK)
                    return NULL;
                else l_i->validated = 1; /*set in validated_hash*/
            }
        }
    }

    if (flags & DAV_VALIDATE_ALL_LOCKS) {
        for (l_i = locks; l_i; l_i = l_i->next)
            if (!l_i->validated/* use validated_hash*/) {
                if (p_offending_lock) *p_offending_lock = l_i;
                return dav_new_error_tag(pool, HTTP_LOCKED, 0,
                                         NULL, NULL, "lock-token-submitted",
                                         apr_psprintf(pool, 
                                                      "<D:href>%s</D:href>", 
                                                      l_i->lockroot), NULL);
            }
    } else if ( flags & DAV_VALIDATE_A_LOCK && locks) {
            return dav_new_error_tag(pool, HTTP_LOCKED, 0,
                                     "The resource is locked", locks->lockroot, 
                                     "lock-token-submitted",
                                     apr_psprintf(pool, "<D:href>%s</D:href>", 
                                                  locks->lockroot), NULL);    
    }

    return NULL;
}

#define AHKS APR_HASH_KEY_STRING

typedef struct {
    dav_walk_params *wp;
    request_rec *rec;
    const dav_hooks_locks *lock_hooks;
    dav_lockdb *lockdb;

    dav_lock *locks_to_inherit;
    dav_lock *new_lock_info;

    dav_bind *bind1;
    dav_bind *bind2;

    int flags;

    apr_hash_t *uri_uuid;
    apr_hash_t *uuid_dinf_lock;
    apr_hash_t *res_ltl_map;
} dav_bind_lock_walker_ctx;

int check_for_lock_clashes(const dav_hooks_locks *hooks,
                           const dav_lock *lock1, const dav_lock *lock2)
{
    if (lock1 && lock2) {
        if ((lock1->scope != lock2->scope)
            || lock1->scope == DAV_LOCKSCOPE_EXCLUSIVE) {
            if (hooks->compare_locktoken(lock1->locktoken, lock2->locktoken) == 0)
                return 0;
            return 1;
        }
    }
    return 0;
}

void filter_locks_of_depth(dav_lock **p_locks, int depth)
{
    dav_lock *li = *p_locks;
    dav_lock *li_filtered = NULL;

    *p_locks = NULL;

    while (li) {
        dav_lock *li_next = li->next;
        li->next = NULL;
        if (li->depth != depth) {
            if (li_filtered)
                li_filtered->next = li;
            else *p_locks = li_filtered = li;

            li_filtered = li;
        }
        li = li_next;
    }
}

dav_error *dav_bind_locks_validate_walker(dav_walk_resource *wres, int calltype)
{
    dav_bind_lock_walker_ctx *ctx = wres->walk_ctx;
    apr_pool_t *pool = wres->pool;
    const dav_resource *res = wres->resource;
    dav_lock *lock = NULL;
    int clash = 0;
    dav_error *clash_err = dav_new_error(pool, HTTP_CONFLICT, 0,
                                         "This operation can't be performed");

    if (ctx->uuid_dinf_lock) {
        char *parent_uri = NULL, *par_uuid = NULL;
        dav_lock *par_dinf_lock = NULL, *own_dinf_lock = NULL;

        apr_hash_set(ctx->uri_uuid, res->uri, AHKS, res->uuid);
        lock = apr_hash_get(ctx->res_ltl_map, res->uuid, AHKS);
    
        parent_uri = ap_make_dirstr_parent(pool, res->uri);
        chomp_slash(parent_uri);
        par_uuid = apr_hash_get(ctx->uri_uuid, parent_uri, AHKS);

        /* Check for any clashes among the depth infinity locks that'll apply to
           this resource after the bind */
        own_dinf_lock = apr_hash_get(ctx->uuid_dinf_lock, res->uuid, AHKS);
        if (par_uuid)
            par_dinf_lock = apr_hash_get(ctx->uuid_dinf_lock, par_uuid, AHKS);

        if (own_dinf_lock == NULL && lock && (lock->depth > 0)) {
            own_dinf_lock = lock;
            apr_hash_set(ctx->uuid_dinf_lock, res->uuid, AHKS, own_dinf_lock);
        }
        if (own_dinf_lock)
            clash = check_for_lock_clashes
              (ctx->lock_hooks, own_dinf_lock, par_dinf_lock);
        else if (par_dinf_lock)
            apr_hash_set(ctx->uuid_dinf_lock, res->uuid, AHKS, par_dinf_lock);
        if (clash) return clash_err;
    }

    if (!(ctx->flags & DAV_VALIDATE_IGNORE_TARGET_LOCKS)) {
        /* No need to do this for COPY */
        dav_lock *ltl = NULL;
        ctx->lock_hooks->get_locks_not_through_binds
          (ctx->lockdb, res, ctx->bind1, ctx->bind2, &ltl);

        clash = check_for_lock_clashes(ctx->lock_hooks, lock, ltl);
        if (clash) return clash_err;
        if (!lock) lock = ltl;
    }

    clash = check_for_lock_clashes(ctx->lock_hooks, lock, ctx->locks_to_inherit);
    if (clash) return clash_err;
    if (!lock) lock = ctx->locks_to_inherit;

    clash = check_for_lock_clashes(ctx->lock_hooks, lock, ctx->new_lock_info);
    if (clash) {
        if (res == ctx->wp->root)
            return dav_new_error(pool, HTTP_LOCKED, 0, "conflicting-lock");
        else {
            dav_add_response(wres, HTTP_LOCKED, NULL);
            return dav_new_error(pool, HTTP_MULTI_STATUS, 0, "Error on child");
        }
    }

    return NULL;
}

dav_error *dav_validate_resource(request_rec *r,
                                 dav_if_header *if_hdr,
                                 dav_lockdb *lockdb,
                                 dav_resource *resource,
                                 int flags,
                                 dav_response **response)
{
    dav_lock *locks = NULL;
    dav_error *err = NULL;

    err = lockdb->hooks->get_locks(lockdb, resource,
                                   DAV_GETLOCKS_RESOLVED, &locks);
    if (err) return err;

    err = dav_validate_ifheader_locks
      (r, lockdb->hooks, if_hdr, locks, DAV_VALIDATE_A_LOCK, NULL);

    return err;
}

DAV_DECLARE(dav_error *) dav_validate_bind(request_rec *r,
                                           int depth,
                                           dav_if_header *if_hdr,
                                           dav_lockdb *lockdb,
                                           dav_bind *bind,
                                           dav_bind *bind_to_ignore,
                                           int flags,
                                           dav_response **response,
                                           dav_lock **lrl_to_refresh,
                                           dav_lock **lrl_to_delete)
{
    apr_pool_t *pool = r->pool;
    dav_walk_params params = { 0 };
    dav_bind_lock_walker_ctx ctx = { 0 };
    apr_hash_t *lr_res_map, *res_ltl_map;
    dav_lock *bind_locks = NULL, *lr_i = NULL, *lr_i_next = NULL;
    dav_lock *cur_locks = NULL, *parent_locks = NULL;
    dav_error *err = NULL;

    if (dav_get_resource_state(r, bind->new_resource) == DAV_RESOURCE_NULL)
        goto check_parent_locks;

    params.walk_type = DAV_WALKTYPE_NORMAL | DAV_WALKTYPE_LOCKNULL;
    params.func = dav_bind_locks_validate_walker;
    params.walk_ctx = &ctx;
    params.pool = pool;
    params.root = bind->new_resource;
    params.lockdb = lockdb;

    ctx.rec = r;
    ctx.lock_hooks = lockdb->hooks;
    ctx.lockdb = lockdb;
    ctx.bind1 = bind;
    ctx.bind2 = bind_to_ignore;
    ctx.flags = flags;
    ctx.uri_uuid = apr_hash_make(pool);
    ctx.uuid_dinf_lock = apr_hash_make(pool);

    ctx.lock_hooks->get_bind_locks(lockdb, bind, &bind_locks);

    lr_res_map = apr_hash_make(pool);
    res_ltl_map = apr_hash_make(pool);

    /* Iterate over all the lockroots that are affected */
    for (lr_i = bind_locks; lr_i; lr_i = lr_i_next) {
        const char *corr_uri, *corr_uuid;
        if (!lr_i->post_bind_uri || !*lr_i->post_bind_uri)
            corr_uri = params.root->uri;
        else
            corr_uri= apr_pstrcat(pool, params.root->uri,
                                  lr_i->post_bind_uri, NULL);

        /* There may be many shared locks with this URI as their lockroot */
        /* We maintain them in a chain as we have to check that one of them is provided */
        dav_lock *ret_lr_group = apr_hash_get(lr_res_map, corr_uri, AHKS);
        lr_i_next = lr_i->next;
        lr_i->next = NULL;

        if (ret_lr_group == NULL) {
            /* Fetch the corresponding resource if there is no such bunch */
            request_rec *new_req;
            dav_resource *corr_res = NULL;
            new_req = ap_sub_req_lookup_uri(corr_uri, ctx.rec, NULL);
            dav_get_resource(new_req, 0, 0, &corr_res);
            corr_uuid = corr_res->uuid;
            apr_hash_set(ctx.uri_uuid, corr_uri, AHKS, corr_uuid);
        } else corr_uuid = apr_hash_get(ctx.uri_uuid, corr_uri, AHKS);

        if (corr_uuid) {
            /* The corresponding uri exists at the target */
            dav_lock *prev_lock = 
              apr_hash_get(res_ltl_map, corr_uuid, AHKS);

            if (check_for_lock_clashes(ctx.lock_hooks, prev_lock, lr_i))
                return dav_new_error(pool, HTTP_CONFLICT, 0,
                                     "Two binds would cause conflicts");

            /* We want res_ltl_map to store the depth inf locks if available */
            if (!prev_lock || (lr_i->depth > prev_lock->depth))
                apr_hash_set(res_ltl_map, corr_uuid, AHKS, lr_i);

            /* Add this lock to the retained lockroot group of this uri */
            lr_i->next = ret_lr_group;
            ret_lr_group = lr_i;
            apr_hash_set(lr_res_map, corr_uri, AHKS, ret_lr_group);

        } else {
            /* The corr uri doesn't exist at target. Mark for deletion */
            if (lrl_to_delete) {
                lr_i->next = *lrl_to_delete;
                *lrl_to_delete = lr_i;
            }
        }
    }

    /* check that all the locks that are being destroyed due to this action
       are provided in the if_header */
    err = dav_validate_ifheader_locks
      (r, ctx.lock_hooks, if_hdr, lrl_to_delete ? *lrl_to_delete : NULL,
       DAV_VALIDATE_ALL_LOCKS, NULL);
    if (err) return err;

    /* verify that one lock on uri being retained is provided
       also create the list of all locks to be refreshed lrl_to_refresh */
    apr_hash_index_t *hi;
    for (hi = apr_hash_first(pool, lr_res_map); hi; hi = apr_hash_next(hi)) {
        const char *corr_uri;
        dav_lock *uri_locks, *iter;
        apr_hash_this(hi, (const void **)&corr_uri, NULL, (void **)&uri_locks);

        err = dav_validate_ifheader_locks(r, ctx.lock_hooks, if_hdr, 
                                          uri_locks, DAV_VALIDATE_A_LOCK, NULL);
        if (err) return err;
        for (iter = uri_locks; iter->next; iter = iter->next);
        if (lrl_to_refresh) {
            iter->next = *lrl_to_refresh;
            *lrl_to_refresh = uri_locks;
        }
    }

    ctx.res_ltl_map = res_ltl_map;
    err = ctx.lock_hooks->get_locks_not_through_binds
      (lockdb, bind->collection, ctx.bind1, ctx.bind2, &ctx.locks_to_inherit);
    filter_locks_of_depth(&ctx.locks_to_inherit, 0);

    if (err) return err;

    /* TODO: check that a lock on bind->old_resource
       (depth inf if old_resource is a collection) is provided */
    err = ctx.lock_hooks->get_locks(lockdb, bind->cur_resource,
                                    DAV_GETLOCKS_COMPLETE, &cur_locks);
    if (bind->cur_resource->collection)
        filter_locks_of_depth(&cur_locks, 0);
    err = dav_validate_ifheader_locks(r, ctx.lock_hooks, if_hdr,
                                      cur_locks, DAV_VALIDATE_A_LOCK, NULL);

    if (ctx.locks_to_inherit && (bind_locks == NULL || err != NULL)) {
        err = dav_validate_ifheader_locks 
          (r, ctx.lock_hooks, if_hdr, ctx.locks_to_inherit, DAV_VALIDATE_A_LOCK,
           NULL);
    }
    if (err) return err;

    err = (*bind->collection->hooks->walk)(&params, depth, response);
    if (err) return err;

 check_parent_locks:
    /* TODO: verify that user has write content priv on all new descendants
       (only in case of exclusive locks?) */
    err = lockdb->hooks->get_locks(lockdb, bind->collection,
                                   DAV_GETLOCKS_RESOLVED, &parent_locks);
    if (err) return err;

    if (dav_get_resource_state(r, bind->new_resource) == DAV_RESOURCE_NULL)
        err = dav_validate_ifheader_locks
          (r, lockdb->hooks, if_hdr, parent_locks, DAV_VALIDATE_A_LOCK, NULL);
    else {
        dav_lock *current_locks = NULL;
        err = lockdb->hooks->get_locks(lockdb, bind->new_resource,
                                       DAV_GETLOCKS_RESOLVED, &current_locks);
        if (err) return err;
        /* Check if a lock on the */
        /* */
        if (bind->new_resource->collection /* and has children? */)
            filter_locks_of_depth(&current_locks, 0);

        err = dav_validate_ifheader_locks
          (r, lockdb->hooks, if_hdr, current_locks, DAV_VALIDATE_A_LOCK, NULL);
        /* The logic might be faulty when new_resource is a collection */
        /* TODO: filter depth 0 locks from current_locks? */
        if (err) {
            filter_locks_of_depth(&current_locks, 0);
            err = dav_validate_ifheader_locks
              (r, lockdb->hooks, if_hdr, parent_locks, DAV_VALIDATE_A_LOCK,
               NULL);
        }
    }

    return err;
}

DAV_DECLARE(dav_error *) dav_validate_unbind(request_rec *r,
                                             dav_if_header *if_hdr,
                                             dav_lockdb *lockdb,
                                             dav_bind *bind,
                                             int flags,
                                             dav_response **p_response,
                                             dav_lock **lrl_to_delete)
{
    const dav_hooks_locks *lock_hooks = DAV_GET_HOOKS_LOCKS(r);
    dav_lock *parent_locks = NULL, *error_lock = NULL;
    dav_error *err = NULL;

    lock_hooks->get_bind_locks(lockdb, bind, lrl_to_delete);
    err = dav_validate_ifheader_locks
      (r, lock_hooks, if_hdr, *lrl_to_delete, DAV_VALIDATE_ALL_LOCKS, &error_lock);
    if (err) {
        if (strcmp(error_lock->lockroot, bind->cur_resource->uri) == 0)
            return err;

        dav_response *new_response;
        new_response = apr_pcalloc(r->pool, sizeof(*new_response));
        new_response->href = error_lock->lockroot;
        new_response->status = err->status;
        new_response->desc =
            "An error occurred on another resource, preventing the "
            "requested operation on this resource.";

        new_response->next = *p_response;
        *p_response = new_response;
        return dav_new_error(r->pool, HTTP_MULTI_STATUS, 0, NULL);
    }

    /* TODO: verify that user has unlock privilege on all the resources being 
       unlocked!! */
    
    /* verify that a lock on the parent is provided */
    err = lock_hooks->get_locks(lockdb, bind->collection, DAV_GETLOCKS_RESOLVED,
                                &parent_locks);
    if (err) return err;

    err = dav_validate_ifheader_locks
      (r, lock_hooks, if_hdr, parent_locks, DAV_VALIDATE_A_LOCK, NULL);

    
    return err;
}

dav_error *dav_validate_new_lock(request_rec *r,
                                 dav_if_header *if_hdr,
                                 int depth,
                                 dav_lockdb *lockdb,
                                 dav_bind *bind,
                                 int flags,
                                 dav_response **p_response)
{
    apr_pool_t *pool = r->pool;
    dav_walk_params params = { 0 };
    dav_bind_lock_walker_ctx ctx = { 0 };
    dav_error *err = NULL;

    params.walk_type = DAV_WALKTYPE_NORMAL | DAV_WALKTYPE_LOCKNULL;
    params.func = dav_bind_locks_validate_walker;
    params.walk_ctx = &ctx;
    params.pool = pool;
    params.root = bind->cur_resource;
    params.lockdb = lockdb;

    ctx.wp = &params;
    ctx.rec = r;
    ctx.lock_hooks = lockdb->hooks;
    ctx.lockdb = lockdb;
    ctx.flags = flags;

    err = ctx.lock_hooks->get_locks
      (lockdb, bind->collection, DAV_GETLOCKS_COMPLETE, &ctx.locks_to_inherit);
    if (err) return err;
    if (flags & DAV_VALIDATE_PARENT) {
        err = dav_validate_ifheader_locks
          (r, lockdb->hooks, if_hdr, ctx.locks_to_inherit, DAV_VALIDATE_A_LOCK,
           NULL);
        if (err) return err;
    }
    filter_locks_of_depth(&ctx.locks_to_inherit, 0);

    ctx.new_lock_info = apr_pcalloc(pool, sizeof(dav_lock));
    ctx.new_lock_info->depth = depth;
    ctx.new_lock_info->scope = 
      (flags & DAV_LOCKSCOPE_SHARED) ? DAV_LOCKSCOPE_SHARED : DAV_LOCKSCOPE_EXCLUSIVE;

    err = (*bind->collection->hooks->walk)(&params, depth, p_response);
    if (err && err->status == HTTP_MULTI_STATUS) {
        dav_response *new_response;
        new_response = apr_pcalloc(r->pool, sizeof(*new_response));
        new_response->href = bind->cur_resource->uri;
        new_response->status = HTTP_FAILED_DEPENDENCY;
        new_response->desc =
            "An error occurred on another resource, preventing the "
            "requested operation on this resource.";

        new_response->next = *p_response;
        *p_response = new_response;
    }
    return err;
}

void dav_parse_header_locktoken(request_rec *r,
                                const dav_hooks_locks *lock_hooks,
                                dav_locktoken **p_locktoken)
{
    dav_locktoken *locktoken = NULL;
    const char *const_locktoken_txt;
    char *locktoken_txt;
    dav_error *err = NULL;

    if ((const_locktoken_txt = apr_table_get(r->headers_in,
                                             "Lock-Token")) == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unlock failed (%s):  "
                      "No Lock-Token specified in header", r->filename);
        return;
    }

    locktoken_txt = apr_pstrdup(r->pool, const_locktoken_txt);
    if (locktoken_txt[0] != '<') {
        /* ### should provide more specifics... */
        return;
    }
    locktoken_txt++;

    if (locktoken_txt[strlen(locktoken_txt) - 1] != '>') {
        /* ### should provide more specifics... */
        return;
    }
    locktoken_txt[strlen(locktoken_txt) - 1] = '\0';

    err = (*lock_hooks->parse_locktoken)(r->pool, locktoken_txt, &locktoken);
    if (err) return;

    *p_locktoken = locktoken;
}

dav_error *dav_validate_unlock(request_rec *r,
                               dav_if_header *if_hdr,
                               dav_lockdb *lockdb,
                               dav_bind *bind,
                               int flags,
                               dav_lock **p_lock_to_remove,
                               dav_response **p_response)
{
    dav_resource *resource = bind->cur_resource;
    dav_locktoken *locktoken = NULL;
    dav_lock *locks = NULL, *lr_i = NULL;
    dav_error *err = NULL;

    dav_parse_header_locktoken(r, lockdb->hooks, &locktoken);
    if (locktoken == NULL)
        return dav_new_error(r->pool, HTTP_BAD_REQUEST, 0,
                             "Invalid Lock-Token header");

    err = lockdb->hooks->get_locks(lockdb, resource, DAV_GETLOCKS_COMPLETE,
                                   &locks);
    if (err) return err;

    for (lr_i = locks; lr_i; lr_i = lr_i->next) {
        if (0 == lockdb->hooks->compare_locktoken(lr_i->locktoken, locktoken))
            break;
    }
    if (lr_i == NULL)
        return dav_new_error(r->pool, HTTP_CONFLICT, 0,
                             "The supplied token not found on Request-URI");
    else if(!r->user || strcmp(r->user, lr_i->auth_user)) {
        int allow = 0;
        const dav_hooks_acl *acl_hooks = dav_get_acl_hooks(r);
        const dav_principal *prin = dav_principal_make_from_request(r);
        allow = (*acl_hooks->is_allow)(prin, resource, DAV_PERMISSION_UNLOCK);
        if (!allow)
            return resource->err;
    }

    if (dav_get_resource_state(r, resource) == DAV_RESOURCE_LOCK_NULL) {
        int last_locknull = 1;
        for (; locks; locks = locks->next) {
            if (locks == lr_i) continue;
            if (strcmp(resource->uri, locks->lockroot) == 0)
                last_locknull = 0;
        }
        if (last_locknull) {
            dav_lock *parent_locks = NULL;
            err = lockdb->hooks->get_locks
              (lockdb, bind->collection, DAV_GETLOCKS_COMPLETE, &parent_locks);
            if (err) return err;
            err = dav_validate_ifheader_locks
              (r, lockdb->hooks, if_hdr, parent_locks, DAV_VALIDATE_A_LOCK,
               NULL);
            if (err) return err;
        }
    }

    *p_lock_to_remove = lr_i;
    return NULL;
}

/* If-* header checking */
int dav_meets_conditions(request_rec *r, int resource_state)
{
    const char *if_match, *if_none_match;
    int retVal;

    /* If-Match '*' fix. Resource existence not checked by ap_meets_conditions.
     * If-Match '*' request should succeed only if the resource exists. */
    if ((if_match = apr_table_get(r->headers_in, "If-Match")) != NULL) {
        if(if_match[0] == '*' && resource_state != DAV_RESOURCE_EXISTS)
            return HTTP_PRECONDITION_FAILED;
    }

    retVal = ap_meets_conditions(r);

    /* If-None-Match '*' fix. If-None-Match '*' request should succeed 
     * if the resource does not exist. */
    if(retVal == HTTP_PRECONDITION_FAILED) {
        /* Note. If if_none_match != NULL, if_none_match is the culprit.
         * Since, in presence of If-None-Match, 
         * other If-* headers are undefined. */
        if((if_none_match = 
                apr_table_get(r->headers_in, "If-None-Match")) != NULL) {
            if(if_none_match[0] == '*' && resource_state != DAV_RESOURCE_EXISTS)
                return OK;
        }
    }

    return retVal;
}

dav_error *dav_validate_state_etag(request_rec *r,
                                   dav_if_state_list *state_list,
                                   dav_resource *res)
{
    const char *given_etag, *current_etag;
    int mismatch;
    const char *reason;
    const char *etag = (*res->hooks->getetag)(res);

    /* Do a weak entity comparison function as defined in
     * RFC 2616 13.3.3.
     */
    if (state_list->etag[0] == 'W' &&
        state_list->etag[1] == '/') {
        given_etag = state_list->etag + 2;
    }
    else {
        given_etag = state_list->etag;
    }
    if (etag[0] == 'W' &&
        etag[1] == '/') {
        current_etag = etag + 2;
    }
    else {
        current_etag = etag;
    }

    mismatch = strcmp(given_etag, current_etag);

    if (state_list->condition == DAV_IF_COND_NORMAL && mismatch) {
        /*
        ** The specified entity-tag does not match the
        ** entity-tag on the resource. This state_list is
        ** not going to match. Bust outta here.
        */
        reason =
          "an entity-tag was specified, but the resource's "
          "actual ETag does not match.";
    }
    else if (state_list->condition == DAV_IF_COND_NOT
             && !mismatch) {
        /*
        ** The specified entity-tag DOES match the
        ** entity-tag on the resource. This state_list is
        ** not going to match. Bust outta here.
        */
        reason =
          "an entity-tag was specified using the \"Not\" form, "
          "but the resource's actual ETag matches the provided "
          "entity-tag.";
    } else return NULL;
    return dav_new_error(r->pool, HTTP_PRECONDITION_FAILED, 0, reason);
}

dav_error *dav_validate_state_opaquelock(request_rec *r,
                                         dav_if_state_list *state_list,
                                         dav_lockdb *lockdb,
                                         dav_resource *res)
{
    dav_lock *locks = NULL, *l_i = NULL;
    dav_error *err = NULL;
    int validated = 0;

    err = lockdb->hooks->get_locks(lockdb, res, DAV_GETLOCKS_PARTIAL, &locks);
    for (l_i = locks; l_i; l_i = l_i->next)
        if (0 == lockdb->hooks->compare_locktoken
            (state_list->locktoken, l_i->locktoken)) {
            validated = 1;
            break;
        }

    if (((state_list->condition == DAV_IF_COND_NORMAL) && !validated) ||
        ((state_list->condition == DAV_IF_COND_NOT) && validated))
        return dav_new_error(r->pool, HTTP_PRECONDITION_FAILED, 0,
                             "Supplied Locktoken not found on resource");
    return NULL;
}

dav_error *dav_validate_ifheader_lists(request_rec *r,
                                       dav_if_header *ifhdr,
                                       dav_lockdb *lockdb)
{
    dav_error *err = NULL;

    for (; ifhdr && !err; ifhdr = ifhdr->next) {
        request_rec *new_req = NULL;
        dav_resource *res = NULL;
        dav_if_state_list *state_i;
        const char *uri = ifhdr->uri;

        for(state_i = ifhdr->state; state_i && !err; state_i = state_i->next) {
            if (res == NULL) {
                if (!uri) {
                    dav_get_resource(r, 0, 0, &res);
                }
                else {
                    new_req = ap_sub_req_lookup_uri(uri, r, NULL);
                    dav_get_resource(new_req, 0, 0, &res);
                }
            }

            switch (state_i->type) {
            case dav_if_etag:
                err = dav_validate_state_etag
                  (r, state_i, (res));
                break;
            case dav_if_opaquelock:
                err = dav_validate_state_opaquelock(r, state_i, lockdb, res);
                break;
            case dav_if_unknown:
                if (state_i->condition == DAV_IF_COND_NORMAL)
                    err = dav_new_error(r->pool, HTTP_PRECONDITION_FAILED, 0,
                                        "Unrecognized statelist");
            }
        }
        if (err == NULL) {
            while (ifhdr->next && (ifhdr->next->uri == ifhdr->uri))
                ifhdr = ifhdr->next;
        } else if (ifhdr->next && (ifhdr->next->uri == ifhdr->uri))
            err = NULL;
    }
    return err;
}

DAV_DECLARE(dav_error *) dav_validate_request(request_rec *r,
                                              int depth,
                                              dav_lockdb *lockdb,
                                              dav_bind *bind,
                                              dav_bind *unbind,
                                              int flags,
                                              int resource_state,
                                              dav_response **response,
                                              dav_lock **p_refresh_locks,
                                              dav_lock **p_remove_locks)
{
    dav_if_header *if_hdr;
    const dav_hooks_repository *repos_hooks = NULL;
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    int lock_db_opened_locally = 0;
    dav_error *err = NULL;

    if (response != NULL) *response = NULL;

    if (p_refresh_locks) *p_refresh_locks = NULL;
    if (p_remove_locks) *p_remove_locks = NULL;

    if (bind && bind->cur_resource && !bind->collection) {
        repos_hooks = bind->cur_resource->hooks;
        err = (*repos_hooks->get_parent_resource)(bind->cur_resource, 
                                                  &bind->collection);
        if (err) return err;
        bind->bind_name = basename(bind->cur_resource->uri);
    }

    if (unbind && unbind->cur_resource && !unbind->collection) {
        if (!repos_hooks)
            repos_hooks = unbind->cur_resource->hooks;
        err = (*repos_hooks->get_parent_resource)(unbind->cur_resource, 
                                                  &unbind->collection);
        if (err) return err;
        unbind->bind_name = basename(unbind->cur_resource->uri);
    }

    /* always parse (and later process) the If: header */
    if ((err = dav_process_if_header(r, &if_hdr)) != NULL) {
        /* ### maybe add higher-level description */
        return err;
    }

    if (lockdb == NULL) {
        if (locks_hooks != NULL) {
            err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb);
            if (err) return err;
            lock_db_opened_locally = 1;
        }
    }

    /* Verify the remainder of ifheader */
    err = dav_validate_ifheader_lists(r, if_hdr, lockdb);
    if (err) return err;

    if (flags & DAV_VALIDATE_BIND) {
        err = dav_validate_bind(r, depth, if_hdr, lockdb, bind, unbind, flags,
                                response, p_refresh_locks, p_remove_locks);
        if (err) goto error;
    }

    if (flags & DAV_VALIDATE_UNBIND) {
        dav_lock *l_i = *p_remove_locks;
        if (l_i) while(l_i->next) l_i = l_i->next;
        err = dav_validate_unbind(r, if_hdr, lockdb, unbind, flags,
                                  response, l_i ? &l_i->next : p_remove_locks);
        if (err) goto error;
    }

    if (flags & DAV_VALIDATE_RESOURCE) {
        err = dav_validate_resource(r, if_hdr, lockdb, bind->cur_resource, flags,
                                    response);
        if (err) goto error;
    }

    if (flags & DAV_VALIDATE_NEW_LOCK) {
        err = dav_validate_new_lock(r, if_hdr, depth, lockdb, bind, flags,
                                    response);
        if (err) goto error;
    }

    if (flags & DAV_VALIDATE_UNLOCK) {
        err = dav_validate_unlock(r, if_hdr, lockdb, bind, flags,
                                  p_remove_locks, response);
        if (err) goto error;
    }

 error:
    if (lock_db_opened_locally)
        (*locks_hooks->close_lockdb)(lockdb);
    return err;
}

/* dav_get_locktoken_list:
 *
 * Sets ltl to a locktoken_list of all positive locktokens in header,
 * else NULL if no If-header, or no positive locktokens.
 */
DAV_DECLARE(dav_error *) dav_get_locktoken_list(request_rec *r,
                                                dav_locktoken_list **ltl)
{
    dav_error *err;
    dav_if_header *if_header;
    dav_if_state_list *if_state;
    dav_locktoken_list *lock_token = NULL;

    *ltl = NULL;

    if ((err = dav_process_if_header(r, &if_header)) != NULL) {
        /* ### add a higher-level description? */
        return err;
    }

    while (if_header != NULL) {
        if_state = if_header->state;        /* Begining of the if_state linked list */
        while (if_state != NULL)        {
            if (if_state->condition == DAV_IF_COND_NORMAL
                && if_state->type == dav_if_opaquelock) {
                lock_token = apr_pcalloc(r->pool, sizeof(dav_locktoken_list));
                lock_token->locktoken = if_state->locktoken;
                lock_token->next = *ltl;
                *ltl = lock_token;
            }
            if_state = if_state->next;
        }
        if_header = if_header->next;
    }
    if (*ltl == NULL) {
        /* No nodes added */
        return dav_new_error(r->pool, HTTP_BAD_REQUEST, DAV_ERR_IF_ABSENT,
                             "No locktokens were specified in the \"If:\" "
                             "header, so the refresh could not be performed.");
    }

    return NULL;
}

#if 0 /* not needed right now... */

static const char *strip_white(const char *s, apr_pool_t *pool)
{
    apr_size_t idx;

    /* trim leading whitespace */
    while (apr_isspace(*s))     /* assume: return false for '\0' */
        ++s;

    /* trim trailing whitespace */
    idx = strlen(s) - 1;
    if (apr_isspace(s[idx])) {
        char *s2 = apr_pstrdup(pool, s);

        while (apr_isspace(s2[idx]) && idx > 0)
            --idx;
        s2[idx + 1] = '\0';
        return s2;
    }

    return s;
}
#endif

#define DAV_LABEL_HDR "Label"

/* dav_add_vary_header
 *
 * If there were any headers in the request which require a Vary header
 * in the response, add it.
 */
DAV_DECLARE(void) dav_add_vary_header(request_rec *in_req,
                                      request_rec *out_req,
                                      const dav_resource *resource)
{
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(in_req);

    /* ### this is probably all wrong... I think there is a function in
       ### the Apache API to add things to the Vary header. need to check */

    /* Only versioning headers require a Vary response header,
     * so only do this check if there is a versioning provider */
    if (vsn_hooks != NULL) {
        const char *target = apr_table_get(in_req->headers_in, DAV_LABEL_HDR);
        const char *vary = apr_table_get(out_req->headers_out, "Vary");

        /* If Target-Selector specified, add it to the Vary header */
        if (target != NULL) {
            if (vary == NULL)
                vary = DAV_LABEL_HDR;
            else
                vary = apr_pstrcat(out_req->pool, vary, "," DAV_LABEL_HDR,
                                   NULL);

            apr_table_setn(out_req->headers_out, "Vary", vary);
        }
    }
}

/* dav_can_auto_checkout
 *
 * Determine whether auto-checkout is enabled for a resource.
 * r - the request_rec
 * resource - the resource
 * auto_version - the value of the auto_versionable hook for the resource
 * lockdb - pointer to lock database (opened if necessary)
 * auto_checkout - set to 1 if auto-checkout enabled
 */
static dav_error * dav_can_auto_checkout(
    request_rec *r,
    dav_resource *resource,
    dav_auto_version auto_version,
    dav_lockdb **lockdb,
    int *auto_checkout)
{
    dav_error *err;
    dav_lock *lock_list;

    *auto_checkout = 0;

    if (*lockdb == NULL) {
        const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);

        if (locks_hooks == NULL) {
            return dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                                 "Auto-checkout is only enabled for locked resources, "
                                 "but there is no lock provider.");
        }

        if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, lockdb)) != NULL) {
            return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                                  "Cannot open lock database to determine "
                                  "auto-versioning behavior.",
                                  err);
        }
    }

    if ((err = dav_lock_query(*lockdb, resource, &lock_list)) != NULL) {
        return dav_push_error(r->pool,
                              HTTP_INTERNAL_SERVER_ERROR, 0,
                              "The locks could not be queried for "
                              "determining auto-versioning behavior.",
                              err);
    }

    if (auto_version == DAV_AUTO_VERSION_ALWAYS) {
        *auto_checkout = 1;
    }
    else if (auto_version == DAV_AUTO_VERSION_LOCKED) {
        if (lock_list != NULL)
            *auto_checkout = 1;
    }

    if (lock_list != NULL) {
        const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
        if (vsn_hooks != NULL)
            vsn_hooks->set_checkin_on_unlock(resource);
    }

    return NULL;
}

/* see mod_dav.h for docco */
DAV_DECLARE(dav_error *) dav_auto_checkout(
    request_rec *r,
    dav_resource *resource,
    int parent_only,
    dav_auto_version_info *av_info)
{
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_lockdb *lockdb = NULL;
    dav_error *err = NULL;
    dav_resource *parent;

    /* Initialize results */
    memset(av_info, 0, sizeof(*av_info));

    if ((err = (*resource->hooks->get_parent_resource)(resource,
                                                           &parent)) != NULL)
	 goto done;

    if (parent == NULL || !parent->exists) {
	 err = dav_new_error(r->pool, HTTP_CONFLICT, 0,
			     apr_psprintf(r->pool,
					  "Missing one or more intermediate "
					  "collections. Cannot create resource %s.",
					  ap_escape_html(r->pool, resource->uri)));
	 goto done;
    }


    /* if no versioning provider, just return */
    if (vsn_hooks == NULL)
        return NULL;

    /* check parent resource if requested or if resource must be created */
    if (parent_only || (!resource->exists && ((*vsn_hooks->auto_versionable)(resource) == DAV_AUTO_VERSION_ALWAYS))) {



        av_info->parent_resource = parent;

        /* if parent versioned and not checked out, see if it can be */
        if (parent->versioned && !parent->working) {
            int checkout_parent;

            if ((err = dav_can_auto_checkout(r, parent,
                                             (*vsn_hooks->auto_versionable)(parent),
                                             &lockdb, &checkout_parent))
                != NULL) {
                goto done;
            }

            if (!checkout_parent) {
                err = dav_new_error(r->pool, HTTP_CONFLICT, 0,
                                    "<DAV:cannot-modify-checked-in-parent>");
                goto done;
            }

            /* Try to checkout the parent collection.
             * Note that auto-versioning can only be applied to a version selector,
             * so no separate working resource will be created.
             */
            if ((err = (*vsn_hooks->checkout)(parent, 1 /*auto_checkout*/,
                                              0, 0, 0, NULL, NULL))
                != NULL)
            {
                err = dav_push_error(r->pool, HTTP_CONFLICT, 0,
                                     apr_psprintf(r->pool,
                                                 "Unable to auto-checkout parent collection. "
                                                 "Cannot create resource %s.",
                                                 ap_escape_html(r->pool, resource->uri)),
                                     err);
                goto done;
            }

            /* remember that parent was checked out */
            av_info->parent_checkedout = 1;
        }
    }

    /* if only checking parent, we're done */
    if (parent_only)
        goto done;

    /* if creating a new resource, see if it should be version-controlled */
    if (!resource->exists
        && (*vsn_hooks->auto_versionable)(resource) == DAV_AUTO_VERSION_ALWAYS) {

        if ((err = (*vsn_hooks->vsn_control)(resource, NULL)) != NULL) {
            err = dav_push_error(r->pool, HTTP_CONFLICT, 0,
                                 apr_psprintf(r->pool,
                                             "Unable to create versioned resource %s.",
                                             ap_escape_html(r->pool, resource->uri)),
                                 err);
            goto done;
        }

        /* remember that resource was created */
        av_info->resource_versioned = 1;
    }

    /* if resource is versioned, make sure it is checked out */
    if (resource->versioned && !resource->working) {
        int checkout_resource;

        if (av_info->resource_versioned == 1)
            checkout_resource = 1;
        else
        if ((err = dav_can_auto_checkout(r, resource,
                                         (*vsn_hooks->auto_versionable)(resource),
                                         &lockdb, &checkout_resource)) != NULL) {
            goto done;
        }

        if (!checkout_resource) {
            err = dav_new_error(r->pool, HTTP_CONFLICT, 0,
                                "<DAV:cannot-modify-version-controlled-content>");
            goto done;
        }

        /* Auto-versioning can only be applied to version selectors, so
         * no separate working resource will be created. */
        if ((err = (*vsn_hooks->checkout)(resource, 1 /*auto_checkout*/,
                                          0, 0, 0, NULL, NULL))
            != NULL)
        {
            err = dav_push_error(r->pool, HTTP_CONFLICT, 0,
                                 apr_psprintf(r->pool,
                                             "Unable to checkout resource %s.",
                                             ap_escape_html(r->pool, resource->uri)),
                                 err);
            goto done;
        }

        /* remember that resource was checked out */
        av_info->resource_checkedout = 1;
    }

done:

    /* make sure lock database is closed */
    if (lockdb != NULL)
        (*lockdb->hooks->close_lockdb)(lockdb);

    /* if an error occurred, undo any auto-versioning operations already done */
    if (err != NULL) {
        dav_auto_checkin(r, resource, 1 /*undo*/, 0 /*unlock*/, av_info);
        return err;
    }

    return NULL;
}

/* see mod_dav.h for docco */
DAV_DECLARE(dav_error *) dav_auto_checkin(
    request_rec *r,
    dav_resource *resource,
    int undo,
    int unlock,
    dav_auto_version_info *av_info)
{
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_error *err = NULL;
    dav_auto_version auto_version;

    /* If no versioning provider, this is a no-op */
    if (vsn_hooks == NULL)
        return NULL;

    /* If undoing auto-checkouts, then do uncheckouts */
    if (undo) {
        if (resource != NULL) {
            if (av_info->resource_checkedout) {
                if ((err = (*vsn_hooks->uncheckout)(resource)) != NULL) {
                    return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                                          apr_psprintf(r->pool,
                                                      "Unable to undo auto-checkout "
                                                      "of resource %s.",
                                                      ap_escape_html(r->pool, resource->uri)),
                                          err);
                }
            }

            if (av_info->resource_versioned) {
                dav_response *response;

                /* ### should we do anything with the response? */
                if ((err = (*resource->hooks->remove_resource)(resource,
                                                               &response)) != NULL) {
                    return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                                          apr_psprintf(r->pool,
                                                      "Unable to undo auto-version-control "
                                                      "of resource %s.",
                                                      ap_escape_html(r->pool, resource->uri)),
                                          err);
                }
            }
        }

        if (av_info->parent_resource != NULL && av_info->parent_checkedout) {
            if ((err = (*vsn_hooks->uncheckout)(av_info->parent_resource)) != NULL) {
                return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                                      apr_psprintf(r->pool,
                                                  "Unable to undo auto-checkout "
                                                  "of parent collection %s.",
                                                  ap_escape_html(r->pool, av_info->parent_resource->uri)),
                                      err);
            }
        }

        return NULL;
    }

    /* If the resource was checked out, and auto-checkin is enabled,
     * then check it in.
     */
    if (resource != NULL && resource->working
        && (unlock || av_info->resource_checkedout)) {

        auto_version = (*vsn_hooks->auto_versionable)(resource);

        if (auto_version == DAV_AUTO_VERSION_ALWAYS ||
            (av_info && av_info->resource_versioned) ||
            (unlock && (auto_version == DAV_AUTO_VERSION_LOCKED))) {

            if ((err = (*vsn_hooks->checkin)(resource,
                                             0 /*keep_checked_out*/, NULL))
                != NULL) {
                return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                                      apr_psprintf(r->pool,
                                                  "Unable to auto-checkin resource %s.",
                                                  ap_escape_html(r->pool, resource->uri)),
                                      err);
            }
        }
    }

    /* If parent resource was checked out, and auto-checkin is enabled,
     * then check it in.
     */
    if (!unlock
        && av_info->parent_checkedout
        && av_info->parent_resource != NULL
        && av_info->parent_resource->working) {

        auto_version = (*vsn_hooks->auto_versionable)(av_info->parent_resource);

        if (auto_version == DAV_AUTO_VERSION_ALWAYS) {
            if ((err = (*vsn_hooks->checkin)(av_info->parent_resource,
                                             0 /*keep_checked_out*/, NULL))
                != NULL) {
                return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                                      apr_psprintf(r->pool,
                                                  "Unable to auto-checkin parent collection %s.",
                                                  ap_escape_html(r->pool, av_info->parent_resource->uri)),
                                                  err);
            }
        }
    }

    return NULL;
}

const char *dav_get_full_url(request_rec *r, const char *uri)
{
    const char *host = apr_table_get(r->headers_in, "Host");
    return apr_psprintf(r->pool, "http://%s%s", host, uri);
}
