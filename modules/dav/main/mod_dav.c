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
 * DAV extension module for Apache 2.0.*
 *
 * This module is repository-independent. It depends on hooks provided by a
 * repository implementation.
 *
 * APACHE ISSUES:
 *   - within a DAV hierarchy, if an unknown method is used and we default
 *     to Apache's implementation, it sends back an OPTIONS with the wrong
 *     set of methods -- there is NO HOOK for us.
 *     therefore: we need to manually handle the HTTP_METHOD_NOT_ALLOWED
 *       and HTTP_NOT_IMPLEMENTED responses (not ap_send_error_response).
 *   - process_mkcol_body() had to dup code from ap_setup_client_block().
 *   - it would be nice to get status lines from Apache for arbitrary
 *     status codes
 *   - it would be nice to be able to extend Apache's set of response
 *     codes so that it doesn't return 500 when an unknown code is placed
 *     into r->status.
 *   - http_vhost functions should apply "const" to their params
 *
 * DESIGN NOTES:
 *   - For PROPFIND, we batch up the entire response in memory before
 *     sending it. We may want to reorganize around sending the information
 *     as we suck it in from the propdb. Alternatively, we should at least
 *     generate a total Content-Length if we're going to buffer in memory
 *     so that we can keep the connection open.
 */

#include "apr_strings.h"
#include "apr_lib.h"            /* for apr_is* */

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"

#include "mod_dav.h"


/* ### what is the best way to set this? */
#define DAV_DEFAULT_PROVIDER    "filesystem"

/* used to denote that mod_dav will be handling this request */
#define DAV_HANDLER_NAME "dav-handler"

/* dav_lookup_uri flags */
#define MUST_BE_ABSOLUTE        1
#define ALLOW_CROSS_DOMAIN      2

enum {
    DAV_ENABLED_UNSET = 0,
    DAV_ENABLED_OFF,
    DAV_ENABLED_ON
};

/* per-dir configuration */
typedef struct {
    const char *provider_name;
    const dav_provider *provider;
    const char *dir;
    const char *rootpath;
    int locktimeout;
    int allow_depthinfinity;
    int allow_unauthenticated_access;
    apr_array_header_t *rewrite_conds;
    apr_array_header_t *rewrite_rules;
} dav_dir_conf;

/* per-server configuration */
typedef struct {
    int unused;

} dav_server_conf;

typedef struct {
    const char *lhs;
    const char *rhs;
} dav_rewrite_entry;

#define DAV_INHERIT_VALUE(parent, child, field) \
                ((child)->field ? (child)->field : (parent)->field)


/* forward-declare for use in configuration lookup */
extern module DAV_DECLARE_DATA dav_module;

/* Principal Methods */
dav_principal *dav_principal_make_from_request(request_rec *r)
{
    dav_principal *principal;
    const dav_hooks_acl *acl_hooks = dav_get_acl_hooks(r);

    principal = (*acl_hooks->get_prin_by_name)(r, r->user);
    return principal;
}

dav_principal* dav_principal_make_from_url(request_rec *r, 
                                           const char *url)
{
    dav_principal *principal = NULL;
    dav_resource *resource = NULL;

    if (url) {
        dav_get_resource_from_uri(apr_pstrcat(r->pool, url, "?no_rewrite", NULL),
                                  r, ALLOW_CROSS_DOMAIN, NULL, &resource);
        if(resource && resource->exists && resource->type == DAV_RESOURCE_TYPE_PRINCIPAL ) {
            principal = apr_pcalloc(r->pool, sizeof(dav_principal));
            principal->type = PRINCIPAL_HREF;
            principal->resource = resource;
        }
    }

    return principal;
}

int dav_get_permission_denied_status(request_rec *r) {
    dav_principal *prin = dav_principal_make_from_request(r);
    if(prin->type == PRINCIPAL_UNAUTHENTICATED) {
        if (!apr_table_get(r->notes, "mod_dav_unauth_set_headers")) {
            apr_table_setn(r->notes, "mod_dav_unauth_set_headers", (char *)1);
            /* Set the authentication headers. If needed, issue the client a fresh challenge */
            return ap_run_check_user_id(r);
        }
        return HTTP_UNAUTHORIZED;
    } else
        return HTTP_FORBIDDEN;
}

/* DAV methods */
static dav_all_methods *dav_registered_methods;

enum {
    DAV_M_BIND = 0,
    DAV_M_UNBIND,
    DAV_M_REBIND,
    DAV_M_SEARCH,
    DAV_M_ACL,
    DAV_M_MKREDIRECTREF,
    DAV_M_UPDATEREDIRECTREF,
    DAV_M_LAST
};
static int dav_methods[DAV_M_LAST];

struct _dav_request {
    request_rec *request;
    dav_transaction *trans;
    dav_resource *resource;
    dav_resource *parent_resource;
    int apply_to_redirectref;
};

struct _dav_method {
    int (*handle)(dav_request *dav_r);
    int (*is_allow)(dav_request *dav_r, const dav_hooks_acl *acl_hooks, 
                    const dav_principal *principal);
    int label_allowed;
    int use_checked_in;
    int is_transactional;
};

struct _dav_all_methods {
    apr_hash_t *method_hash;
};

static void *dav_create_server_config(apr_pool_t *p, server_rec *s)
{
    dav_server_conf *newconf;

    newconf = (dav_server_conf *)apr_pcalloc(p, sizeof(*newconf));

    return newconf;
}

static void *dav_merge_server_config(apr_pool_t *p, void *base, void *overrides)
{
#if 0
    dav_server_conf *child = overrides;
#endif
    dav_server_conf *newconf;

    newconf = (dav_server_conf *)apr_pcalloc(p, sizeof(*newconf));

    /* ### nothing to merge right now... */

    return newconf;
}

static void *dav_create_dir_config(apr_pool_t *p, char *dir)
{
    /* NOTE: dir==NULL creates the default per-dir config */

    dav_dir_conf *conf;

    conf = (dav_dir_conf *)apr_pcalloc(p, sizeof(*conf));

    /* clean up the directory to remove any trailing slash */
    if (dir != NULL) {
        char *d;
        apr_size_t l;

        d = apr_pstrdup(p, dir);
        l = strlen(d);
        if (l > 1 && d[l - 1] == '/')
            d[l - 1] = '\0';
        conf->dir = d;
    }
    conf->allow_unauthenticated_access = -1;
    conf->rewrite_conds = apr_array_make(p, 2, sizeof(dav_rewrite_entry));
    conf->rewrite_rules = apr_array_make(p, 2, sizeof(dav_rewrite_entry));

    return conf;
}

static void *dav_merge_dir_config(apr_pool_t *p, void *base, void *overrides)
{
    dav_dir_conf *parent = base;
    dav_dir_conf *child = overrides;
    dav_dir_conf *newconf = (dav_dir_conf *)apr_pcalloc(p, sizeof(*newconf));

    /* DBG3("dav_merge_dir_config: new=%08lx  base=%08lx  overrides=%08lx",
       (long)newconf, (long)base, (long)overrides); */

    newconf->provider_name = DAV_INHERIT_VALUE(parent, child, provider_name);
    newconf->provider = DAV_INHERIT_VALUE(parent, child, provider);
    if (parent->provider_name != NULL) {
        if (child->provider_name == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "\"DAV Off\" cannot be used to turn off a subtree "
                         "of a DAV-enabled location.");
        }
        else if (strcasecmp(child->provider_name,
                            parent->provider_name) != 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "A subtree cannot specify a different DAV provider "
                         "than its parent.");
        }
    }

    newconf->locktimeout = DAV_INHERIT_VALUE(parent, child, locktimeout);
    newconf->dir = DAV_INHERIT_VALUE(parent, child, dir);
    newconf->rootpath = DAV_INHERIT_VALUE(child, parent, rootpath);
    newconf->allow_depthinfinity = DAV_INHERIT_VALUE(parent, child,
                                                     allow_depthinfinity);
    newconf->allow_unauthenticated_access = 
        child->allow_unauthenticated_access == -1 ? 
            parent->allow_unauthenticated_access : 
            child->allow_unauthenticated_access;

    newconf->rewrite_conds = apr_array_append(p, child->rewrite_conds, 
                                                parent->rewrite_conds);
    newconf->rewrite_rules = apr_array_append(p, child->rewrite_rules, 
                                                parent->rewrite_rules);
    return newconf;
}

static const dav_provider *dav_get_provider(request_rec *r)
{
    dav_dir_conf *conf;

    conf = ap_get_module_config(r->per_dir_config, &dav_module);
    /* assert: conf->provider_name != NULL
       (otherwise, DAV is disabled, and we wouldn't be here) */

    /* assert: conf->provider != NULL
       (checked when conf->provider_name is set) */
    return conf->provider;
}

DAV_DECLARE(const dav_hooks_repository *) dav_get_repos_hooks(request_rec *r)
{
    return dav_get_provider(r)->repos;
}

DAV_DECLARE(const dav_hooks_locks *) dav_get_lock_hooks(request_rec *r)
{
    return dav_get_provider(r)->locks;
}

DAV_DECLARE(const dav_hooks_propdb *) dav_get_propdb_hooks(request_rec *r)
{
    return dav_get_provider(r)->propdb;
}

DAV_DECLARE(const dav_hooks_vsn *) dav_get_vsn_hooks(request_rec *r)
{
    return dav_get_provider(r)->vsn;
}

DAV_DECLARE(const dav_hooks_binding *) dav_get_binding_hooks(request_rec *r)
{
    return dav_get_provider(r)->binding;
}

DAV_DECLARE(const dav_hooks_search *) dav_get_search_hooks(request_rec *r)
{
    return dav_get_provider(r)->search;
}

DAV_DECLARE(const dav_hooks_acl *) dav_get_acl_hooks(request_rec *r)
{
    return dav_get_provider(r)->acl;
}

DAV_DECLARE(const dav_hooks_transaction *) dav_get_transaction_hooks(request_rec *r)
{
    return dav_get_provider(r)->transaction;
}

DAV_DECLARE(const dav_hooks_redirect *) dav_get_redirect_hooks(request_rec *r)
{
    return dav_get_provider(r)->redirect;
}

static dav_error *dav_transaction_start(request_rec *r, dav_transaction **t)
{
    const dav_hooks_transaction *transaction_hooks = DAV_GET_HOOKS_TRANSACTION(r);
    dav_error *err = NULL;

    if(transaction_hooks)
        err = transaction_hooks->start(r, t);

    if(!err) 
        (*t)->state = DAV_TRANSACTION_STATE_STARTED;

    return err;
}

static dav_error *dav_transaction_end(request_rec *r, dav_transaction *t)
{
    const dav_hooks_transaction *transaction_hooks = dav_get_transaction_hooks(r);
    dav_error *err = NULL;

    if(t && t->state == DAV_TRANSACTION_STATE_STARTED) {
        err = transaction_hooks->end(t);
        t->state = DAV_TRANSACTION_STATE_ENDED;
    }
    return err;
}

/*
 * Command handler for the DAV directive, which is TAKE1.
 */
static const char *dav_cmd_dav(cmd_parms *cmd, void *config, const char *arg1)
{
    dav_dir_conf *conf = (dav_dir_conf *)config;

    if (strcasecmp(arg1, "on") == 0) {
        conf->provider_name = DAV_DEFAULT_PROVIDER;
    }
    else if (strcasecmp(arg1, "off") == 0) {
        conf->provider_name = NULL;
        conf->provider = NULL;
    }
    else {
        conf->provider_name = apr_pstrdup(cmd->pool, arg1);
    }

    if (conf->provider_name != NULL) {
        conf->rootpath = conf->dir;

        /* lookup and cache the actual provider now */
        conf->provider = dav_lookup_provider(conf->provider_name);

        if (conf->provider == NULL) {
            /* by the time they use it, the provider should be loaded and
               registered with us. */
            return apr_psprintf(cmd->pool,
                                "Unknown DAV provider: %s",
                                conf->provider_name);
        }
    }

    return NULL;
}

/*
 * Command handler for the DAVDepthInfinity directive, which is FLAG.
 */
static const char *dav_cmd_davdepthinfinity(cmd_parms *cmd, void *config,
                                            int arg)
{
    dav_dir_conf *conf = (dav_dir_conf *)config;

    if (arg)
        conf->allow_depthinfinity = DAV_ENABLED_ON;
    else
        conf->allow_depthinfinity = DAV_ENABLED_OFF;
    return NULL;
}

/*
 * Command handler for DAVMinTimeout directive, which is TAKE1
 */
static const char *dav_cmd_davmintimeout(cmd_parms *cmd, void *config,
                                         const char *arg1)
{
    dav_dir_conf *conf = (dav_dir_conf *)config;

    conf->locktimeout = atoi(arg1);
    if (conf->locktimeout < 0)
        return "DAVMinTimeout requires a non-negative integer.";

    return NULL;
}

static const char *dav_cmd_davresponserewritecond(cmd_parms *cmd, void *config,
                                                  const char *lhs, const char *rhs)
{
    dav_dir_conf *conf = (dav_dir_conf *)config;
    dav_rewrite_entry *new_entry = apr_array_push(conf->rewrite_conds);

    new_entry->lhs = lhs;
    new_entry->rhs = rhs;

    return NULL;
}

static const char *dav_cmd_davresponserewriterule(cmd_parms *cmd, void *config,
                                                  const char *lhs, const char *rhs)
{
    dav_dir_conf *conf = (dav_dir_conf *)config;
    dav_rewrite_entry *new_entry = apr_array_push(conf->rewrite_rules);

    new_entry->lhs = lhs;
    new_entry->rhs = rhs;

    return NULL;
}

static void expect_100_fixups(request_rec *r)
{
    /* According to RFC 2616 Sec 4.4, 
     * request bodies MUST be denoted by either CL or TE.
     * unset the CL/TE headers so that input filters do not wait for body */
    apr_table_unset(r->headers_in, "Content-Length");
    apr_table_unset(r->headers_in, "Transfer-Encoding");

    /* We need to flush the error response 
     * before the input filters send back 100 Continue. */
    ap_rflush(r);

    /* Signal end of response */
    ap_finalize_request_protocol(r);
}

/*
** dav_error_response()
**
** Send a nice response back to the user. In most cases, Apache doesn't
** allow us to provide details in the body about what happened. This
** function allows us to completely specify the response body.
**
** ### this function is not logging any errors! (e.g. the body)
*/
static int dav_error_response(request_rec *r, int status, const char *body)
{
    r->status = status;

    /* ### I really don't think this is needed; gotta test */
    r->status_line = ap_get_status_line(status);

    ap_set_content_type(r, "text/html; charset=ISO-8859-1");

    /* begin the response now... */
    ap_rvputs(r,
              DAV_RESPONSE_BODY_1,
              r->status_line,
              DAV_RESPONSE_BODY_2,
              &r->status_line[4],
              DAV_RESPONSE_BODY_3,
              body,
              DAV_RESPONSE_BODY_4,
              ap_psignature("<hr />\n", r),
              DAV_RESPONSE_BODY_5,
              NULL);

    /* the response has been sent. */
    /*
     * ### Use of DONE obviates logging..!
     */
    return DONE;
}


/*
 * Send a "standardized" error response based on the error's namespace & tag
 */
static int dav_error_response_tag(request_rec *r,
                                  dav_error *err)
{
    r->status = err->status;

    ap_set_content_type(r, DAV_XML_CONTENT_TYPE);

    ap_rputs(DAV_XML_HEADER DEBUG_CR, r);

    /* append any additional prolog supplied */
    if (err->prolog) {
        ap_rputs(err->prolog, r);
    }

    ap_rputs("<D:error xmlns:D=\"DAV:\"", r);

    if (err->desc != NULL) {
        /* ### should move this namespace somewhere (with the others!) */
        ap_rputs(" xmlns:m=\"http://apache.org/dav/xmlns\"", r);
    }

    if (err->namespace != NULL) {
        ap_rprintf(r,
                   " xmlns:C=\"%s\">" DEBUG_CR
                   "<C:%s>%s</C:%s>" DEBUG_CR,
                   err->namespace, err->tagname, err->content, err->tagname);
    }
    else {
        ap_rprintf(r,
                   ">" DEBUG_CR
                   "<D:%s>%s</D:%s>" DEBUG_CR, err->tagname,err->content, err->tagname);
    }

    /* here's our mod_dav specific tag: */
    if (err->desc != NULL) {
        ap_rprintf(r,
                   "<m:human-readable errcode=\"%d\">" DEBUG_CR
                   "%s" DEBUG_CR
                   "</m:human-readable>" DEBUG_CR,
                   err->error_id,
                   apr_xml_quote_string(r->pool, err->desc, 0));
    }

    ap_rputs("</D:error>" DEBUG_CR, r);

    /* the response has been sent. */
    /*
     * ### Use of DONE obviates logging..!
     */
    return DONE;
}


/*
 * Apache's URI escaping does not replace '&' since that is a valid character
 * in a URI (to form a query section). We must explicitly handle it so that
 * we can embed the URI into an XML document.
 */
static const char *dav_xml_escape_uri(apr_pool_t *p, const char *uri)
{
    const char *e_uri = ap_escape_uri(p, uri);

    /* check the easy case... */
    if (ap_strchr_c(e_uri, '&') == NULL)
        return e_uri;

    /* there was a '&', so more work is needed... sigh. */

    /*
     * Note: this is a teeny bit of overkill since we know there are no
     * '<' or '>' characters, but who cares.
     */
    return apr_xml_quote_string(p, e_uri, 0);
}

/*
 * apply response uri rewrites, escape the uri, construct the href tags
 */
const char *dav_get_response_href(request_rec *r, const char *uri)
{
    dav_dir_conf *conf = ap_get_module_config(r->per_dir_config, &dav_module);
    const char *host = apr_table_get(r->headers_in, "Host");
    ap_regex_t *cond_regex, *rule_regex;
    apr_size_t nmatch = AP_MAX_REG_MATCH;
    ap_regmatch_t pmatch[AP_MAX_REG_MATCH];
    char *result_uri = apr_pstrdup(r->pool, uri);
    const dav_hooks_repository *repos_hooks = dav_get_repos_hooks(r);
    int i, match = 0;
    dav_rewrite_entry cond_i, rule_i;


    /* check rewrite condition, we only support Host for now */
    if(!apr_table_get(r->subprocess_env, "no-response-rewrite")) {
        for(i=0; i<conf->rewrite_conds->nelts; i++) {
            match = 0;
            cond_i = ((dav_rewrite_entry *)conf->rewrite_conds->elts)[i];
            rule_i = ((dav_rewrite_entry *)conf->rewrite_rules->elts)[i];

            cond_regex = ap_pregcomp(r->pool, cond_i.rhs, 0);
            if(!apr_strnatcasecmp(cond_i.lhs, "Host")) {
                if(!ap_regexec(cond_regex, host, nmatch, pmatch, 0)) {
                    /* condition matched, apply the rule */
                    match = 1;
                }
            }
            else if(!apr_strnatcasecmp(cond_i.lhs, "Request-URI")) {
                if(!ap_regexec(cond_regex, r->unparsed_uri, nmatch, pmatch, 0)) {
                    match = 1;
                }
            }

            if (match) {
                rule_regex = ap_pregcomp(r->pool, rule_i.lhs, 0);
                if(!ap_regexec(rule_regex, uri, nmatch, pmatch, 0)) {
                    /* uri matches the rule lhs, rewrite uri to rhs */
                    result_uri = ap_pregsub(r->pool, rule_i.rhs, result_uri, 
                                            nmatch, pmatch);
                }
                ap_pregfree(r->pool, rule_regex);
            }
            ap_pregfree(r->pool, cond_regex);
        }
    }

    return repos_hooks->response_href_transform(r, result_uri);
} 

/* Write a complete RESPONSE object out as a <DAV:repsonse> xml
   element.  Data is sent into brigade BB, which is auto-flushed into
   OUTPUT filter stack.  Use POOL for any temporary allocations.

   [Presumably the <multistatus> tag has already been written;  this
   routine is shared by dav_send_multistatus and dav_stream_response.]
*/
static void dav_send_one_response(dav_response *response,
                                  apr_bucket_brigade *bb,
                                  ap_filter_t *output,
                                  apr_pool_t *pool)
{
    apr_text *t = NULL;

    if (response->propresult.xmlns == NULL) {
      ap_fputs(output, bb, "<D:response>");
    }
    else {
      ap_fputs(output, bb, "<D:response");
      for (t = response->propresult.xmlns; t; t = t->next) {
        ap_fputs(output, bb, t->text);
      }
      ap_fputc(output, bb, '>');
    }

    ap_fputstrs(output, bb,
                DEBUG_CR "<D:href>",
                dav_xml_escape_uri(pool, response->href),
                "</D:href>" DEBUG_CR,
                NULL);

    if (response->propresult.propstats == NULL) {
      /* use the Status-Line text from Apache.  Note, this will
       * default to 500 Internal Server Error if first->status
       * is not a known (or valid) status code.
       */
      ap_fputstrs(output, bb,
                  "<D:status>HTTP/1.1 ",
                  ap_get_status_line(response->status),
                  "</D:status>" DEBUG_CR,
                  NULL);
    }
    else {
      /* assume this includes <propstat> and is quoted properly */
      for (t = response->propresult.propstats; t; t = t->next) {
        ap_fputs(output, bb, t->text);
      }
    }

    if (response->desc != NULL) {
      /*
       * We supply the description, so we know it doesn't have to
       * have any escaping/encoding applied to it.
       */
      ap_fputstrs(output, bb,
                  "<D:responsedescription>",
                  response->desc,
                  "</D:responsedescription>" DEBUG_CR,
                  NULL);
    }

    ap_fputs(output, bb, "</D:response>" DEBUG_CR);
}


/* Factorized helper function: prep request_rec R for a multistatus
   response and write <multistatus> tag into BB, destined for
   R->output_filters.  Use xml NAMESPACES in initial tag, if
   non-NULL. */
static void dav_begin_multistatus(apr_bucket_brigade *bb,
                                  request_rec *r, int status,
                                  apr_array_header_t *namespaces)
{
    /* Set the correct status and Content-Type */
    r->status = status;
    ap_set_content_type(r, DAV_XML_CONTENT_TYPE);

    /* Send the headers and actual multistatus response now... */
    ap_fputs(r->output_filters, bb, DAV_XML_HEADER DEBUG_CR
             "<D:multistatus xmlns:D=\"DAV:\"");

    if (namespaces != NULL) {
       int i;

       for (i = namespaces->nelts; i--; ) {
           ap_fprintf(r->output_filters, bb, " xmlns:ns%d=\"%s\"", i,
                      APR_XML_GET_URI_ITEM(namespaces, i));
       }
    }

    ap_fputs(r->output_filters, bb, ">" DEBUG_CR);
}

/* Finish a multistatus response started by dav_begin_multistatus: */
static apr_status_t dav_finish_multistatus(request_rec *r,
                                           apr_bucket_brigade *bb)
{
    apr_bucket *b;

    ap_fputs(r->output_filters, bb, "</D:multistatus>" DEBUG_CR);

    /* indicate the end of the response body */
    b = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    /* deliver whatever might be remaining in the brigade */
    return ap_pass_brigade(r->output_filters, bb);
}

static void dav_send_multistatus(request_rec *r, int status,
                                 dav_response *first,
                                 apr_array_header_t *namespaces)
{
    apr_pool_t *subpool;
    apr_bucket_brigade *bb = apr_brigade_create(r->pool,
                                                r->connection->bucket_alloc);

    dav_begin_multistatus(bb, r, status, namespaces);

    apr_pool_create(&subpool, r->pool);

    for (; first != NULL; first = first->next) {
      apr_pool_clear(subpool);
      first->href = dav_get_response_href(r, first->href);
      dav_send_one_response(first, bb, r->output_filters, subpool);
    }
    apr_pool_destroy(subpool);

    dav_finish_multistatus(r, bb);
}

/*
 * dav_log_err()
 *
 * Write error information to the log.
 */
static void dav_log_err(request_rec *r, dav_error *err, int level)
{
    dav_error *errscan;

    /* Log the errors */
    /* ### should have a directive to log the first or all */
    for (errscan = err; errscan != NULL; errscan = errscan->prev) {
        if (errscan->desc == NULL)
            continue;

        if (errscan->save_errno != 0) {
            errno = errscan->save_errno;
            ap_log_rerror(APLOG_MARK, level, errno, r, "%s  [%d, #%d]",
                          errscan->desc, errscan->status, errscan->error_id);
        }
        else {
            ap_log_rerror(APLOG_MARK, level, 0, r,
                          "%s  [%d, #%d]",
                          errscan->desc, errscan->status, errscan->error_id);
        }
    }
}

/*
 * dav_handle_err()
 *
 * Handle the standard error processing. <err> must be non-NULL.
 *
 * <response> is set by the following:
 *   - dav_validate_request()
 *   - dav_add_lock()
 *   - repos_hooks->remove_resource
 *   - repos_hooks->move_resource
 *   - repos_hooks->copy_resource
 *   - vsn_hooks->update
 */
static int dav_handle_err(request_rec *r, dav_error *err,
                          dav_response *response)
{
    /* log the errors */
    dav_log_err(r, err, APLOG_ERR);

    if (response == NULL) {
        dav_error *stackerr = err;

        /* our error messages are safe; tell Apache this */
        apr_table_setn(r->notes, "verbose-error-to", "*");

        /* Didn't get a multistatus response passed in, but we still
           might be able to generate a standard <D:error> response.
           Search the error stack for an errortag. */
        while (stackerr != NULL && stackerr->tagname == NULL)
            stackerr = stackerr->prev;

        if (stackerr != NULL && stackerr->tagname != NULL)
            return dav_error_response_tag(r, stackerr);

        return err->status;
    }

    /* send the multistatus and tell Apache the request/response is DONE. */
    dav_send_multistatus(r, err->status, response, NULL);
    return DONE;
}

/* handy function for return values of methods that (may) create things */
static int dav_created(request_rec *r, const char *locn, const char *what,
                       int replaced)
{
    const char *body;

    if (locn == NULL) {
        locn = r->uri;
    }

    /* did the target resource already exist? */
    if (replaced) {
        /* Apache will supply a default message */
        return HTTP_NO_CONTENT;
    }

    /* Per HTTP/1.1, S10.2.2: add a Location header to contain the
     * URI that was created. */

    /* Convert locn to an absolute URI, and return in Location header
       Disable setting Location header because IE uses it to redirect when it shouldn't
    apr_table_setn(r->headers_out, "Location", ap_construct_url(r->pool, locn, r));
    */

    /* ### insert an ETag header? see HTTP/1.1 S10.2.2 */

    /* Apache doesn't allow us to set a variable body for HTTP_CREATED, so
     * we must manufacture the entire response. */
    body = apr_psprintf(r->pool, "%s %s has been created.",
                        what, ap_escape_html(r->pool, locn));
    return dav_error_response(r, HTTP_CREATED, body);
}

/* ### move to dav_util? */
DAV_DECLARE(int) dav_get_depth(request_rec *r, int def_depth)
{
    const char *depth = apr_table_get(r->headers_in, "Depth");

    if (depth == NULL) {
        return def_depth;
    }

    if (strcasecmp(depth, "infinity") == 0) {
        return DAV_INFINITY;
    }
    else if (strcmp(depth, "0") == 0) {
        return 0;
    }
    else if (strcmp(depth, "1") == 0) {
        return 1;
    }

    /* The caller will return an HTTP_BAD_REQUEST. This will augment the
     * default message that Apache provides. */
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "An invalid Depth header was specified.");
    return -1;
}

static int dav_get_overwrite(request_rec *r)
{
    const char *overwrite = apr_table_get(r->headers_in, "Overwrite");

    if (overwrite == NULL) {
        return 1; /* default is "T" */
    }

    if ((*overwrite == 'F' || *overwrite == 'f') && overwrite[1] == '\0') {
        return 0;
    }

    if ((*overwrite == 'T' || *overwrite == 't') && overwrite[1] == '\0') {
        return 1;
    }

    /* The caller will return an HTTP_BAD_REQUEST. This will augment the
     * default message that Apache provides. */
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "An invalid Overwrite header was specified.");
    return -1;
}

/* resolve a request URI to a resource descriptor.
 *
 * If label_allowed != 0, then allow the request target to be altered by
 * a Label: header.
 *
 * If use_checked_in is true, then the repository provider should return
 * the resource identified by the DAV:checked-in property of the resource
 * identified by the Request-URI.
 */
DAV_DECLARE(dav_error) *dav_get_resource(request_rec *r, int label_allowed,
                                         int use_checked_in, dav_resource **res_p)
{
    dav_dir_conf *conf;
    const char *label = NULL;
    dav_error *err;

    /* if the request target can be overridden, get any target selector */
    if (label_allowed) {
        label = apr_table_get(r->headers_in, "label");
    }

    conf = ap_get_module_config(r->per_dir_config, &dav_module);
    /* assert: conf->provider != NULL */

    /* resolve the resource */
    err = (*conf->provider->repos->get_resource)(r, conf->rootpath,
                                                 label, use_checked_in,
                                                 res_p);
    if (err != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             "Could not fetch resource information.", err);
        return err;
    }

    /* Note: this shouldn't happen, but just be sure... */
    if (*res_p == NULL) {
        /* ### maybe use HTTP_INTERNAL_SERVER_ERROR */
        return dav_new_error(r->pool, HTTP_NOT_FOUND, 0,
                             apr_psprintf(r->pool,
                                          "The provider did not define a "
                                          "resource for %s.",
                                          ap_escape_html(r->pool, r->uri)));
    }

    /* ### hmm. this doesn't feel like the right place or thing to do */
    /* if there were any input headers requiring a Vary header in the response,
     * add it now */
    dav_add_vary_header(r, r, *res_p);

    return NULL;
}

static dav_error * dav_open_lockdb(request_rec *r, int ro, dav_lockdb **lockdb)
{
    const dav_hooks_locks *hooks = DAV_GET_HOOKS_LOCKS(r);

    if (hooks == NULL) {
        *lockdb = NULL;
        return NULL;
    }

    /* open the thing lazily */
    return (*hooks->open_lockdb)(r, ro, 0, lockdb);
}

static int dav_parse_range(request_rec *r,
                           apr_off_t *range_start, apr_off_t *range_end)
{
    const char *range_c;
    char *range;
    char *dash;
    char *slash;
    char *errp;

    range_c = apr_table_get(r->headers_in, "content-range");
    if (range_c == NULL)
        return 0;

    range = apr_pstrdup(r->pool, range_c);
    if (strncasecmp(range, "bytes ", 6) != 0
        || (dash = ap_strchr(range, '-')) == NULL
        || (slash = ap_strchr(range, '/')) == NULL) {
        /* malformed header. ignore it (per S14.16 of RFC2616) */
        return 0;
    }

    *dash++ = *slash++ = '\0';

    /* ignore invalid ranges. (per S14.16 of RFC2616) */
    if (apr_strtoff(range_start, range + 6, &errp, 10)
        || *errp || *range_start < 0) {
        return 0;
    }

    if (apr_strtoff(range_end, dash, &errp, 10)
        || *errp || *range_end < 0 || *range_end < *range_start) {
        return 0;
    }

    if (*slash != '*') {
        apr_off_t dummy;

        if (apr_strtoff(&dummy, slash, &errp, 10)
            || *errp || dummy <= *range_end) {
            return 0;
        }
    }

    /* we now have a valid range */
    return 1;
}

int dav_handle_davmount(request_rec *r)
{
    /* set-up response headers */
    r->status = HTTP_OK;
    r->status_line = ap_get_status_line(HTTP_OK);
    ap_set_content_type(r, DAV_MOUNT_CONTENT_TYPE);

    /* since we are reporting dm:username, disallow public caching */
    apr_table_setn(r->headers_out, "Cache-Control", "private");

    /* now send the xml body */

    if (!strcmp(r->user, "unauthenticated")) {
        /* dont send username element for unauthenticated user */
        ap_rprintf(r, 
                DAV_XML_HEADER DEBUG_CR
                "<dm:mount xmlns:dm=" DAV_MOUNT_XMLNS ">" DEBUG_CR
                "  <dm:url>%s</dm:url>" DEBUG_CR
                "</dm:mount>" DEBUG_CR,
                dav_get_full_url(r, dav_get_response_href(r, r->uri)));
    }
    else {
        ap_rprintf(r, 
                DAV_XML_HEADER DEBUG_CR
                "<dm:mount xmlns:dm=" DAV_MOUNT_XMLNS ">" DEBUG_CR
                "  <dm:url>%s</dm:url>" DEBUG_CR
                "  <dm:username>%s</dm:username>" DEBUG_CR
                "</dm:mount>" DEBUG_CR,
                dav_get_full_url(r, dav_get_response_href(r, r->uri)), r->user);
    }

    return DONE;
}

int dav_query_handler(request_rec *r)
{
    /* currently we only handle action=davmount */
    if(strcmp(r->args, DAV_MOUNT_QUERY) == 0) 
        return dav_handle_davmount(r);

    /* for unhandled queries, just return NOT_FOUND */
    return DECLINED;
}

/* handle the GET method */
static int dav_method_get(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    int retVal;
    dav_error *err = NULL;
    
    /* RFC 4437, Section 5:
        As redirect references do not have body,
        GET and PUT requests with Apply-To-Redirect-Ref: "T" must fail,
        with status 403
    */
    if (dav_r->apply_to_redirectref) {
        return HTTP_FORBIDDEN;
    }

    /* look for QUERY_ARGS that have been extracted from the request 
     * and handle them appropriately */
    if(r->args) {
        if ((retVal = dav_query_handler(r)) != DECLINED)
            return retVal;
    }

    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    if (err) {
        return dav_handle_err(r, err, NULL);
    }

    if (resource->type != DAV_RESOURCE_TYPE_REGULAR
        && resource->type != DAV_RESOURCE_TYPE_VERSION) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    /* set up the HTTP headers for the response */
    if ((err = (*resource->hooks->set_headers)(r, resource)) != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             "Unable to set up HTTP headers.",
                             err);
        return dav_handle_err(r, err, NULL);
    }

    if (r->header_only) {
        return DONE;
    }

    /* Discard the body needed to handle Expect 100-Continue
     * if this is an internal redirect (think ErrorDocument) */
    if ((retVal = ap_discard_request_body(r)) != OK) {
        return retVal;
    }

    /* okay... time to deliver the content */
    if ((err = (*resource->hooks->deliver)(resource,
                                           r->output_filters)) != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             "Unable to deliver content.",
                             err);
        return dav_handle_err(r, err, NULL);
    }

    return DONE;
}

static int dav_is_allow_method_get(dav_request *dav_r, 
                                   const dav_hooks_acl *acl_hook, 
                                   const dav_principal *principal)
{
    int retVal = TRUE;
    dav_resource *resource = dav_r->resource;

    if(resource->exists && acl_hook != NULL) 
        retVal = (*acl_hook->is_allow)(principal, resource, 
                                       DAV_PERMISSION_READ);

    return retVal;
}

/* validate resource/locks on POST, then pass to the default handler */
static int dav_method_post(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    dav_error *err;
    int resource_state;

    dav_bind bind = { 0 };
    bind.cur_resource = bind.new_resource = resource;

    resource_state = dav_get_resource_state(r, resource);
    err = dav_validate_request
      (r, 0, NULL, &bind, NULL, DAV_VALIDATE_BIND |
       DAV_VALIDATE_IGNORE_TARGET_LOCKS, resource_state, NULL, NULL, NULL);
    if (err) return dav_handle_err(r, err, NULL);

    return DECLINED;
}

/* handle the PUT method */
static int dav_method_put(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    int resource_state;
    dav_auto_version_info av_info;
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    const char *body;
    dav_error *err;
    dav_error *err2;
    dav_stream_mode mode;
    dav_stream *stream;
    int has_range;
    apr_off_t range_start;
    apr_off_t range_end;

    /* RFC 4437, Section 5:
        As redirect references do not have body,
        GET and PUT requests with Apply-To-Redirect-Ref: "T" must fail,
        with status 403
    */
    if (dav_r->apply_to_redirectref) {
        return HTTP_FORBIDDEN;
    }

    /* If not a file or collection resource, PUT not allowed */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR
        && resource->type != DAV_RESOURCE_TYPE_WORKING
        && resource->type != DAV_RESOURCE_TYPE_PRINCIPAL) {
        body = apr_psprintf(r->pool,
                            "Cannot create resource %s with PUT.",
                            ap_escape_html(r->pool, r->uri));
        return dav_error_response(r, HTTP_CONFLICT, body);
    }

    /* Cannot PUT a collection */
    if (resource->collection) {
        return dav_error_response(r, HTTP_METHOD_NOT_ALLOWED,
                                  "Cannot PUT to a collection.");

    }

    resource_state = dav_get_resource_state(r, resource);

    dav_bind bind = { 0 };
    bind.cur_resource = bind.new_resource = resource;
    err = dav_validate_request
      (r, 0, NULL, &bind, NULL, DAV_VALIDATE_BIND |
       DAV_VALIDATE_IGNORE_TARGET_LOCKS, resource_state, NULL, NULL, NULL);
    if (err) return dav_handle_err(r, err, NULL);

    /* make sure the resource can be modified (if versioning repository) */
    if ((err = dav_auto_checkout(r, resource,
                                 0 /* not parent_only */,
                                 &av_info)) != NULL) {
        /* ### add a higher-level description? */
        return dav_handle_err(r, err, NULL);
    }

    /* truncate and rewrite the file unless we see a Content-Range */
    mode = DAV_MODE_WRITE_TRUNC;

    has_range = dav_parse_range(r, &range_start, &range_end);
    if (has_range) {
        mode = DAV_MODE_WRITE_SEEKABLE;
    }

    /* Create the new file in the repository */
    if ((err = (*resource->hooks->open_stream)(resource, mode,
                                               &stream)) != NULL) {
        goto error;
    }

    if (err == NULL && has_range) {
        /* a range was provided. seek to the start */
        err = (*resource->hooks->seek_stream)(stream, range_start);
    }

    if (err == NULL) {
        apr_bucket_brigade *bb;
        apr_bucket *b;
        int seen_eos = 0;

        bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

        do {
            apr_status_t rc;

            rc = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                                APR_BLOCK_READ, DAV_READ_BLOCKSIZE);

            if (rc != APR_SUCCESS) {
                err = dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                                    "Could not get next bucket brigade");
                break;
            }

            for (b = APR_BRIGADE_FIRST(bb);
                 b != APR_BRIGADE_SENTINEL(bb);
                 b = APR_BUCKET_NEXT(b))
            {
                const char *data;
                apr_size_t len;

                if (APR_BUCKET_IS_EOS(b)) {
                    seen_eos = 1;
                    break;
                }

                if (APR_BUCKET_IS_METADATA(b)) {
                    continue;
                }

                rc = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
                if (rc != APR_SUCCESS) {
                    err = dav_new_error(r->pool, HTTP_BAD_REQUEST, 0,
                                        "An error occurred while reading "
                                        "the request body.");
                    break;
                }

                if (err == NULL) {
                    /* write whatever we read, until we see an error */
                    err = (*resource->hooks->write_stream)(stream, data, len);
                }
            }

            apr_brigade_cleanup(bb);
        } while (!seen_eos);

        apr_brigade_destroy(bb);

        err2 = (*resource->hooks->close_stream)(stream,
                                                err == NULL /* commit */);
        if (err2 != NULL && err == NULL) {
            /* no error during the write, but we hit one at close. use it. */
            err = err2;
        }
    }

    /*
     * Ensure that we think the resource exists now.
     * ### eek. if an error occurred during the write and we did not commit,
     * ### then the resource might NOT exist (e.g. dav_fs_repos.c)
     */
    if (err == NULL) {
        resource->exists = 1;
    }

    /* restore modifiability of resources back to what they were */
    err2 = dav_auto_checkin(r, resource, err != NULL /* undo if error */,
                            0 /*unlock*/, &av_info);

    /* check for errors now */
    if (err != NULL) {
        goto error;
    }

    if (err2 != NULL) {
        /* just log a warning */
        err2 = dav_push_error(r->pool, err2->status, 0,
                              "The PUT was successful, but there "
                              "was a problem automatically checking in "
                              "the resource or its parent collection.",
                              err2);
        dav_log_err(r, err2, APLOG_WARNING);
    }

    /* ### place the Content-Type and Content-Language into the propdb */

    if (locks_hooks != NULL) {
        dav_lockdb *lockdb;

        if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb)) != NULL) {
            /* The file creation was successful, but the locking failed. */
            err = dav_push_error(r->pool, err->status, 0,
                                 "The file was PUT successfully, but there "
                                 "was a problem opening the lock database "
                                 "which prevents inheriting locks from the "
                                 "parent resources.",
                                 err);
            goto error;
        }

        /* notify lock system that we have created/replaced a resource */
        err = dav_notify_created(r, lockdb, resource, resource_state, 0);

        (*locks_hooks->close_lockdb)(lockdb);

        if (err != NULL) {
            /* The file creation was successful, but the locking failed. */
            err = dav_push_error(r->pool, err->status, 0,
                                 "The file was PUT successfully, but there "
                                 "was a problem updating its lock "
                                 "information.",
                                 err);
            goto error;
        }
    }
    
    /* set up the HTTP headers for the response */
    if ((err = (*resource->hooks->set_headers)(r, resource)) != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             "Unable to set up HTTP headers.",
                             err);
        goto error;
    }

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    /* NOTE: WebDAV spec, S8.7.1 states properties should be unaffected */

    /* return an appropriate response (HTTP_CREATED or HTTP_NO_CONTENT) */
    return dav_created(r, NULL, "Resource", resource_state == DAV_RESOURCE_EXISTS);

 error:
    if (dav_r->trans) {
        const dav_hooks_transaction *xaction_hooks = dav_get_transaction_hooks(r);
        xaction_hooks->mode_set(dav_r->trans, DAV_TRANSACTION_ROLLBACK);
    }

    return dav_handle_err(r, err, NULL);
}

static int dav_is_allow_method_put(dav_request *dav_r, 
                                   const dav_hooks_acl *acl_hook, 
                                   const dav_principal *principal)
{
    request_rec *r = dav_r->request;
    int retVal = TRUE;
    dav_resource *resource = dav_r->resource;
    dav_error *err;

    /* If not a file or collection resource, PUT not allowed */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR
        && resource->type != DAV_RESOURCE_TYPE_WORKING
        && resource->type != DAV_RESOURCE_TYPE_PRINCIPAL)
        return retVal;

    /* Cannot PUT a collection */
    if (resource->collection)
        return retVal;

    if (acl_hook != NULL)
    {
        if(dav_get_resource_state(r, resource) == DAV_RESOURCE_NULL) {
            const dav_hooks_repository *repos_hooks = resource->hooks;
            dav_resource *parent_resource = NULL;

            err = (*repos_hooks->get_parent_resource)(resource, 
                                                      &parent_resource);

            if (err == NULL && parent_resource && parent_resource->exists ) {
                retVal = (*acl_hook->is_allow)(principal, parent_resource, 
                                               DAV_PERMISSION_BIND);

                /* percolate the need-privileges error tag */
                if(!retVal) resource->err = parent_resource->err; 
            }
        }
        else
            retVal = (*acl_hook->is_allow)(principal, resource, 
                                           DAV_PERMISSION_WRITE_CONTENT);
      
    }
    
    return retVal;	
}

/* Use POOL to temporarily construct a dav_response object (from WRES
   STATUS, and PROPSTATS) and stream it via WRES's ctx->brigade. */
static void dav_stream_response(dav_walk_resource *wres,
                                int status,
                                dav_get_props_result *propstats,
                                apr_pool_t *pool)
{
    dav_response resp = { 0 };
    dav_walker_ctx *ctx = wres->walk_ctx;

    resp.href = dav_get_response_href(ctx->r, wres->resource->uri);
    resp.status = status;
    if (propstats) {
        resp.propresult = *propstats;
    }

    dav_send_one_response(&resp, ctx->bb, ctx->r->output_filters, pool);
}


/* ### move this to dav_util? */
DAV_DECLARE(void) dav_add_response(dav_walk_resource *wres,
                                   int status, dav_get_props_result *propstats)
{
    dav_response *resp;

    /* just drop some data into an dav_response */
    resp = apr_pcalloc(wres->pool, sizeof(*resp));
    resp->href = apr_pstrdup(wres->pool, wres->resource->uri);
    resp->status = status;
    if (propstats) {
        resp->propresult = *propstats;
    }

    resp->next = wres->response;
    wres->response = resp;
}


/* handle the DELETE method */
static int dav_method_delete(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    dav_lockdb *lockdb = NULL;
    dav_auto_version_info av_info;
    dav_error *err = NULL;
    dav_error *err2 = NULL;
    dav_response *multi_response;
    int result;
    int depth;
    int resource_state;

    /* We don't use the request body right now, so torch it. */
    if ((result = ap_discard_request_body(r)) != OK) {
        return result;
    }

    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    /* 2518 says that depth must be infinity only for collections.
     * For non-collections, depth is ignored, unless it is an illegal value (1).
     */
    depth = dav_get_depth(r, DAV_INFINITY);

    if (resource->collection && depth != DAV_INFINITY) {
        /* This supplies additional information for the default message. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Depth must be \"infinity\" for DELETE of a collection.");
        return HTTP_BAD_REQUEST;
    }

    if (!resource->collection && depth == 1) {
        /* This supplies additional information for the default message. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Depth of \"1\" is not allowed for DELETE.");
        return HTTP_BAD_REQUEST;
    }

    if ((err = dav_open_lockdb(r, 0, &lockdb)) != NULL) {
        /* ### add a higher-level description? */
        return dav_handle_err(r, err, NULL);
    }

    dav_lock *lrl_to_delete = NULL, *li = NULL;
    dav_bind unbind = { 0 };
    unbind.cur_resource = resource;
    resource_state = dav_get_resource_state(r, resource);
    err = dav_validate_request
      (r, DAV_INFINITY, lockdb, NULL, &unbind, DAV_VALIDATE_UNBIND, resource_state,
       &multi_response, NULL, &lrl_to_delete);
    if (err) return dav_handle_err(r, err, multi_response);

    /* ### RFC 2518 s. 8.10.5 says to remove _all_ locks, not just those
     *     locked by the token(s) in the if_header.
     */
    if ((result = dav_unlock(r, resource, NULL)) != OK) {
        return result;
    }

    /* if versioned resource, make sure parent is checked out */
    if ((err = dav_auto_checkout(r, resource, 1 /* parent_only */,
                                 &av_info)) != NULL) {
        /* ### add a higher-level description? */
        return dav_handle_err(r, err, NULL);
    }

    /* try to remove the resource */
    err = (*resource->hooks->remove_resource)(resource, &multi_response);

    if (!err) 
        for (li = lrl_to_delete; li && !err; li = li->next)
            err = (*lockdb->hooks->remove_lock)(lockdb, NULL, li->locktoken);

    if (lockdb != NULL)
        (*lockdb->hooks->close_lockdb)(lockdb);
        
    /* restore writability of parent back to what it was */
    err2 = dav_auto_checkin(r, NULL, err != NULL /* undo if error */,
                            0 /*unlock*/, &av_info);

    /* check for errors now */
    if (err != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             apr_psprintf(r->pool,
                                          "Could not DELETE %s.",
                                          ap_escape_html(r->pool, r->uri)),
                             err);
        return dav_handle_err(r, err, multi_response);
    }
    if (err2 != NULL) {
        /* just log a warning */
        err = dav_push_error(r->pool, err2->status, 0,
                             "The DELETE was successful, but there "
                             "was a problem automatically checking in "
                             "the parent collection.",
                             err2);
        dav_log_err(r, err, APLOG_WARNING);
    }

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    /* ### HTTP_NO_CONTENT if no body, HTTP_OK if there is a body (some day) */

    /* Apache will supply a default error for this. */
    return HTTP_NO_CONTENT;
}

static int dav_is_allow_method_delete(dav_request *dav_r, 
                                      const dav_hooks_acl *acl_hook, 
                                      const dav_principal *principal)
{
    int retVal = TRUE;
    dav_resource *resource = dav_r->resource;
    dav_error *err;

    if(acl_hook != NULL) {
        const dav_hooks_repository *repos_hooks = resource->hooks;
        dav_resource *parent_resource = NULL;

        err = (*repos_hooks->get_parent_resource)(resource, 
                                                  &parent_resource);

        if (err == NULL && parent_resource && parent_resource->exists ) {
            retVal = (*acl_hook->is_allow)(principal, parent_resource, 
                                           DAV_PERMISSION_UNBIND); 
            
            /* percolate the need-privileges error tag */
            if(!retVal) resource->err = parent_resource->err; 
        }    
    }
    
    return retVal;
}

static void dav_gen_supported_methods_table(request_rec *r,
                                            const dav_resource *resource,
                                            apr_table_t **p_methods)
{
    /*
     * Determine which methods are allowed on the resource.
     * Three cases:  resource is null (3), is lock-null (7.4), or exists.
     *
     * All cases support OPTIONS, and if there is a lock provider, LOCK.
     * (Lock-) null resources also support MKCOL and PUT.
     * Lock-null supports PROPFIND and UNLOCK.
     * Existing resources support lots of stuff.
     */

    const dav_hooks_acl *acl_hooks = dav_get_acl_hooks(r);
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    const dav_hooks_binding *binding_hooks = DAV_GET_HOOKS_BINDING(r);
    const dav_hooks_search *search_hooks = DAV_GET_HOOKS_SEARCH(r);
    const dav_hooks_redirect *redirect_hooks = dav_get_redirect_hooks(r);
    apr_table_t *methods = apr_table_make(r->pool, 12);
    *p_methods = methods;

    apr_table_addn(methods, "OPTIONS", "");

    /* ### take into account resource type */
    switch (dav_get_resource_state(r, resource))
    {
    case DAV_RESOURCE_EXISTS:
        /* resource exists */
        apr_table_addn(methods, "GET", "");
        apr_table_addn(methods, "HEAD", "");
        apr_table_addn(methods, "POST", "");
        apr_table_addn(methods, "DELETE", "");
        apr_table_addn(methods, "TRACE", "");
        apr_table_addn(methods, "PROPFIND", "");
        apr_table_addn(methods, "PROPPATCH", "");
        apr_table_addn(methods, "COPY", "");
        apr_table_addn(methods, "MOVE", "");

        if (!resource->collection)
            apr_table_addn(methods, "PUT", "");

        if (locks_hooks != NULL) {
            apr_table_addn(methods, "LOCK", "");
            apr_table_addn(methods, "UNLOCK", "");
        }

        break;

    case DAV_RESOURCE_LOCK_NULL:
        /* resource is lock-null. */
        apr_table_addn(methods, "MKCOL", "");
        apr_table_addn(methods, "PROPFIND", "");
        apr_table_addn(methods, "PUT", "");

        if (locks_hooks != NULL) {
            apr_table_addn(methods, "LOCK", "");
            apr_table_addn(methods, "UNLOCK", "");
        }

        break;

    case DAV_RESOURCE_NULL:
        /* resource is null. */
        apr_table_addn(methods, "MKCOL", "");
        apr_table_addn(methods, "PUT", "");

        if (locks_hooks != NULL)
            apr_table_addn(methods, "LOCK", "");

        break;

    default:
        /* ### internal error! */
        break;
    }

    /* If there is a versioning provider, add versioning methods */
    if (vsn_hooks != NULL) {
        if (!resource->exists) {
            if ((*vsn_hooks->versionable)(resource))
                apr_table_addn(methods, "VERSION-CONTROL", "");

            if (vsn_hooks->can_be_workspace != NULL
                && (*vsn_hooks->can_be_workspace)(resource))
                apr_table_addn(methods, "MKWORKSPACE", "");

            if (vsn_hooks->can_be_activity != NULL
                && (*vsn_hooks->can_be_activity)(resource))
                apr_table_addn(methods, "MKACTIVITY", "");
        }
        else if (!resource->versioned) {
            if ((*vsn_hooks->versionable)(resource))
                apr_table_addn(methods, "VERSION-CONTROL", "");
        }
        else if (resource->working) {
            apr_table_addn(methods, "CHECKIN", "");

            /* ### we might not support this DeltaV option */
            apr_table_addn(methods, "UNCHECKOUT", "");
        }
        else if (vsn_hooks->add_label != NULL) {
            apr_table_addn(methods, "CHECKOUT", "");
            apr_table_addn(methods, "LABEL", "");
        }
        else {
            apr_table_addn(methods, "CHECKOUT", "");
        }
    }

    /* If there is a bindings provider, see if resource is bindable */
    if (binding_hooks != NULL
        && (*binding_hooks->is_bindable)(resource)) {
        apr_table_addn(methods, "BIND", "");
        apr_table_addn(methods, "UNBIND", "");
        apr_table_addn(methods, "REBIND", "");
   
    }

    /* If there is a search provider, set SEARCH in option */
    if (search_hooks != NULL) {
        apr_table_addn(methods, "SEARCH", "");
    }

    if (acl_hooks != NULL) {
        apr_table_addn(methods, "ACL", "");
    }

    if (redirect_hooks != NULL) {
        apr_table_addn(methods, "MKREDIRECTREF", "");
    }
}

/* generate DAV:supported-method-set OPTIONS response */
static dav_error *dav_gen_supported_methods(request_rec *r,
                                            const apr_xml_elem *elem,
                                            const apr_table_t *methods,
                                            apr_text_header *body)
{
    const apr_array_header_t *arr;
    const apr_table_entry_t *elts;
    apr_xml_elem *child;
    apr_xml_attr *attr;
    char *s;
    int i;

    apr_text_append(r->pool, body, "<D:supported-method-set>" DEBUG_CR);

    if (elem == NULL || elem->first_child == NULL) {
        /* show all supported methods */
        arr = apr_table_elts(methods);
        elts = (const apr_table_entry_t *)arr->elts;

        for (i = 0; i < arr->nelts; ++i) {
            if (elts[i].key == NULL)
                continue;

            s = apr_psprintf(r->pool,
                             "<D:supported-method D:name=\"%s\"/>"
                             DEBUG_CR,
                             elts[i].key);
            apr_text_append(r->pool, body, s);
        }
    }
    else {
        /* check for support of specific methods */
        for (child = elem->first_child; child != NULL; child = child->next) {
            if (child->ns == APR_XML_NS_DAV_ID
                && strcmp(child->name, "supported-method") == 0) {
                const char *name = NULL;

                /* go through attributes to find method name */
                for (attr = child->attr; attr != NULL; attr = attr->next) {
                    if (attr->ns == APR_XML_NS_DAV_ID
                        && strcmp(attr->name, "name") == 0)
                            name = attr->value;
                }

                if (name == NULL) {
                    return dav_new_error(r->pool, HTTP_BAD_REQUEST, 0,
                                         "A DAV:supported-method element "
                                         "does not have a \"name\" attribute");
                }

                /* see if method is supported */
                if (apr_table_get(methods, name) != NULL) {
                    s = apr_psprintf(r->pool,
                                     "<D:supported-method D:name=\"%s\"/>"
                                     DEBUG_CR,
                                     name);
                    apr_text_append(r->pool, body, s);
                }
            }
        }
    }

    apr_text_append(r->pool, body, "</D:supported-method-set>" DEBUG_CR);
    return NULL;
}

/* generate DAV:supported-live-property-set OPTIONS response */
static dav_error *dav_gen_supported_live_props(request_rec *r,
                                               const dav_resource *resource,
                                               const apr_xml_elem *elem,
                                               apr_text_header *body)
{
    dav_lockdb *lockdb;
    dav_propdb *propdb;
    apr_xml_elem *child;
    apr_xml_attr *attr;
    dav_error *err;

    /* open lock database, to report on supported lock properties */
    /* ### should open read-only */
    if ((err = dav_open_lockdb(r, 0, &lockdb)) != NULL) {
        return dav_push_error(r->pool, err->status, 0,
                              "The lock database could not be opened, "
                              "preventing the reporting of supported lock "
                              "properties.",
                              err);
    }

    /* open the property database (readonly) for the resource */
    if ((err = dav_open_propdb(r, lockdb, resource, 1, NULL,
                               &propdb)) != NULL) {
        if (lockdb != NULL)
            (*lockdb->hooks->close_lockdb)(lockdb);

        return dav_push_error(r->pool, err->status, 0,
                              "The property database could not be opened, "
                              "preventing report of supported properties.",
                              err);
    }

    apr_text_append(r->pool, body, "<D:supported-live-property-set>" DEBUG_CR);

    if (elem == NULL || elem->first_child == NULL) {
        /* show all supported live properties */
        dav_get_props_result props = dav_get_allprops(propdb, DAV_PROP_INSERT_SUPPORTED);
        body->last->next = props.propstats;
        while (body->last->next != NULL)
            body->last = body->last->next;
    }
    else {
        /* check for support of specific live property */
        for (child = elem->first_child; child != NULL; child = child->next) {
            if (child->ns == APR_XML_NS_DAV_ID
                && strcmp(child->name, "supported-live-property") == 0) {
                const char *name = NULL;
                const char *nmspace = NULL;

                /* go through attributes to find name and namespace */
                for (attr = child->attr; attr != NULL; attr = attr->next) {
                    if (attr->ns == APR_XML_NS_DAV_ID) {
                        if (strcmp(attr->name, "name") == 0)
                            name = attr->value;
                        else if (strcmp(attr->name, "namespace") == 0)
                            nmspace = attr->value;
                    }
                }

                if (name == NULL) {
                    err = dav_new_error(r->pool, HTTP_BAD_REQUEST, 0,
                                        "A DAV:supported-live-property "
                                        "element does not have a \"name\" "
                                        "attribute");
                    break;
                }

                /* default namespace to DAV: */
                if (nmspace == NULL)
                    nmspace = "DAV:";

                /* check for support of property */
                dav_get_liveprop_supported(propdb, nmspace, name, body);
            }
        }
    }

    apr_text_append(r->pool, body, "</D:supported-live-property-set>" DEBUG_CR);

    dav_close_propdb(propdb);

    if (lockdb != NULL)
        (*lockdb->hooks->close_lockdb)(lockdb);

    return err;
}

/* generate DAV:supported-report-set OPTIONS response */
static dav_error *dav_gen_supported_reports(request_rec *r,
                                            const dav_resource *resource,
                                            const apr_xml_elem *elem,
                                            const dav_hooks_vsn *vsn_hooks,
                                            apr_text_header *body)
{
    apr_xml_elem *child;
    apr_xml_attr *attr;
    dav_error *err;
    char *s;

    apr_text_append(r->pool, body, "<D:supported-report-set>" DEBUG_CR);

    if (vsn_hooks != NULL) {
        const dav_report_elem *reports;
        const dav_report_elem *rp;

        if ((err = (*vsn_hooks->avail_reports)(resource, &reports)) != NULL) {
            return dav_push_error(r->pool, err->status, 0,
                                  "DAV:supported-report-set could not be "
                                  "determined due to a problem fetching the "
                                  "available reports for this resource.",
                                  err);
        }

        if (reports != NULL) {
            if (elem == NULL || elem->first_child == NULL) {
                /* show all supported reports */
                for (rp = reports; rp->nmspace != NULL; ++rp) {
                    /* Note: we presume reports->namespace is
                     * properly XML/URL quoted */
                    s = apr_psprintf(r->pool,
                                     "<D:supported-report D:name=\"%s\" "
                                     "D:namespace=\"%s\"/>" DEBUG_CR,
                                     rp->name, rp->nmspace);
                    apr_text_append(r->pool, body, s);
                }
            }
            else {
                /* check for support of specific report */
                for (child = elem->first_child; child != NULL; child = child->next) {
                    if (child->ns == APR_XML_NS_DAV_ID
                        && strcmp(child->name, "supported-report") == 0) {
                        const char *name = NULL;
                        const char *nmspace = NULL;

                        /* go through attributes to find name and namespace */
                        for (attr = child->attr; attr != NULL; attr = attr->next) {
                            if (attr->ns == APR_XML_NS_DAV_ID) {
                                if (strcmp(attr->name, "name") == 0)
                                    name = attr->value;
                                else if (strcmp(attr->name, "namespace") == 0)
                                    nmspace = attr->value;
                            }
                        }

                        if (name == NULL) {
                            return dav_new_error(r->pool, HTTP_BAD_REQUEST, 0,
                                                 "A DAV:supported-report element "
                                                 "does not have a \"name\" attribute");
                        }

                        /* default namespace to DAV: */
                        if (nmspace == NULL)
                            nmspace = "DAV:";

                        for (rp = reports; rp->nmspace != NULL; ++rp) {
                            if (strcmp(name, rp->name) == 0
                                && strcmp(nmspace, rp->nmspace) == 0) {
                                /* Note: we presume reports->nmspace is
                                 * properly XML/URL quoted
                                 */
                                s = apr_psprintf(r->pool,
                                                 "<D:supported-report "
                                                 "D:name=\"%s\" "
                                                 "D:namespace=\"%s\"/>"
                                                 DEBUG_CR,
                                                 rp->name, rp->nmspace);
                                apr_text_append(r->pool, body, s);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    apr_text_append(r->pool, body, "</D:supported-report-set>" DEBUG_CR);
    return NULL;
}

dav_error *dav_gen_supported_options(request_rec *r,
                                     const dav_resource *resource,
                                     int propid, apr_text_header *body)
{
    if (propid == DAV_PROPID_supported_live_property_set)
        return dav_gen_supported_live_props(r, resource, NULL, body);

    if (propid == DAV_PROPID_supported_report_set) {
        const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
        return dav_gen_supported_reports(r, resource, NULL, vsn_hooks, body);
    }

    if (propid == DAV_PROPID_supported_method_set) {
        apr_table_t *methods;
        dav_gen_supported_methods_table(r, resource, &methods);
        return dav_gen_supported_methods(r, NULL, methods, body);
    }

    return NULL;
}

static const dav_principal *dav_acl_get_principal(request_rec *r,
                                                  apr_xml_elem *principal_elem)
{
    apr_pool_t *p = r->pool;
    const char *principal_url = NULL;
    dav_principal *principal = apr_pcalloc(p, sizeof(dav_principal));
    
    if (principal_elem)
    {
	apr_xml_elem *child_elem = NULL;
	if ( dav_find_child(principal_elem, "all") != NULL )
            principal->type = PRINCIPAL_ALL;
	else if ( dav_find_child(principal_elem, "authenticated") != NULL )
    	    principal->type = PRINCIPAL_AUTHENTICATED;
	else if ( dav_find_child(principal_elem, "unauthenticated") != NULL )
    	    principal->type = PRINCIPAL_UNAUTHENTICATED;
	else if ( ( child_elem = dav_find_child(principal_elem, "href") ) != NULL )
    	    principal_url = dav_xml_get_cdata(child_elem, p, TRUE);
        else
            principal = NULL;
    }
    
    if (principal_url)
	principal = dav_principal_make_from_url(r, principal_url);
    
    return principal;
}

static dav_prop_name *dav_acl_get_property(apr_pool_t *p, 
                                           apr_xml_elem *principal_elem,
                                           apr_array_header_t *ns_xlate )
{
    dav_prop_name *property = NULL;
    apr_xml_elem *child_elem = NULL;

    if ( ( child_elem = dav_find_child(principal_elem, "property") ) != NULL )
    {
        property = apr_pcalloc(p, sizeof(*property));
        property->ns = APR_XML_GET_URI_ITEM(ns_xlate, child_elem->first_child->ns);
        property->name = child_elem->first_child->name;
    }

    return property;
}

static dav_privileges *dav_acl_get_privileges(apr_pool_t *p, 
                                              apr_xml_elem *privilege_elem,
                                              apr_array_header_t *namespaces)
{
    dav_privileges *privileges = dav_privileges_new(p);
    if (privileges)
    {
	if (privilege_elem)
	{
	    apr_xml_elem *child_elem;
	    for (child_elem = privilege_elem->first_child; 
                 child_elem; 
                 child_elem = child_elem->next)
	    {
		if (child_elem->ns == APR_XML_NS_DAV_ID 
                 && !strcmp(child_elem->name, "privilege"))
		{
		    dav_privilege *privilege = dav_privilege_new_by_xml(p, namespaces, child_elem);
		    if (privilege)
			dav_add_privilege(privileges, privilege);
		}
	    }
	}
    }
    return privileges;
}

/* handle the SEARCH method */
static int dav_method_search(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    const dav_hooks_search *search_hooks = DAV_GET_HOOKS_SEARCH(r);
    dav_resource *resource = dav_r->resource;
    dav_error *err;
    dav_response *multi_status;

    /* If no search provider, decline the request */
    if (search_hooks == NULL)
        return DECLINED;

    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    /* set up the HTTP headers for the response */
    if ((err = (*resource->hooks->set_headers)(r, resource)) != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             "Unable to set up HTTP headers.",
                             err);
        return dav_handle_err(r, err, NULL);
    }

    if (r->header_only) {
        return DONE;
    }

    /* okay... time to search the content */
    /* Let's validate XML and process walk function
     * in the hook function
     */
    if ((err = (*search_hooks->search_resource)(r, resource, &multi_status)) != NULL) {
        /* ### add a higher-level description? */
        return dav_handle_err(r, err, NULL);
    }

    /* We have results in multi_status */
    /* Should I pass namespace?? */
    dav_send_multistatus(r, HTTP_MULTI_STATUS, multi_status, NULL);

    return DONE;
}

/* handle the ACL method */
static int dav_method_acl(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    dav_error *err = NULL;
    apr_xml_doc *doc;
    apr_xml_elem *ace_elem;

    dav_acl *new_acl;
    int result;
    const dav_hooks_acl *acl_hooks = dav_get_acl_hooks(r);

    if ( acl_hooks == NULL )
        return DECLINED;

    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    if (!(doc = (apr_xml_doc *)apr_table_get(r->notes, "parsed_xml_body"))) {
        if ((result = ap_xml_parse_input(r, &doc)) != OK)
            return result;
        apr_table_setn(r->notes, "parsed_xml_body", (char *)doc);
    }

    if ((doc == NULL) || (doc && !dav_validate_root(doc, "acl"))) {
        /* This supplies additional information for the default message. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "The \"acl\" element was not found.");
        return HTTP_BAD_REQUEST;
    }

    new_acl = (*acl_hooks->get_current_acl)(resource);
    if (!new_acl)
    {
        const dav_principal *currentPrincipal = 
            dav_principal_make_from_request(r);
        new_acl = dav_acl_new(r->pool, resource, currentPrincipal, 
                              currentPrincipal);
    }
    else
        dav_clear_all_ace(new_acl);

    if (!new_acl) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "can not create acl");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    for (ace_elem = doc->root->first_child; 
         ace_elem; 
         ace_elem = ace_elem->next)
    {
        if(ace_elem->ns != APR_XML_NS_DAV_ID 
         || strcmp(ace_elem->name, "ace") != 0)
            continue;   /* ignore non DAV:ace elements */

        apr_xml_elem *principal_elem;
        apr_xml_elem *property_elem;
        const dav_principal *principal = NULL;
        dav_prop_name *property = NULL;

        principal_elem = dav_find_child(ace_elem, "principal");
        principal = dav_acl_get_principal(r, principal_elem);

        if(!principal) {
            property_elem = dav_find_child(principal_elem, "property");
            property = dav_acl_get_property(r->pool, principal_elem, 
                                            doc->namespaces);
            apr_xml_elem *self_elem = NULL;
            if(property) {
                /* get the principal corresponding to the DAV:property */
                dav_propdb *propdb = NULL;
                dav_open_propdb(r, NULL, resource, 1, doc->namespaces, &propdb);
                dav_get_props_result prop_result = 
                                        dav_get_props(propdb, property_elem);

                /* parse the prop_result */
                apr_xml_parser *parser = apr_xml_parser_create(r->pool);
                apr_text *t = prop_result.propstats;
                apr_xml_doc *doc = NULL;

                /* DAV: xmlns declaration fix */
                const char *begin_multistatus = 
                                            "<D:multistatus xmlns:D=\"DAV:\">";
                apr_xml_parser_feed(parser, begin_multistatus, 
                                    strlen(begin_multistatus));
                for(; t; t = t->next)
                    apr_xml_parser_feed(parser, t->text, strlen(t->text));

                const char *end_multistatus = "</D:multistatus>";
                apr_xml_parser_feed(parser, end_multistatus, 
                                    strlen(end_multistatus));

                apr_xml_parser_done(parser, &doc);

                /* get the href elem */
                apr_xml_elem *property_elem = 
                            doc->root->first_child->first_child->first_child;

                apr_xml_elem *href_elem = dav_find_child(property_elem, "href");

                const char *principal_uri = 
                                    dav_xml_get_cdata(href_elem, r->pool, 1);

                principal = dav_principal_make_from_url(r, principal_uri);

            }
            else if((self_elem = dav_find_child(principal_elem, "self"))) {
                principal = dav_principal_make_from_url(r, resource->uri);
                property = apr_pcalloc(r->pool, sizeof(*property));
                property->name = self_elem->name;
            }
        }

        if(principal)
        {
            int is_deny;
            apr_xml_elem *ace_deny_elem;
            apr_xml_elem *ace_grant_elem;
            apr_xml_elem *ace_privileges_elem;
            dav_privileges *privileges;
            char *inherited=NULL;

            if (dav_find_child(ace_elem, "protected") 
             || dav_find_child(ace_elem, "inherited"))
                return HTTP_BAD_REQUEST;

            ace_deny_elem = dav_find_child(ace_elem, "deny");
            ace_grant_elem = dav_find_child(ace_elem, "grant");

            is_deny = ( ace_deny_elem != NULL );
            if ( is_deny && ( ace_grant_elem != NULL ) )
            {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "The grant and deny elements have found.");
                return HTTP_BAD_REQUEST;
            }

            ace_privileges_elem = is_deny ? ace_deny_elem : ace_grant_elem;
            privileges = dav_acl_get_privileges(r->pool, ace_privileges_elem, doc->namespaces);
            if ( privileges )
            {
                dav_ace *new_ace = dav_ace_new(r->pool, principal, property, 
                                               privileges, is_deny, inherited, 
                                               0 /*is_protected*/);
                if (new_ace)
                    dav_add_ace(new_acl, new_ace);
            }
        }
        else
        {
            err = dav_new_error_tag(r->pool, HTTP_FORBIDDEN, 0, 
                                    "wrong principal in ace", NULL, 
                                    "recognized-principal", NULL, NULL);
        }
    }

    if(!err) 
        err = (*acl_hooks->set_acl)(new_acl, NULL);

    /* if there was an error in set_acl, rollback any changes to this point */ 
    if(err) {
        const dav_hooks_transaction *xaction_hooks = dav_get_transaction_hooks(r);
        if (xaction_hooks && dav_r->trans)
            xaction_hooks->mode_set(dav_r->trans, DAV_TRANSACTION_ROLLBACK);
        
        return dav_handle_err(r, err, NULL);
    }

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    return OK;
}

static int dav_is_allow_method_acl(dav_request *dav_r, 
                                   const dav_hooks_acl *acl_hook, 
                                   const dav_principal *principal)
{
    int retVal = TRUE;
    dav_resource *resource = dav_r->resource;

    if(resource->exists && acl_hook != NULL) 
        retVal = (*acl_hook->is_allow)(principal, resource,
                                       DAV_PERMISSION_WRITE_ACL);

    return retVal;
}

/* handle the OPTIONS method */
static int dav_method_options(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    const dav_hooks_acl *acl_hooks = dav_get_acl_hooks(r);
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    const dav_hooks_binding *binding_hooks = DAV_GET_HOOKS_BINDING(r);
    const dav_hooks_search *search_hooks = DAV_GET_HOOKS_SEARCH(r);
    const dav_hooks_redirect *redirect_hooks = dav_get_redirect_hooks(r);
    dav_resource *resource = dav_r->resource;
    const char *dav_level;
    char *allow;
    char *s;
    const apr_array_header_t *arr;
    const apr_table_entry_t *elts;
    apr_table_t *methods;
    apr_text_header vsn_options = { 0 };
    apr_text_header body = { 0 };
    apr_text *t;
    int text_size;
    int result;
    int i;
    apr_array_header_t *uri_ary;
    apr_xml_doc *doc;
    const apr_xml_elem *elem;
    dav_error *err;

    /* parse any request body */
    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
        return result;
    }
    /* note: doc == NULL if no request body */

    if (doc && !dav_validate_root(doc, "options")) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The \"options\" element was not found.");
        return HTTP_BAD_REQUEST;
    }

    /* determine which providers are available */
    dav_level = "1";

    if (locks_hooks != NULL) {
        dav_level = "1, 2";
    }

    if (binding_hooks != NULL)
        dav_level = apr_pstrcat(r->pool, dav_level, ", bindings", NULL);

    if (acl_hooks != NULL)
        dav_level = apr_pstrcat(r->pool, dav_level, ", access-control", NULL);

    if (redirect_hooks != NULL)
        dav_level = apr_pstrcat(r->pool, dav_level, ", redirectrefs", NULL);

    /* ###
     * MSFT Web Folders chokes if length of DAV header value > 63 characters!
     * To workaround that, we use separate DAV headers for versioning and
     * live prop provider namespace URIs.
     * ###
     */
    apr_table_setn(r->headers_out, "DAV", dav_level);

    /*
     * If there is a versioning provider, generate DAV headers
     * for versioning options.
     */
    if (vsn_hooks != NULL) {
        (*vsn_hooks->get_vsn_options)(r->pool, &vsn_options);

        for (t = vsn_options.first; t != NULL; t = t->next)
            apr_table_addn(r->headers_out, "DAV", t->text);
    }

    /*
     * Gather property set URIs from all the liveprop providers,
     * and generate a separate DAV header for each URI, to avoid
     * problems with long header lengths.
     */
    uri_ary = apr_array_make(r->pool, 5, sizeof(const char *));
    dav_run_gather_propsets(uri_ary);
    for (i = 0; i < uri_ary->nelts; ++i) {
        if (((char **)uri_ary->elts)[i] != NULL)
            apr_table_addn(r->headers_out, "DAV", ((char **)uri_ary->elts)[i]);
    }

    /* this tells MSFT products to skip looking for FrontPage extensions */
    apr_table_setn(r->headers_out, "MS-Author-Via", "DAV");

    dav_gen_supported_methods_table(r, resource, &methods);

    /* Generate the Allow header */
    arr = apr_table_elts(methods);
    elts = (const apr_table_entry_t *)arr->elts;
    text_size = 0;

    /* first, compute total length */
    for (i = 0; i < arr->nelts; ++i) {
        if (elts[i].key == NULL)
            continue;

        /* add 1 for comma or null */
        text_size += strlen(elts[i].key) + 1;
    }

    s = allow = apr_pcalloc(r->pool, text_size);

    for (i = 0; i < arr->nelts; ++i) {
        if (elts[i].key == NULL)
            continue;

        if (s != allow)
            *s++ = ',';

        strcpy(s, elts[i].key);
        s += strlen(s);
    }

    apr_table_setn(r->headers_out, "Allow", allow);


    /* If there is search set_option_head function, set head */
    /* DASL: <DAV:basicsearch>
     * DASL: <http://foo.bar.com/syntax1>
     * DASL: <http://akuma.com/syntax2>
     */
    if (search_hooks != NULL
        && *search_hooks->set_option_head != NULL) {
        if ((err = (*search_hooks->set_option_head)(r)) != NULL) {
            return dav_handle_err(r, err, NULL);
        }
    }

    /* if there was no request body, then there is no response body */
    if (doc == NULL) {
        ap_set_content_length(r, 0);

        /* ### this sends a Content-Type. the default OPTIONS does not. */

        /* ### the default (ap_send_http_options) returns OK, but I believe
         * ### that is because it is the default handler and nothing else
         * ### will run after the thing. */
        return DONE;
    }

    /* handle each options request */
    for (elem = doc->root->first_child; elem != NULL; elem = elem->next) {
        /* check for something we recognize first */
        int core_option = 0;
        dav_error *err = NULL;

        if (elem->ns == APR_XML_NS_DAV_ID) {
            if (strcmp(elem->name, "supported-method-set") == 0) {
                err = dav_gen_supported_methods(r, elem, methods, &body);
                core_option = 1;
            }
            else if (strcmp(elem->name, "supported-live-property-set") == 0) {
                err = dav_gen_supported_live_props(r, resource, elem, &body);
                core_option = 1;
            }
            else if (strcmp(elem->name, "supported-report-set") == 0) {
                err = dav_gen_supported_reports(r, resource, elem, vsn_hooks, &body);
                core_option = 1;
            }
        }

        if (err != NULL)
            return dav_handle_err(r, err, NULL);

        /* if unrecognized option, pass to versioning provider */
        if (!core_option && vsn_hooks != NULL) {
            if ((err = (*vsn_hooks->get_option)(resource, elem, &body))
                != NULL) {
                return dav_handle_err(r, err, NULL);
            }
        }
    }

    /* send the options response */
    r->status = HTTP_OK;
    ap_set_content_type(r, DAV_XML_CONTENT_TYPE);

    /* send the headers and response body */
    ap_rputs(DAV_XML_HEADER DEBUG_CR
             "<D:options-response xmlns:D=\"DAV:\">" DEBUG_CR, r);

    for (t = body.first; t != NULL; t = t->next)
        ap_rputs(t->text, r);

    ap_rputs("</D:options-response>" DEBUG_CR, r);

    /* we've sent everything necessary to the client. */
    return DONE;
}

static void dav_cache_badprops(dav_walker_ctx *ctx)
{
    const apr_xml_elem *elem;
    apr_text_header hdr = { 0 };

    /* just return if we built the thing already */
    if (ctx->propstat_404 != NULL) {
        return;
    }

    apr_text_append(ctx->w.pool, &hdr,
                    "<D:propstat>" DEBUG_CR
                    "<D:prop>" DEBUG_CR);

    elem = dav_find_child(ctx->doc->root, "prop");
    for (elem = elem->first_child; elem; elem = elem->next) {
        apr_text_append(ctx->w.pool, &hdr,
                        apr_xml_empty_elem(ctx->w.pool, elem));
    }

    apr_text_append(ctx->w.pool, &hdr,
                    "</D:prop>" DEBUG_CR
                    "<D:status>HTTP/1.1 404 Not Found</D:status>" DEBUG_CR
                    "</D:propstat>" DEBUG_CR);

    ctx->propstat_404 = hdr.first;
}

static dav_error * dav_propfind_walker(dav_walk_resource *wres, int calltype)
{
    dav_walker_ctx *ctx = wres->walk_ctx;
    dav_error *err;
    dav_propdb *propdb;
    int is_allow = TRUE;
    apr_xml_elem *prop_elem;
    char *prop_text;
    dav_get_props_result propstats = { 0 };
    request_rec *r = ctx->r;
    const dav_hooks_acl *acl_hooks = dav_get_acl_hooks(r);
    const dav_hooks_redirect *redirect_hooks = dav_get_redirect_hooks(r);
    const dav_principal *principal = dav_principal_make_from_request(r);
    const char *status_forbidden;
    apr_text_header hdr = { 0 };

    /* check for DAV:read */
    if(acl_hooks != NULL)
        /* TODO: try to cache DAV:read checks */
        is_allow = (*acl_hooks->is_allow)(principal, 
                                          (dav_resource *) wres->resource,
                                          DAV_PERMISSION_READ);


    /*
    ** Note: ctx->doc can only be NULL for DAV_PROPFIND_IS_ALLPROP. Since
    ** dav_get_allprops() does not need to do namespace translation,
    ** we're okay.
    **
    ** Note: we cast to lose the "const". The propdb won't try to change
    ** the resource, however, since we are opening readonly.
    */
    err = dav_open_propdb(ctx->r, ctx->w.lockdb, wres->resource, 1,
                          ctx->doc ? ctx->doc->namespaces : NULL, &propdb);
    if (err != NULL) {
        /* ### do something with err! */

        if (ctx->propfind_type == DAV_PROPFIND_IS_PROP) {
            dav_get_props_result badprops = { 0 };

            /* some props were expected on this collection/resource */
            dav_cache_badprops(ctx);
            badprops.propstats = ctx->propstat_404;
            dav_stream_response(wres, 0, &badprops, ctx->scratchpool);
        }
        else {
            /* no props on this collection/resource */
            dav_stream_response(wres, HTTP_OK, NULL, ctx->scratchpool);
        }

        apr_pool_clear(ctx->scratchpool);
        return NULL;
    }
    /* ### what to do about closing the propdb on server failure? */

    /* If the principal does not have DAV:read on the resource,
     * send 403 for all the requested props */
    if(!is_allow) {
        if(ctx->propfind_type == DAV_PROPFIND_IS_PROP) {
            /* get the "prop" element */
            prop_elem = dav_find_child(ctx->doc->root, "prop");

            /* begin propstat */
            apr_text_append(r->pool, &hdr, "<D:propstat>" DEBUG_CR);

            /* convert prop xml elem to text */
            apr_xml_to_text(r->pool, prop_elem, APR_XML_X2T_FULL_NS_LANG, 
                            ctx->doc->namespaces, NULL, 
                            (const char **) &prop_text, NULL);

            /* append "prop" text */
            apr_text_append(r->pool, &hdr, (const char *)prop_text);

            /* append status */
            status_forbidden = apr_psprintf(r->pool, 
                                           "<D:status>HTTP/1.1 %s </D:status>" DEBUG_CR, 
                                            ap_get_status_line(dav_get_permission_denied_status(r)));
            apr_text_append(r->pool, &hdr, status_forbidden);

            /* end propstat */
            apr_text_append(r->pool, &hdr, "</D:propstat>" DEBUG_CR);

            propstats.propstats = hdr.first;
            propstats.xmlns = NULL;
        }
        else {
            propstats = dav_get_allprops(propdb, DAV_PROP_INSERT_NAME);

            /* get the last text element */
            apr_text *last;
            for(last = propstats.propstats; last->next; last = last->next);
            
            /* over-write the status */
            last->text = 
                (const char *)apr_psprintf(r->pool,
                                           "</D:prop>" DEBUG_CR
                                           "<D:status>HTTP/1.1 %s </D:status>" DEBUG_CR 
                                           "</D:propstat>" DEBUG_CR,
                                           ap_get_status_line(dav_get_permission_denied_status(r)));
        }
    }
    else if(redirect_hooks && 
            wres->resource->type == DAV_RESOURCE_TYPE_REDIRECTREF &&
            !ctx->apply_to_redirectref) {
        dav_resource *resource = (dav_resource *)wres->resource;
        const char *reftarget = redirect_hooks->get_reftarget(resource);
        dav_redirectref_lifetime t = redirect_hooks->get_lifetime(resource);
        int status = HTTP_MOVED_TEMPORARILY;

        if (t != DAV_REDIRECTREF_TEMPORARY) {
            status = HTTP_MOVED_PERMANENTLY;
        }
       
        const char *stat = apr_psprintf(r->pool, 
                                          "<D:status>HTTP/1.1 %s</D:status>"
                                          DEBUG_CR, ap_get_status_line(status));

        const char *location = apr_psprintf(r->pool,
                                            "<D:location>" DEBUG_CR 
                                            "  <D:href>%s</D:href>" DEBUG_CR 
                                            "</D:location>" DEBUG_CR,
                                            reftarget);

        /* add a 3xx status */
        apr_text_append(r->pool, &hdr, stat);

        /* append a DAV:location */
        apr_text_append(r->pool, &hdr, location);

        propstats.propstats = hdr.first;
        propstats.xmlns = NULL;
    }
    else {

        if (ctx->propfind_type == DAV_PROPFIND_IS_PROP) {
            prop_elem = dav_find_child(ctx->doc->root, "prop");
            propstats = dav_get_props(propdb, prop_elem);
        } else if (ctx->propfind_type == DAV_PROPFIND_IS_PROPNAME)
            propstats = dav_get_allprops(propdb, DAV_PROP_INSERT_NAME);
        else if (ctx->propfind_type == DAV_PROPFIND_IS_ALLPROP) {
            apr_text *iter;
            dav_get_props_result inc_propstats = { 0 };
            if (ctx->doc != NULL) {
                apr_xml_elem *inc_elem = dav_find_child(ctx->doc->root, "include");
                if (inc_elem)
                    inc_propstats = dav_get_props(propdb, inc_elem);
            }
            propstats = dav_get_allprops(propdb, DAV_PROP_INSERT_VALUE);
            propstats.xmlns = inc_propstats.xmlns;

            /* go to the last propstat */
            for (iter = propstats.propstats; iter->next; iter = iter->next);

            /* link inc_propstats to the end */
            iter->next = inc_propstats.propstats;
        }
    }
    dav_close_propdb(propdb);

    dav_stream_response(wres, 0, &propstats, ctx->scratchpool);

    /* at this point, ctx->scratchpool has been used to stream a
       single response.  this function fully controls the pool, and
       thus has the right to clear it for the next iteration of this
       callback. */
    apr_pool_clear(ctx->scratchpool);

    return NULL;
}

static int apply_to_redirectref(request_rec *r)
{
    const char *apply_to_redirectref = apr_table_get(r->headers_in,
                                                     "Apply-To-Redirect-Ref");

    return (apply_to_redirectref && apply_to_redirectref[0] == 'T');
}

/* handle the PROPFIND method */
static int dav_method_propfind(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    int depth;
    dav_error *err;
    int result;
    apr_xml_doc *doc;
    const apr_xml_elem *child;
    dav_walker_ctx ctx = { { 0 } };
    dav_response *multi_status;

    if (dav_get_resource_state(r, resource) == DAV_RESOURCE_NULL) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    if ((depth = dav_get_depth(r, DAV_INFINITY)) < 0) {
        /* dav_get_depth() supplies additional information for the
         * default message. */
        return HTTP_BAD_REQUEST;
    }

    if (depth == DAV_INFINITY && resource->collection) {
        dav_dir_conf *conf;
        conf = (dav_dir_conf *)ap_get_module_config(r->per_dir_config,
                                                    &dav_module);
        /* default is to DISALLOW these requests */
        if (conf->allow_depthinfinity != DAV_ENABLED_ON) {
            return dav_error_response(r, HTTP_FORBIDDEN,
                                      apr_psprintf(r->pool,
                                                   "PROPFIND requests with a "
                                                   "Depth of \"infinity\" are "
                                                   "not allowed for %s.",
                                                   ap_escape_html(r->pool,
                                                                  r->uri)));
        }
    }

    if (!(doc = (apr_xml_doc *)apr_table_get(r->notes, "parsed_xml_body"))) {
        if ((result = ap_xml_parse_input(r, &doc)) != OK)
            return result;
        apr_table_setn(r->notes, "parsed_xml_body", (char *)doc);
    }
    /* note: doc == NULL if no request body */

    if (doc && !dav_validate_root(doc, "propfind")) {
        /* This supplies additional information for the default message. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The \"propfind\" element was not found.");
        return HTTP_BAD_REQUEST;
    }

    /* ### validate that only one of these three elements is present */

    if (doc == NULL
        || (child = dav_find_child(doc->root, "allprop")) != NULL) {
        /* note: no request body implies allprop */
        ctx.propfind_type = DAV_PROPFIND_IS_ALLPROP;
    }
    else if ((child = dav_find_child(doc->root, "propname")) != NULL) {
        ctx.propfind_type = DAV_PROPFIND_IS_PROPNAME;
    }
    else if ((child = dav_find_child(doc->root, "prop")) != NULL) {
        ctx.propfind_type = DAV_PROPFIND_IS_PROP;
    }
    else {
        /* "propfind" element must have one of the above three children */

        /* This supplies additional information for the default message. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The \"propfind\" element does not contain one of "
                      "the required child elements (the specific command).");
        return HTTP_BAD_REQUEST;
    }

    ctx.w.walk_type = DAV_WALKTYPE_NORMAL;
    ctx.w.func = dav_propfind_walker;
    ctx.w.walk_ctx = &ctx;
    ctx.w.pool = r->pool;
    ctx.w.root = resource;

    ctx.apply_to_redirectref = apply_to_redirectref(r);
    ctx.doc = doc;
    ctx.r = r;
    ctx.bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    apr_pool_create(&ctx.scratchpool, r->pool);

    /* ### should open read-only */
    if ((err = dav_open_lockdb(r, 0, &ctx.w.lockdb)) != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             "The lock database could not be opened, "
                             "preventing access to the various lock "
                             "properties for the PROPFIND.",
                             err);
        return dav_handle_err(r, err, NULL);
    }
    if (ctx.w.lockdb != NULL) {
        /* if we have a lock database, then we can walk locknull resources */
        /* ctx.w.walk_type |= DAV_WALKTYPE_LOCKNULL; */
    }

    /* send <multistatus> tag, with all doc->namespaces attached.  */

    /* NOTE: we *cannot* leave out the doc's namespaces from the
       initial <multistatus> tag.  if a 404 was generated for an HREF,
       then we need to spit out the doc's namespaces for use by the
       404. Note that <response> elements will override these ns0,
       ns1, etc, but NOT within the <response> scope for the
       badprops. */
    dav_begin_multistatus(ctx.bb, r, HTTP_MULTI_STATUS,
                          doc ? doc->namespaces : NULL);

    /* Have the provider walk the resource. */
    err = (*resource->hooks->walk)(&ctx.w, depth, &multi_status);

    if (ctx.w.lockdb != NULL) {
        (*ctx.w.lockdb->hooks->close_lockdb)(ctx.w.lockdb);
    }

    if (err != NULL) {
        /* If an error occurred during the resource walk, there's
           basically nothing we can do but abort the connection and
           log an error.  This is one of the limitations of HTTP; it
           needs to "know" the entire status of the response before
           generating it, which is just impossible in these streamy
           response situations. */
        err = dav_push_error(r->pool, err->status, 0,
                             "Provider encountered an error while streaming"
                             " a multistatus PROPFIND response.", err);
        dav_log_err(r, err, APLOG_ERR);
        r->connection->aborted = 1;
        return DONE;
    }

    dav_finish_multistatus(r, ctx.bb);

    /* the response has been sent. */
    return DONE;
}

static int dav_is_allow_method_propfind(dav_request *dav_r, 
                                        const dav_hooks_acl *acl_hook, 
                                        const dav_principal *principal)
{
    int retVal = TRUE;
    dav_resource *resource = dav_r->resource;

    if(resource->exists && acl_hook != NULL)
        retVal = (*acl_hook->is_allow)(principal, resource, DAV_PERMISSION_READ);
    
    return retVal;
}

static apr_text * dav_failed_proppatch(apr_pool_t *p,
                                      apr_array_header_t *prop_ctx)
{
    apr_text_header hdr = { 0 };
    int i = prop_ctx->nelts;
    dav_prop_ctx *ctx = (dav_prop_ctx *)prop_ctx->elts;
    dav_error *err424_set = NULL;
    dav_error *err424_delete = NULL;
    const char *s;

    /* ### might be nice to sort by status code and description */

    for ( ; i-- > 0; ++ctx ) {
        apr_text_append(p, &hdr,
                        "<D:propstat>" DEBUG_CR
                        "<D:prop>");
        apr_text_append(p, &hdr, apr_xml_empty_elem(p, ctx->prop));
        apr_text_append(p, &hdr, "</D:prop>" DEBUG_CR);

        if (ctx->err == NULL) {
            /* nothing was assigned here yet, so make it a 424 */

            if (ctx->operation == DAV_PROP_OP_SET) {
                if (err424_set == NULL)
                    err424_set = dav_new_error(p, HTTP_FAILED_DEPENDENCY, 0,
                                               "Attempted DAV:set operation "
                                               "could not be completed due "
                                               "to other errors.");
                ctx->err = err424_set;
            }
            else if (ctx->operation == DAV_PROP_OP_DELETE) {
                if (err424_delete == NULL)
                    err424_delete = dav_new_error(p, HTTP_FAILED_DEPENDENCY, 0,
                                                  "Attempted DAV:remove "
                                                  "operation could not be "
                                                  "completed due to other "
                                                  "errors.");
                ctx->err = err424_delete;
            }
        }

        s = apr_psprintf(p,
                         "<D:status>"
                         "HTTP/1.1 %d (status)"
                         "</D:status>" DEBUG_CR,
                         ctx->err->status);
        apr_text_append(p, &hdr, s);

        if(ctx->err->tagname) {
            /* might also have to handle err->content & err->namespace.
             * currently only using for cannot-modify-protected-property,
             * so content/namespace support not required */
            s = apr_psprintf(p,
                             "<D:error><D:%s/></D:error>",
                             ctx->err->tagname);
            apr_text_append(p, &hdr, s);
        }

        /* ### we should use compute_desc if necessary... */
        if (ctx->err->desc != NULL) {
            apr_text_append(p, &hdr, "<D:responsedescription>" DEBUG_CR);
            apr_text_append(p, &hdr, ctx->err->desc);
            apr_text_append(p, &hdr, "</D:responsedescription>" DEBUG_CR);
        }

        apr_text_append(p, &hdr, "</D:propstat>" DEBUG_CR);
    }

    return hdr.first;
}

static apr_text * dav_success_proppatch(apr_pool_t *p, apr_array_header_t *prop_ctx)
{
    apr_text_header hdr = { 0 };
    int i = prop_ctx->nelts;
    dav_prop_ctx *ctx = (dav_prop_ctx *)prop_ctx->elts;

    /*
     * ### we probably need to revise the way we assemble the response...
     * ### this code assumes everything will return status==200.
     */

    apr_text_append(p, &hdr,
                    "<D:propstat>" DEBUG_CR
                    "<D:prop>" DEBUG_CR);

    for ( ; i-- > 0; ++ctx ) {
        apr_text_append(p, &hdr, apr_xml_empty_elem(p, ctx->prop));
    }

    apr_text_append(p, &hdr,
                   "</D:prop>" DEBUG_CR
                   "<D:status>HTTP/1.1 200 OK</D:status>" DEBUG_CR
                   "</D:propstat>" DEBUG_CR);

    return hdr.first;
}

static void dav_prop_log_errors(dav_prop_ctx *ctx)
{
    dav_log_err(ctx->r, ctx->err, APLOG_ERR);
}

/*
 * Call <func> for each context. This can stop when an error occurs, or
 * simply iterate through the whole list.
 *
 * Returns 1 if an error occurs (and the iteration is aborted). Returns 0
 * if all elements are processed.
 *
 * If <reverse> is true (non-zero), then the list is traversed in
 * reverse order.
 */
static int dav_process_ctx_list(void (*func)(dav_prop_ctx *ctx),
                                apr_array_header_t *ctx_list, int stop_on_error,
                                int reverse)
{
    int i = ctx_list->nelts;
    dav_prop_ctx *ctx = (dav_prop_ctx *)ctx_list->elts;

    if (reverse)
        ctx += i;

    while (i--) {
        if (reverse)
            --ctx;

        if (!ctx->no_process) {
            (*func)(ctx);
            if (stop_on_error && DAV_PROP_CTX_HAS_ERR(*ctx)) {
                return 1;
            }
        }

        if (!reverse)
            ++ctx;
    }

    return 0;
}

static int dav_get_props_ctx_list(request_rec *r,
                                  dav_propdb *propdb,
                                  apr_xml_elem *update_elems,
                                  apr_array_header_t **p_ctx_list)
{
    apr_array_header_t *ctx_list;
    dav_prop_ctx *ctx;
    apr_xml_elem *child;

    /* set up an array to hold property operation contexts */
    ctx_list = apr_array_make(r->pool, 10, sizeof(dav_prop_ctx));

    /* do a first pass to ensure that all "remove" properties exist */
    for (child = update_elems->first_child; child; child = child->next) {
        int is_remove;
        apr_xml_elem *prop_group;
        apr_xml_elem *one_prop;

        /* Ignore children that are not set/remove */
        if (child->ns != APR_XML_NS_DAV_ID
            || (!(is_remove = (strcmp(child->name, "remove") == 0))
                && strcmp(child->name, "set") != 0)) {
            continue;
        }

        /* make sure that a "prop" child exists for set/remove */
        if ((prop_group = dav_find_child(child, "prop")) == NULL) {
            /* This supplies additional information for the default message. */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "A \"prop\" element is missing inside "
                          "the propertyupdate command.");
            return HTTP_BAD_REQUEST;
        }

        for (one_prop = prop_group->first_child; one_prop;
             one_prop = one_prop->next) {

            ctx = (dav_prop_ctx *)apr_array_push(ctx_list);
            ctx->propdb = propdb;
            ctx->operation = is_remove ? DAV_PROP_OP_DELETE : DAV_PROP_OP_SET;
            ctx->prop = one_prop;

            ctx->r = r;         /* for later use by dav_prop_log_errors() */

        }
    }
    *p_ctx_list = ctx_list;
    return OK;
}

/* handle the PROPPATCH method */
static int dav_method_proppatch(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_error *err;
    dav_resource *resource = dav_r->resource;
    int result;
    apr_xml_doc *doc;
    dav_propdb *propdb;
    apr_array_header_t *ctx_list;
    int failure = 0;
    dav_response resp = { 0 };
    apr_text *propstat_text;
    dav_auto_version_info av_info;
    int resource_state;

    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    if (!(doc = (apr_xml_doc *)apr_table_get(r->notes, "parsed_xml_body"))) {
        if ((result = ap_xml_parse_input(r, &doc)) != OK)
            return result;
        apr_table_setn(r->notes, "parsed_xml_body", (char *)doc);
    }
    /* note: doc == NULL if no request body */

    if (doc == NULL || !dav_validate_root(doc, "propertyupdate")) {
        /* This supplies additional information for the default message. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The request body does not contain "
                      "a \"propertyupdate\" element.");
        return HTTP_BAD_REQUEST;
    }

    dav_bind bind = { 0 };
    bind.cur_resource = bind.new_resource = resource;
    resource_state = dav_get_resource_state(r, resource);
    err = dav_validate_request
      (r, 0, NULL, &bind, NULL, DAV_VALIDATE_BIND |
       DAV_VALIDATE_IGNORE_TARGET_LOCKS, resource_state, NULL, NULL, NULL);
    if (err) return dav_handle_err(r, err, NULL);

    /* make sure the resource can be modified (if versioning repository) */
    if ((err = dav_auto_checkout(r, resource,
                                 0 /* not parent_only */,
                                 &av_info)) != NULL) {
        /* ### add a higher-level description? */
        return dav_handle_err(r, err, NULL);
    }

    if ((err = dav_open_propdb(r, NULL, resource, 0, doc->namespaces,
                               &propdb)) != NULL) {
        /* undo any auto-checkout */
        dav_auto_checkin(r, resource, 1 /*undo*/, 0 /*unlock*/, &av_info);

        err = dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                             apr_psprintf(r->pool,
                                          "Could not open the property "
                                          "database for %s.",
                                          ap_escape_html(r->pool, r->uri)),
                             err);
        return dav_handle_err(r, err, NULL);
    }
    /* ### what to do about closing the propdb on server failure? */

    /* ### validate "live" properties */
    result = dav_get_props_ctx_list(r, propdb, doc->root, &ctx_list);
    if (result != OK) {
        dav_close_propdb(propdb);
        dav_auto_checkin(r, resource, 1, 0, &av_info);
        return result;
    }

    if (dav_process_ctx_list(dav_prop_validate, ctx_list, 1, 0)) {
        failure = 1;
    }
    /* execute all of the operations */
    if (!failure && dav_process_ctx_list(dav_prop_exec, ctx_list, 1, 0)) {
        failure = 1;
    }

    /* generate a failure/success response */
    if (failure) {
        const dav_hooks_transaction *xaction_hooks = dav_get_transaction_hooks(r);
        if (xaction_hooks)
            xaction_hooks->mode_set(dav_r->trans, DAV_TRANSACTION_ROLLBACK);
        else
            (void)dav_process_ctx_list(dav_prop_rollback, ctx_list, 0, 1);
        propstat_text = dav_failed_proppatch(r->pool, ctx_list);
    }
    else {
        (void)dav_process_ctx_list(dav_prop_commit, ctx_list, 0, 0);
        propstat_text = dav_success_proppatch(r->pool, ctx_list);
    }

    /* log any errors that occurred */
    (void)dav_process_ctx_list(dav_prop_log_errors, ctx_list, 0, 0);

    /* make sure this gets closed! */
    dav_close_propdb(propdb);

    /* complete any auto-versioning */
    dav_auto_checkin(r, resource, failure, 0 /*unlock*/, &av_info);

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    resp.href = resource->uri;

    /* ### should probably use something new to pass along this text... */
    resp.propresult.propstats = propstat_text;

    /* set up the HTTP headers for the response */
    if ((err = (*resource->hooks->set_headers)(r, resource)) != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             "Unable to set up HTTP headers.",
                             err);
        return dav_handle_err(r, err, NULL);
    }

    dav_send_multistatus(r, HTTP_MULTI_STATUS, &resp, doc->namespaces);

    /* the response has been sent. */
    return DONE;
}

static int dav_is_allow_method_proppatch(dav_request *dav_r, 
                                         const dav_hooks_acl *acl_hook, 
                                         const dav_principal *principal)
{
    int retVal = TRUE;
    dav_resource *resource = dav_r->resource;

    if(resource->exists && acl_hook != NULL) 
        retVal = (*acl_hook->is_allow)(principal, resource, 
                  DAV_PERMISSION_WRITE_PROPERTIES);

    return retVal;
}

static int process_mkcol_body(request_rec *r)
{
    /* This is snarfed from ap_setup_client_block(). We could get pretty
     * close to this behavior by passing REQUEST_NO_BODY, but we need to
     * return HTTP_UNSUPPORTED_MEDIA_TYPE (while ap_setup_client_block
     * returns HTTP_REQUEST_ENTITY_TOO_LARGE). */

    const char *tenc = apr_table_get(r->headers_in, "Transfer-Encoding");
    const char *lenp = apr_table_get(r->headers_in, "Content-Length");
    const char *ctype = apr_table_get(r->headers_in, "Content-Type");

    /* make sure to set the Apache request fields properly. */
    r->read_body = REQUEST_NO_BODY;
    r->read_chunked = 0;
    r->remaining = 0;

    if (ctype && !strcmp(ctype, "application/xml"))
        return OK;

    if (tenc) {
        if (strcasecmp(tenc, "chunked")) {
            /* Use this instead of Apache's default error string */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Unknown Transfer-Encoding %s", tenc);
            return HTTP_NOT_IMPLEMENTED;
        }

        r->read_chunked = 1;
    }
    else if (lenp) {
        const char *pos = lenp;

        while (apr_isdigit(*pos) || apr_isspace(*pos)) {
            ++pos;
        }

        if (*pos != '\0') {
            /* This supplies additional information for the default message. */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Invalid Content-Length %s", lenp);
            return HTTP_BAD_REQUEST;
        }

        r->remaining = apr_atoi64(lenp);
    }

    if (r->read_chunked || r->remaining > 0) {
        /* ### log something? */

        /* Apache will supply a default error for this. */
        return HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    /*
     * Get rid of the body. this will call ap_setup_client_block(), but
     * our copy above has already verified its work.
     */
    return ap_discard_request_body(r);
}

/* handle the MKCOL method */
static int dav_method_mkcol(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    int resource_state;
    dav_auto_version_info av_info;
    apr_xml_doc *doc = NULL;
    apr_text *propstat_text = NULL;
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    dav_error *err;
    dav_error *err2;
    int result, failure = 0;
    dav_dir_conf *conf;

    /* handle the request body */
    /* ### this may move lower once we start processing bodies */
    if ((result = process_mkcol_body(r)) != OK) {
        return result;
    }

    conf = (dav_dir_conf *)ap_get_module_config(r->per_dir_config,
                                                &dav_module);

    if (resource->exists) {
        /* oops. something was already there! */

        /* Apache will supply a default error for this. */
        /* ### we should provide a specific error message! */
        return HTTP_METHOD_NOT_ALLOWED;
    }

    resource_state = dav_get_resource_state(r, resource);

    dav_bind bind = { 0 };
    bind.cur_resource = bind.new_resource = resource;
    err = dav_validate_request
      (r, 0, NULL, &bind, NULL, DAV_VALIDATE_BIND |
       DAV_VALIDATE_IGNORE_TARGET_LOCKS, resource_state, NULL, NULL, NULL);
    if (err) return dav_handle_err(r, err, NULL);

    resource->collection = 1;

    /* if versioned resource, make sure parent is checked out */
    if ((err = dav_auto_checkout(r, resource, 0 /* parent_only */,
                                 &av_info)) != NULL) {
        /* ### add a higher-level description? */
        return dav_handle_err(r, err, NULL);
    }

    /* create the collection if auto versioning code didn't already create it */
    if (!resource->exists)
	 err = (*resource->hooks->create_collection)(resource);

    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
        return result;
    }
    /* parse the request body */
    if (doc) {
        dav_propdb *propdb;
        apr_array_header_t *ctx_list;
        int i;

        if (!dav_validate_root(doc, "mkcol")) {
            /* undo any auto-checkout */
            dav_auto_checkin(r, resource, 1 /*undo*/, 0 /*unlock*/, &av_info);

            /* This supplies additional information for the default message. */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "The request body does not contain "
                          "a \"mkcol\" element.");
            return HTTP_BAD_REQUEST;
        }

        if ((err = dav_open_propdb(r, NULL, resource, 0, doc->namespaces,
                                   &propdb)) != NULL) {
            /* undo any auto-checkout */
            dav_auto_checkin(r, resource, 1 /*undo*/, 0 /*unlock*/, &av_info);

            err = dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                                 apr_psprintf(r->pool,
                                              "Could not open the property "
                                              "database for %s.",
                                              ap_escape_html(r->pool, r->uri)),
                                 err);
            return dav_handle_err(r, err, NULL);
        }
        /* ### what to do about closing the propdb on server failure? */

        /* ### validate "live" properties */
        result = dav_get_props_ctx_list(r, propdb, doc->root, &ctx_list);
        if (result != OK) {
            dav_close_propdb(propdb);
            dav_auto_checkin(r, resource, 1, 0, &av_info);
            return result;
        }

        for (i = 0; i < ctx_list->nelts; i++) {
            dav_prop_ctx *ctx = (dav_prop_ctx*)ctx_list->elts + i;
            if (ctx->prop->ns == APR_XML_NS_DAV_ID &&
                !strcmp(ctx->prop->name, "resourcetype")) {
                int resourcetype = DAV_RESOURCE_TYPE_UNKNOWN;
                ctx->no_process = 1;
                if (dav_find_child(ctx->prop, "activity"))
                    resourcetype = DAV_RESOURCE_TYPE_ACTIVITY;
                else if (dav_find_child(ctx->prop, "principal"))
                    resourcetype = DAV_RESOURCE_TYPE_PRINCIPAL;
                else
                    ctx->no_process = 0;

                if (resourcetype != DAV_RESOURCE_TYPE_UNKNOWN)
                    err = (*resource->hooks->set_collection_type)(resource, resourcetype);
                if (err) return dav_handle_err(r, err, NULL);
                break;
            }
        }

        if (dav_process_ctx_list(dav_prop_validate, ctx_list, 1, 0)) {
            failure = 1;
        }
        /* execute all of the operations */
        if (!failure && dav_process_ctx_list(dav_prop_exec, ctx_list, 1, 0)) {
            failure = 1;
        }

        /* generate a failure/success response */
        if (failure) {
            const dav_hooks_transaction *xaction_hooks = dav_get_transaction_hooks(r);
            if (xaction_hooks)
                xaction_hooks->mode_set(dav_r->trans, DAV_TRANSACTION_ROLLBACK);
            else
                (void)dav_process_ctx_list(dav_prop_rollback, ctx_list, 0, 1);
            propstat_text = dav_failed_proppatch(r->pool, ctx_list);
        }
        else {
            (void)dav_process_ctx_list(dav_prop_commit, ctx_list, 0, 0);
            propstat_text = dav_success_proppatch(r->pool, ctx_list);
        }

        /* log any errors that occurred */
        (void)dav_process_ctx_list(dav_prop_log_errors, ctx_list, 0, 0);

        /* make sure this gets closed! */
        dav_close_propdb(propdb);
    }

    /* restore modifiability of parent back to what it was */
    err2 = dav_auto_checkin(r, resource, err != NULL /* undo if error */,
                            0 /*unlock*/, &av_info);

    /* check for errors now */
    if (err != NULL) {
        return dav_handle_err(r, err, NULL);
    }
    if (err2 != NULL) {
        /* just log a warning */
        err = dav_push_error(r->pool, err2->status, 0,
                             "The MKCOL was successful, but there "
                             "was a problem automatically checking in "
                             "the parent collection.",
                             err2);
        dav_log_err(r, err, APLOG_WARNING);
    }

    if (locks_hooks != NULL) {
        dav_lockdb *lockdb;

        if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb)) != NULL) {
            /* The directory creation was successful, but the locking failed. */
            err = dav_push_error(r->pool, err->status, 0,
                                 "The MKCOL was successful, but there "
                                 "was a problem opening the lock database "
                                 "which prevents inheriting locks from the "
                                 "parent resources.",
                                 err);
            return dav_handle_err(r, err, NULL);
        }

        /* notify lock system that we have created/replaced a resource */
        err = dav_notify_created(r, lockdb, resource, resource_state, 0);

        (*locks_hooks->close_lockdb)(lockdb);

        if (err != NULL) {
            /* The dir creation was successful, but the locking failed. */
            err = dav_push_error(r->pool, err->status, 0,
                                 "The MKCOL was successful, but there "
                                 "was a problem updating its lock "
                                 "information.",
                                 err);
            return dav_handle_err(r, err, NULL);
        }
    }

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    if (doc) {
        apr_text *t = NULL;
        apr_bucket_brigade *bb = apr_brigade_create
          (r->pool, r->connection->bucket_alloc);
        ap_filter_t *output = r->output_filters;

        if (failure)
            r->status = HTTP_FAILED_DEPENDENCY;
        else
            r->status = HTTP_CREATED;
        ap_set_content_type(r, DAV_XML_CONTENT_TYPE);

        /* Send the headers and actual response now... */
        ap_fputs(output, bb, DAV_XML_HEADER DEBUG_CR
                 "<D:mkcol-response xmlns:D=\"DAV:\"");

        if (doc->namespaces != NULL) {
            int i;
            for (i = doc->namespaces->nelts; i--; )
                ap_fprintf(output, bb, " xmlns:ns%d=\"%s\"", i,
                           APR_XML_GET_URI_ITEM(doc->namespaces, i));
        }
        ap_fputs(output, bb, ">" DEBUG_CR);

        for (t = propstat_text; t; t = t->next) {
            ap_fputs(output, bb, t->text);
        }
        ap_fputs(output, bb, "</D:mkcol-response>" DEBUG_CR);
        APR_BRIGADE_INSERT_TAIL
          (bb, apr_bucket_eos_create(r->connection->bucket_alloc));

        /* deliver whatever might be remaining in the brigade */
        ap_pass_brigade(output, bb);

        return DONE;
    } else {
        /* return an appropriate response (HTTP_CREATED) */
        return dav_created(r, NULL, "Collection", 0);
    }
}

static int dav_is_allow_method_mkcol(dav_request *dav_r, 
                                     const dav_hooks_acl *acl_hook, 
                                     const dav_principal *principal)
{
    dav_resource *resource = dav_r->resource;
    int retVal = TRUE;
    dav_error *err;

    if (acl_hook != NULL) {
	const dav_hooks_repository *repos_hooks = resource->hooks;
	dav_resource *parent_resource = NULL;
	
        err = (*repos_hooks->get_parent_resource)(resource, &parent_resource);
	
        if (err == NULL && parent_resource && parent_resource->exists ) {
            dav_r->parent_resource = parent_resource;
	    retVal = (*acl_hook->is_allow)(principal, parent_resource, 
                                           DAV_PERMISSION_BIND);

            /* percolate the need-privileges error tag */
            if(!retVal) resource->err = parent_resource->err; 
	}    
    }

    
    return retVal;
}

/* handle the COPY and MOVE methods */
static int dav_method_copymove(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    int is_move = (r->method_number == M_MOVE) ;
    dav_resource *resource = dav_r->resource;
    dav_resource *resnew;
    request_rec *rnew;
    dav_auto_version_info src_av_info = { 0 };
    dav_auto_version_info dst_av_info = { 0 };
    const char *body;
    const char *dest;
    dav_error *err;
    dav_error *err2 = NULL;
    dav_error *err3;
    dav_response *multi_response;
    int is_dir;
    int overwrite;
    int depth;
    int result;
    dav_lockdb *lockdb;
    int resnew_state;
    int resource_state;

    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    /* If not a file or collection resource, COPY/MOVE not allowed */
    /* ### allow COPY/MOVE of DeltaV resource types */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR &&
	 !(!is_move && resource->type == DAV_RESOURCE_TYPE_VERSION && !resource->collection)) {
        body = apr_psprintf(r->pool,
                            "Cannot COPY/MOVE resource %s.",
                            ap_escape_html(r->pool, r->uri));
        return dav_error_response(r, HTTP_METHOD_NOT_ALLOWED, body);
    }

    /* get the destination URI */
    dest = apr_table_get(r->headers_in, "Destination");
    if (dest == NULL) {
        /* Look in headers provided by Netscape's Roaming Profiles */
        const char *nscp_host = apr_table_get(r->headers_in, "Host");
        const char *nscp_path = apr_table_get(r->headers_in, "New-uri");

        if (nscp_host != NULL && nscp_path != NULL)
            dest = apr_psprintf(r->pool, "http://%s%s", nscp_host, nscp_path);
    }
    if (dest == NULL) {
        /* This supplies additional information for the default message. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The request is missing a Destination header.");
        return HTTP_BAD_REQUEST;
    }

    /* Resolve destination resource */
    err = dav_get_resource_from_uri(dest, r, 0, &rnew, &resnew);
    if (err != NULL)
        return dav_handle_err(r, err, NULL);

    if (dav_get_provider(rnew) == NULL) {
        return dav_error_response(r, HTTP_METHOD_NOT_ALLOWED,
                                  "DAV not enabled for Destination URI.");
    }

    /* are the two resources handled by the same repository? */
    if (resource->hooks != resnew->hooks) {
        /* ### this message exposes some backend config, but screw it... */
        return dav_error_response(r, HTTP_BAD_GATEWAY,
                                  "Destination URI is handled by a "
                                  "different repository than the source URI. "
                                  "MOVE or COPY between repositories is "
                                  "not possible.");
    }

    /* get and parse the overwrite header value */
    if ((overwrite = dav_get_overwrite(r)) < 0) {
        /* dav_get_overwrite() supplies additional information for the
         * default message. */
        return HTTP_BAD_REQUEST;
    }

    /* quick failure test: if dest exists and overwrite is false. */
    if (resnew->exists && !overwrite) {
        /* Supply some text for the error response body. */
        return dav_error_response(r, HTTP_PRECONDITION_FAILED,
                                  "Destination is not empty and "
                                  "Overwrite is not \"T\"");
    }

    /* if dest is a checked-in vcr or a version resource */
    if (resnew->exists && ( resnew->type == DAV_RESOURCE_TYPE_VERSION))
      return dav_error_response(r, HTTP_PRECONDITION_FAILED,
				"Destination is not writiable");

    /* are the source and destination the same? */
    if ((*resource->hooks->is_same_resource)(resource, resnew)) {
        /* Supply some text for the error response body. */
        return dav_error_response(r, HTTP_FORBIDDEN,
                                  "Source and Destination URIs are the same.");

    }

    is_dir = resource->collection;

    /* get and parse the Depth header value. "0" and "infinity" are legal. */
    if ((depth = dav_get_depth(r, DAV_INFINITY)) < 0) {
        /* dav_get_depth() supplies additional information for the
         * default message. */
        return HTTP_BAD_REQUEST;
    }
    if (depth == 1) {
        /* This supplies additional information for the default message. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Depth must be \"0\" or \"infinity\" for COPY or MOVE.");
        return HTTP_BAD_REQUEST;
    }
    if (is_move && is_dir && depth != DAV_INFINITY) {
        /* This supplies additional information for the default message. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Depth must be \"infinity\" when moving a collection.");
        return HTTP_BAD_REQUEST;
    }

    if ((err = dav_open_lockdb(r, 0, &lockdb)) != NULL) {
        /* ### add a higher-level description? */
        return dav_handle_err(r, err, NULL);
    }

    dav_lock *lrl_to_refresh=NULL, *lrl_to_delete=NULL, *lock_i=NULL;
    dav_bind bind = { 0 }, unbind = { 0 };
    bind.cur_resource = resnew;
    bind.new_resource = resource;
    if (is_move)
        unbind.cur_resource = resource;
    resource_state = dav_get_resource_state(r, resource);
    err = dav_validate_request
      (r, depth, lockdb, &bind, is_move? &unbind : NULL,
       DAV_VALIDATE_BIND | (is_move ? DAV_VALIDATE_UNBIND : DAV_VALIDATE_IGNORE_TARGET_LOCKS),
       resource_state, &multi_response, &lrl_to_refresh, &lrl_to_delete);
    if (err) return dav_handle_err(r, err, multi_response);
    
    /* ### for now, we don't need anything in the body */
    if ((result = ap_discard_request_body(r)) != OK) {
        return result;
    }

    /* remove any locks from the old resources */
    /*
     * ### this is Yet Another Traversal. if we do a rename(), then we
     * ### really don't have to do this in some cases since the inode
     * ### values will remain constant across the move. but we can't
     * ### know that fact from outside the provider :-(
     *
     * ### note that we now have a problem atomicity in the move/copy
     * ### since a failure after this would have removed locks (technically,
     * ### this is okay to do, but really...)
     */
    if (is_move && lockdb != NULL) {
        /* ### this is wrong! it blasts direct locks on parent resources */
        /* ### pass lockdb! */
        (void)dav_unlock(r, resource, NULL);
    }

    /* if this is a move, then the source parent collection will be modified */
    if (is_move) {
        if ((err = dav_auto_checkout(r, resource, 1 /* parent_only */,
                                     &src_av_info)) != NULL) {
            if (lockdb != NULL)
                (*lockdb->hooks->close_lockdb)(lockdb);

            /* ### add a higher-level description? */
            return dav_handle_err(r, err, NULL);
        }
    }

    /*
     * Remember the initial state of the destination, so the lock system
     * can be notified as to how it changed.
     */
    resnew_state = dav_get_resource_state(rnew, resnew);

    /* For a MOVE operation, do auto-versioning for parent collection
     * For a COPY operation, do auto-versioning for destination and its parent
     */
    if (!(is_move&&!resource->versioned) && 
        (err=dav_auto_checkout(r, resnew, is_move, &dst_av_info))) {
        /* could not make destination writable:
         * restore state of source and its parent
         */
        (void)dav_auto_checkin(r, NULL, 1 /* undo */,
			       0 /*unlock*/, &src_av_info);
        if (lockdb != NULL)
            (*lockdb->hooks->close_lockdb)(lockdb);
        
        /* ### add a higher-level description? */
        return dav_handle_err(r, err, NULL);
    }

    /* If source and destination parents are the same, then
     * use the same resource object, so status updates to one are reflected
     * in the other, when doing auto-versioning. Otherwise,
     * we may try to checkin the parent twice.
     */
    if (src_av_info.parent_resource != NULL
        && dst_av_info.parent_resource != NULL
        && (*src_av_info.parent_resource->hooks->is_same_resource)
            (src_av_info.parent_resource, dst_av_info.parent_resource)) {

        dst_av_info.parent_resource = src_av_info.parent_resource;
    }

    if (err == NULL) {
        if (is_move)
            err = (*resource->hooks->move_resource)(resource, resnew,
                                                    &multi_response);
        else
            err = (*resource->hooks->copy_resource)(resource, resnew, depth,
                                                    &multi_response);
    }

    /* perform any auto-versioning cleanup */
    if( !(is_move && !resource->versioned))
	err2 = dav_auto_checkin(r, is_move?NULL:resnew, err != NULL /* undo if error */,
				0 /*unlock*/, &dst_av_info);

    if (is_move) {
        err3 = dav_auto_checkin(r, NULL, err != NULL /* undo if error */,
                                0 /*unlock*/, &src_av_info);
    }
    else
        err3 = NULL;

    /* check for error from remove/copy/move operations */
    if (err != NULL) {
        if (lockdb != NULL)
            (*lockdb->hooks->close_lockdb)(lockdb);

        err = dav_push_error(r->pool, err->status, 0,
                             apr_psprintf(r->pool,
                                          "Could not MOVE/COPY %s.",
                                          ap_escape_html(r->pool, r->uri)),
                             err);
        return dav_handle_err(r, err, multi_response);
    }

    /* check for errors from auto-versioning */
    if (err2 != NULL) {
        /* just log a warning */
        err = dav_push_error(r->pool, err2->status, 0,
                             "The MOVE/COPY was successful, but there was a "
                             "problem automatically checking in the "
                             "source parent collection.",
                             err2);
        dav_log_err(r, err, APLOG_WARNING);
    }
    if (err3 != NULL) {
        /* just log a warning */
        err = dav_push_error(r->pool, err3->status, 0,
                             "The MOVE/COPY was successful, but there was a "
                             "problem automatically checking in the "
                             "destination or its parent collection.",
                             err3);
        dav_log_err(r, err, APLOG_WARNING);
    }

    /* propagate any indirect locks at the target */
    if (lockdb != NULL) {

        for (lock_i = lrl_to_delete; lock_i && !err; lock_i = lock_i->next)
            err = (*lockdb->hooks->remove_lock)(lockdb, NULL, lock_i->locktoken);
        for (lock_i = lrl_to_refresh; lock_i && !err; lock_i = lock_i->next)
            err = (*lockdb->hooks->remove_lock)(lockdb, NULL, lock_i->locktoken);

        if (!err && lrl_to_refresh)
            err = (*lockdb->hooks->refresh_locks)(lockdb, resource, lrl_to_refresh, 1);

        if (err) return dav_handle_err(r, err, NULL);

        /* notify lock system that we have created/replaced a resource */
        err = dav_notify_created(r, lockdb, resnew, resnew_state, depth);

        (*lockdb->hooks->close_lockdb)(lockdb);

        if (err != NULL) {
            /* The move/copy was successful, but the locking failed. */
            err = dav_push_error(r->pool, err->status, 0,
                                 "The MOVE/COPY was successful, but there "
                                 "was a problem updating the lock "
                                 "information.",
                                 err);
            return dav_handle_err(r, err, NULL);
        }
    }

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    /* return an appropriate response (HTTP_CREATED or HTTP_NO_CONTENT) */
    return dav_created(r, rnew->uri, "Destination",
                       resnew_state == DAV_RESOURCE_EXISTS);
}

static int dav_is_allow_method_copy(dav_request *dav_r, 
                                    const dav_hooks_acl *acl_hook, 
                                    const dav_principal *principal)
{
    dav_resource *resource = dav_r->resource;
    request_rec *r = dav_r->request, *rnew;
    int retVal = TRUE;
    dav_resource *resnew;
    const char *dest;
    dav_error *err = NULL;

    if (!resource->exists)
        return retVal;

    /* If not a file or collection resource, COPY/MOVE not allowed */
    /* ### allow COPY/MOVE of DeltaV resource types */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR)
        return retVal;

    /* get the destination URI */
    dest = apr_table_get(r->headers_in, "Destination");
    if (dest == NULL) {
        /* Look in headers provided by Netscape's Roaming Profiles */
        const char *nscp_host = apr_table_get(r->headers_in, "Host");
        const char *nscp_path = apr_table_get(r->headers_in, "New-uri");

        if (nscp_host != NULL && nscp_path != NULL)
            dest = apr_psprintf(r->pool, "http://%s%s", nscp_host, nscp_path);
    }
    if (dest == NULL)
        return retVal;

    /* Resolve destination resource */
    err = dav_get_resource_from_uri(dest, r, 0, &rnew, &resnew);
    if (err != NULL)
        return retVal;

    /* are the source and destination the same? */
    if ((*resource->hooks->is_same_resource)(resource, resnew)) {
        /* Supply some text for the error response body. */
        return retVal;

    }

    if (acl_hook != NULL) {
	const dav_hooks_repository *repos_hooks = resource->hooks;
	dav_resource *parent_new_resource = NULL;
	
	if (err == NULL)
    	    err = (*repos_hooks->get_parent_resource)(resnew, &parent_new_resource);
	
        if (err == NULL && parent_new_resource && parent_new_resource->exists ) {
	    int is_acl_allow = 0;
	    is_acl_allow = (*acl_hook->is_allow)(principal, resource, 
                                                 DAV_PERMISSION_READ);
	    
	    if (resnew->exists) {

                int overwrite = dav_get_overwrite(r);

                if(overwrite > 0) {
                    if ((resnew->collection == 0) ^ (resource->collection == 0)) {
                        /* If resourcetype is being changed, check for *bind priv */
                        is_acl_allow = 
                          is_acl_allow
                          && ((*acl_hook->is_allow)(principal, parent_new_resource, 
                                                    DAV_PERMISSION_UNBIND))
                          && ((*acl_hook->is_allow)(principal, parent_new_resource, 
                                                    DAV_PERMISSION_BIND));
                        if (!is_acl_allow) err = parent_new_resource->err;
                    } else {
                        is_acl_allow = 
                          is_acl_allow 
                          && (*acl_hook->is_allow)(principal, resnew, 
                                                 DAV_PERMISSION_WRITE_CONTENT);
                        is_acl_allow = 
                          is_acl_allow 
                          && (*acl_hook->is_allow)(principal, resnew, 
                                                 DAV_PERMISSION_WRITE_PROPERTIES);
                        if(!is_acl_allow) err = resnew->err;
                    }
                }
                else {
                    /* if Overwrite is F we only need to check read on destination */
                    is_acl_allow =
                      is_acl_allow
                      && ((*acl_hook->is_allow)(principal, parent_new_resource,
                                                DAV_PERMISSION_READ));

                    if (!is_acl_allow) err = parent_new_resource->err;
                }
	    }
	    else {
	        is_acl_allow = 
                    is_acl_allow 
                    && (*acl_hook->is_allow)(principal, parent_new_resource, 
                                             DAV_PERMISSION_BIND);
                if(!is_acl_allow) err = parent_new_resource->err;
            }
	
	    if (!is_acl_allow && resource->err == NULL) {
                resource->err = err;
	    }

            retVal = is_acl_allow;
	}
    }
    
    if (resource->err) {
        const char *auth = apr_table_get(rnew->err_headers_out,
                                         "WWW-Authenticate");
        if (resource->err->status == HTTP_UNAUTHORIZED && auth != NULL) {
            /* propagate the WWW-Authorization header up from the
             * subreq so the client sees it. */
            apr_table_set(r->err_headers_out, "WWW-Authenticate",
                          apr_pstrdup(r->pool, auth));
        }
    }

    return retVal;
}

static int dav_is_allow_method_move(dav_request *dav_r, 
                                    const dav_hooks_acl *acl_hook, 
                                    const dav_principal *principal)
{
    dav_resource *resource = dav_r->resource, *resnew = NULL;
    request_rec *r = dav_r->request, *rnew = NULL;
    int retVal = TRUE;
    const char *dest;
    dav_error *err;

    if (!resource->exists)
        return retVal;

    /* If not a file or collection resource, COPY/MOVE not allowed */
    /* ### allow COPY/MOVE of DeltaV resource types */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR)
        return retVal;

    /* get the destination URI */
    dest = apr_table_get(r->headers_in, "Destination");
    if (dest == NULL) {
        /* Look in headers provided by Netscape's Roaming Profiles */
        const char *nscp_host = apr_table_get(r->headers_in, "Host");
        const char *nscp_path = apr_table_get(r->headers_in, "New-uri");

        if (nscp_host != NULL && nscp_path != NULL)
            dest = apr_psprintf(r->pool, "http://%s%s", nscp_host, nscp_path);
    }
    if (dest == NULL)
        return retVal;

    /* Resolve destination resource */
    err = dav_get_resource_from_uri(dest, r, 0 , &rnew, &resnew);
    if (err != NULL)
        return retVal;

    /* are the source and destination the same? */
    if ((*resource->hooks->is_same_resource)(resource, resnew)) {
        /* Supply some text for the error response body. */
        return retVal;

    }

    if (acl_hook != NULL) {
	const dav_hooks_repository *repos_hooks = resource->hooks;
	dav_resource *parent_resource = NULL;
	dav_resource *parent_new_resource = NULL;
	
        err = (*repos_hooks->get_parent_resource)(resource, &parent_resource);
	
	if (err == NULL)
    	    err = (*repos_hooks->get_parent_resource)(resnew, &parent_new_resource);
	
        if (err == NULL && parent_resource && parent_new_resource 
            && parent_resource->exists && parent_new_resource->exists) {
	    int is_acl_allow = 0;
	    is_acl_allow = (*acl_hook->is_allow)(principal, parent_resource, 
                                                 DAV_PERMISSION_UNBIND);

	    is_acl_allow = 
                is_acl_allow 
                && (*acl_hook->is_allow)(principal, parent_new_resource, 
                                         DAV_PERMISSION_BIND);
	    
	    if (resnew->exists)
	        is_acl_allow = 
                    is_acl_allow 
                    && (*acl_hook->is_allow)(principal, parent_new_resource, 
                                             DAV_PERMISSION_UNBIND);
	
	    if (!is_acl_allow) {
                if(parent_resource->err)
                    resource->err = parent_resource->err;
                else
                    resource->err = parent_new_resource->err;
	    }
            retVal = is_acl_allow;
	}    
    }

    if (resource->err) {
        const char *auth = apr_table_get(rnew->err_headers_out,
                                         "WWW-Authenticate");
        if (resource->err->status == HTTP_UNAUTHORIZED && auth != NULL) {
            /* propagate the WWW-Authorization header up from the
             * subreq so the client sees it. */
            apr_table_set(r->err_headers_out, "WWW-Authenticate",
                          apr_pstrdup(r->pool, auth));
        }
    }

    return retVal;
}

/* dav_method_lock:  Handler to implement the DAV LOCK method
 *    Returns appropriate HTTP_* response.
 */
static int dav_method_lock(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_error *err;
    dav_resource *resource = dav_r->resource;
    const dav_hooks_locks *locks_hooks;
    int result;
    int depth;
    int new_lock_request = 0;
    apr_xml_doc *doc;
    dav_lock *lock;
    dav_response *multi_response = NULL;
    dav_lockdb *lockdb;
    int resource_state;
    const dav_hooks_transaction *transaction_hooks 
      = DAV_GET_HOOKS_TRANSACTION(r);

    /* If no locks provider, decline the request */
    locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    if (locks_hooks == NULL)
        return DECLINED;

    if (!(doc = (apr_xml_doc *)apr_table_get(r->notes, "parsed_xml_body"))) {
        if ((result = ap_xml_parse_input(r, &doc)) != OK)
            return result;
        apr_table_setn(r->notes, "parsed_xml_body", (char *)doc);
    }

    depth = dav_get_depth(r, DAV_INFINITY);
    if (depth != 0 && depth != DAV_INFINITY) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Depth must be 0 or \"infinity\" for LOCK.");
        return HTTP_BAD_REQUEST;
    }

    resource_state = dav_get_resource_state(r, resource);

    /*
     * Open writable. Unless an error occurs, we'll be
     * writing into the database.
     */
    if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb)) != NULL) {
        /* ### add a higher-level description? */
        return dav_handle_err(r, err, NULL);
    }

    if (doc != NULL) {
        if ((err = dav_lock_parse_lockinfo(r, resource, lockdb, doc,
                                               &lock)) != NULL) {
            /* ### add a higher-level description to err? */
            goto error;
        }
        new_lock_request = 1;

        lock->auth_user = apr_pstrdup(r->pool, r->user);
    }

    dav_bind bind = { 0 };
    bind.cur_resource = bind.new_resource = resource;
    int flags = 0;
    if (new_lock_request) {
        flags = DAV_VALIDATE_NEW_LOCK | lock->scope;
        if (resource_state == DAV_RESOURCE_NULL)
            flags = flags | DAV_VALIDATE_PARENT;
    }
    err = dav_validate_request
      (r, depth, lockdb, &bind, NULL, flags, resource_state, &multi_response, NULL, NULL);
    if (err) goto error;

    if (new_lock_request == 0) {
        dav_locktoken_list *ltl;

        /*
         * Refresh request
         * ### Assumption:  We can renew multiple locks on the same resource
         * ### at once. First harvest all the positive lock-tokens given in
         * ### the If header. Then modify the lock entries for this resource
         * ### with the new Timeout val.
         */

        if ((err = dav_get_locktoken_list(r, &ltl)) != NULL) {
            err = dav_push_error(r->pool, err->status, 0,
                                 apr_psprintf(r->pool,
                                              "The lock refresh for %s failed "
                                              "because no lock tokens were "
                                              "specified in an \"If:\" "
                                              "header.",
                                              ap_escape_html(r->pool, r->uri)),
                                 err);
            goto error;
        }

        if (ltl && ltl->next) {
            err = dav_new_error(r->pool, HTTP_BAD_REQUEST, 0,
                                "Only one lock can be submitted for refreshing a lock");
            goto error;
        }

        lock = apr_pcalloc(r->pool, sizeof(*lock));
        lock->locktoken = ltl->locktoken;
        if ((err = (*locks_hooks->refresh_locks)(lockdb, resource, lock,
                                                 dav_get_timeout(r))) != NULL) {
            /* ### add a higher-level description to err? */
            goto error;
        }
    } else {
        /* New lock request */
        char *locktoken_txt;
        dav_dir_conf *conf;

        conf = (dav_dir_conf *)ap_get_module_config(r->per_dir_config,
                                                    &dav_module);

        /* apply lower bound (if any) from DAVMinTimeout directive */
        if (lock->timeout != DAV_TIMEOUT_INFINITE
            && lock->timeout < time(NULL) + conf->locktimeout)
            lock->timeout = time(NULL) + conf->locktimeout;

        err = dav_add_lock(r, resource, lockdb, lock, &multi_response);
        if (err != NULL) {
            /* ### add a higher-level description to err? */
            goto error;
        }

        locktoken_txt = apr_pstrcat(r->pool, "<",
                                    (*locks_hooks->format_locktoken)(r->pool,
                                        lock->locktoken),
                                    ">", NULL);

        apr_table_set(r->headers_out, "Lock-Token", locktoken_txt);
    }

    (*locks_hooks->close_lockdb)(lockdb);

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    r->status = (resource_state == DAV_RESOURCE_NULL && resource->exists) ?
      HTTP_CREATED : HTTP_OK;
    ap_set_content_type(r, DAV_XML_CONTENT_TYPE);

    ap_rputs(DAV_XML_HEADER DEBUG_CR "<D:prop xmlns:D=\"DAV:\">" DEBUG_CR, r);
    if (lock == NULL)
        ap_rputs("<D:lockdiscovery/>" DEBUG_CR, r);
    else {
        ap_rprintf(r,
                   "<D:lockdiscovery>" DEBUG_CR
                   "%s" DEBUG_CR
                   "</D:lockdiscovery>" DEBUG_CR,
                   dav_lock_get_activelock(r, lock, NULL));
    }
    ap_rputs("</D:prop>", r);

    /* the response has been sent. */
    return DONE;

  error:
    (*locks_hooks->close_lockdb)(lockdb);
    transaction_hooks->mode_set(dav_r->trans, DAV_TRANSACTION_ROLLBACK);
    return dav_handle_err(r, err, multi_response);
}

static int dav_is_allow_method_lock(dav_request *dav_r, 
                                    const dav_hooks_acl *acl_hook, 
                                    const dav_principal *principal)
{
    int retVal = TRUE;
    dav_resource *resource = dav_r->resource;
    dav_error *err;

    if (acl_hook != NULL) 
    {
	int is_acl_allow = 0;
        
	if (resource->exists)
	    is_acl_allow = (*acl_hook->is_allow)(principal, resource, 
                                                 DAV_PERMISSION_WRITE);
	else {
	    const dav_hooks_repository *repos_hooks = resource->hooks;
	    dav_resource *parent_resource = NULL;
	
	    err = (*repos_hooks->get_parent_resource)(resource, &parent_resource);
	
	    if (err == NULL && parent_resource && parent_resource->exists)
		is_acl_allow = (*acl_hook->is_allow)(principal, parent_resource, 
                                                     DAV_PERMISSION_BIND);
	    
	    if (!is_acl_allow && resource->err == NULL) {
                resource->err = parent_resource->err;
	    }
	}
	retVal = is_acl_allow;
    }

    return retVal;
}

/* dav_method_unlock:  Handler to implement the DAV UNLOCK method
 *    Returns appropriate HTTP_* response.
 */
static int dav_method_unlock(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_error *err;
    dav_resource *resource = dav_r->resource;
    const dav_hooks_locks *locks_hooks;
    int result;
    int resource_state;
    dav_response *multi_response;

    /* If no locks provider, decline the request */
    locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    if (locks_hooks == NULL)
        return DECLINED;


    resource_state = dav_get_resource_state(r, resource);

    dav_bind bind = { 0 };
    dav_lock *lock_to_remove;
    bind.cur_resource = bind.new_resource = resource;
    err = dav_validate_request
      (r, 0, NULL, &bind, NULL, DAV_VALIDATE_UNLOCK, resource_state,
       &multi_response, NULL, &lock_to_remove);
    if (err) return dav_handle_err(r, err, multi_response);

    /* ### RFC 2518 s. 8.11: If this resource is locked by locktoken,
     *     _all_ resources locked by locktoken are released.  It does not say
     *     resource has to be the root of an infinte lock.  Thus, an UNLOCK
     *     on any part of an infinte lock will remove the lock on all resources.
     *
     *     For us, if r->filename represents an indirect lock (part of an infinity lock),
     *     we must actually perform an UNLOCK on the direct lock for this resource.
     */
    if ((result = dav_unlock(r, resource, lock_to_remove->locktoken)) != OK) {
        return result;
    }

    /* if a locknull resource is shorn of all its locks, delete it */
    if (resource_state == DAV_RESOURCE_LOCK_NULL &&
        dav_get_resource_state(r, resource) == DAV_RESOURCE_NULL)
        err = (*resource->hooks->remove_resource)(resource, NULL);

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    return HTTP_NO_CONTENT;
}

static int dav_is_allow_method_unlock(dav_request *dav_r, 
                                      const dav_hooks_acl *acl_hook, 
                                      const dav_principal *principal)
{
			   
    /* We won't check for permission here because the lock owners can unlock
       without the unlock privilege
      if(resource->exists && acl_hook != NULL) 
        retVal = (*acl_hook->is_allow)(principal, resource, DAV_PERMISSION_UNLOCK);
    */

    return TRUE;
}

static int dav_method_vsn_control(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    int resource_state;
    dav_auto_version_info av_info;
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_error *err;
    apr_xml_doc *doc;
    const char *target = NULL;
    int result;

    /* if no versioning provider, decline the request */
    if (vsn_hooks == NULL)
        return DECLINED;

    /* remember the pre-creation resource state */
    resource_state = dav_get_resource_state(r, resource);

    /* parse the request body (may be a version-control element) */
    if (!(doc = (apr_xml_doc *)apr_table_get(r->notes, "parsed_xml_body"))) {
        if ((result = ap_xml_parse_input(r, &doc)) != OK)
            return result;
        apr_table_setn(r->notes, "parsed_xml_body", (char *)doc);
    }
    /* note: doc == NULL if no request body */

    if (doc != NULL) {
        const apr_xml_elem *child;
        apr_size_t tsize;

        if (!dav_validate_root(doc, "version-control")) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "The request body does not contain "
                          "a \"version-control\" element.");
            return HTTP_BAD_REQUEST;
        }

        /* get the version URI */
        if ((child = dav_find_child(doc->root, "version")) == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "The \"version-control\" element does not contain "
                          "a \"version\" element.");
            return HTTP_BAD_REQUEST;
        }

        if ((child = dav_find_child(child, "href")) == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "The \"version\" element does not contain "
                          "an \"href\" element.");
            return HTTP_BAD_REQUEST;
        }

        /* get version URI */
        apr_xml_to_text(r->pool, child, APR_XML_X2T_INNER, doc->namespaces, NULL,
                        &target, &tsize);
        if (tsize == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "An \"href\" element does not contain a URI.");
            return HTTP_BAD_REQUEST;
        }
    }

    /* Check request preconditions */

    /* ### need a general mechanism for reporting precondition violations
     * ### (should be returning XML document for 403/409 responses)
     */

    /* if not versioning existing resource, must specify version to select */
    if (!resource->exists && target == NULL) {
        err = dav_new_error(r->pool, HTTP_CONFLICT, 0,
                            "<DAV:initial-version-required/>");
        return dav_handle_err(r, err, NULL);
    }
    else if (resource->exists) {
        /* cannot add resource to existing version history */
        if (target != NULL) {
            err = dav_new_error(r->pool, HTTP_CONFLICT, 0,
                                "<DAV:cannot-add-to-existing-history/>");
            return dav_handle_err(r, err, NULL);
        }

        /* resource must be unversioned and versionable, or version selector */
        if (resource->type != DAV_RESOURCE_TYPE_REGULAR
            || (!resource->versioned && !(vsn_hooks->versionable)(resource))) {
            err = dav_new_error(r->pool, HTTP_CONFLICT, 0,
                                "<DAV:must-be-versionable/>");
            return dav_handle_err(r, err, NULL);
        }

        /* the DeltaV spec says if resource is a version selector,
         * then VERSION-CONTROL is a no-op
         */
        if (resource->versioned) {
            /* set the Cache-Control header, per the spec */
            apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

            /* no body */
            ap_set_content_length(r, 0);

            return DONE;
        }
    }

    dav_bind bind = { 0 };
    bind.cur_resource = bind.new_resource = resource;
    err = dav_validate_request
      (r, 0, NULL, &bind, NULL, DAV_VALIDATE_BIND |
       DAV_VALIDATE_IGNORE_TARGET_LOCKS, resource_state, NULL, NULL, NULL);
    if (err) return dav_handle_err(r, err, NULL);

    /* if in versioned collection, make sure parent is checked out */
    if ((err = dav_auto_checkout(r, resource, 1 /* parent_only */,
                                 &av_info)) != NULL) {
        return dav_handle_err(r, err, NULL);
    }

    /* attempt to version-control the resource */
    if ((err = (*vsn_hooks->vsn_control)(resource, target)) != NULL) {
        dav_auto_checkin(r, resource, 1 /*undo*/, 0 /*unlock*/, &av_info);
        err = dav_push_error(r->pool, HTTP_CONFLICT, 0,
                             apr_psprintf(r->pool,
                                          "Could not VERSION-CONTROL resource %s.",
                                          ap_escape_html(r->pool, r->uri)),
                             err);
        return dav_handle_err(r, err, NULL);
    }

    /* revert writability of parent directory */
    err = dav_auto_checkin(r, resource, 0 /*undo*/, 0 /*unlock*/, &av_info);
    if (err != NULL) {
        /* just log a warning */
        err = dav_push_error(r->pool, err->status, 0,
                             "The VERSION-CONTROL was successful, but there "
                             "was a problem automatically checking in "
                             "the parent collection.",
                             err);
        dav_log_err(r, err, APLOG_WARNING);
    }

    /* if the resource is lockable, let lock system know of new resource */
    if (locks_hooks != NULL
        && (*locks_hooks->get_supportedlock)(resource) != NULL) {
        dav_lockdb *lockdb;

        if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb)) != NULL) {
            /* The resource creation was successful, but the locking failed. */
            err = dav_push_error(r->pool, err->status, 0,
                                 "The VERSION-CONTROL was successful, but there "
                                 "was a problem opening the lock database "
                                 "which prevents inheriting locks from the "
                                 "parent resources.",
                                 err);
            return dav_handle_err(r, err, NULL);
        }

        /* notify lock system that we have created/replaced a resource */
        err = dav_notify_created(r, lockdb, resource, resource_state, 0);

        (*locks_hooks->close_lockdb)(lockdb);

        if (err != NULL) {
            /* The dir creation was successful, but the locking failed. */
            err = dav_push_error(r->pool, err->status, 0,
                                 "The VERSION-CONTROL was successful, but there "
                                 "was a problem updating its lock "
                                 "information.",
                                 err);
            return dav_handle_err(r, err, NULL);
        }
    }

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    /* set the Cache-Control header, per the spec */
    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

    /* return an appropriate response (HTTP_CREATED) */
    #if 0
    return dav_created(r, resource->uri, "Version selector", 0 /*replaced*/);
    #endif

    return HTTP_OK;
}

/* handle the CHECKOUT method */
static int dav_method_checkout(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    dav_resource *working_resource;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_error *err;
    int result;
    apr_xml_doc *doc;
    int apply_to_vsn = 0;
    int is_unreserved = 0;
    int is_fork_ok = 0;
    int create_activity = 0;
    apr_array_header_t *activities = NULL;

    /* If no versioning provider, decline the request */
    if (vsn_hooks == NULL)
        return DECLINED;

    if (!(doc = (apr_xml_doc *)apr_table_get(r->notes, "parsed_xml_body"))) {
        if ((result = ap_xml_parse_input(r, &doc)) != OK)
            return result;
        apr_table_setn(r->notes, "parsed_xml_body", (char *)doc);
    }

    if (doc != NULL) {
        const apr_xml_elem *aset;

        if (!dav_validate_root(doc, "checkout")) {
            /* This supplies additional information for the default msg. */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "The request body, if present, must be a "
                          "DAV:checkout element.");
            return HTTP_BAD_REQUEST;
        }

        if (dav_find_child(doc->root, "apply-to-version") != NULL) {
            if (apr_table_get(r->headers_in, "label") != NULL) {
                /* ### we want generic 403/409 XML reporting here */
                /* ### DAV:must-not-have-label-and-apply-to-version */
                return dav_error_response(r, HTTP_CONFLICT,
                                          "DAV:apply-to-version cannot be "
                                          "used in conjunction with a "
                                          "Label header.");
            }
            apply_to_vsn = 1;
        }

        is_unreserved = dav_find_child(doc->root, "unreserved") != NULL;
        is_fork_ok = dav_find_child(doc->root, "fork-ok") != NULL;

        if ((aset = dav_find_child(doc->root, "activity-set")) != NULL) {
            if (dav_find_child(aset, "new") != NULL) {
                create_activity = 1;
            }
            else {
                const apr_xml_elem *child = aset->first_child;

                activities = apr_array_make(r->pool, 1, sizeof(const char *));

                for (; child != NULL; child = child->next) {
                    if (child->ns == APR_XML_NS_DAV_ID
                        && strcmp(child->name, "href") == 0) {
                        const char *href;

                        href = dav_xml_get_cdata(child, r->pool,
                                                 1 /* strip_white */);
                        *(const char **)apr_array_push(activities) = href;
                    }
                }

                if (activities->nelts == 0) {
                    /* no href's is a DTD violation:
                       <!ELEMENT activity-set (href+ | new)>
                    */

                    /* This supplies additional info for the default msg. */
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "Within the DAV:activity-set element, the "
                                  "DAV:new element must be used, or at least "
                                  "one DAV:href must be specified.");
                    return HTTP_BAD_REQUEST;
                }
            }
        }
    }

#if 0
    /* TODO: investigate apply_to_vsn here */
    if(resource == NULL) {
        /* Ask repository module to resolve the resource */
        err = dav_get_resource(r, 1 /*label_allowed*/, apply_to_vsn, &resource);
        if (err != NULL)
            return dav_handle_err(r, err, NULL);
    }
#endif

    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    /* Check the state of the resource: must be a file or collection,
     * must be versioned, and must not already be checked out.
     */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR
        && resource->type != DAV_RESOURCE_TYPE_VERSION) {
        return dav_error_response(r, HTTP_CONFLICT,
                                  "Cannot checkout this type of resource.");
    }

    if (!resource->versioned) {
        return dav_error_response(r, HTTP_CONFLICT,
                                  "Cannot checkout unversioned resource.");
    }

    if (resource->working) {
        return dav_error_response(r, HTTP_CONFLICT,
                                  "The resource is already checked out to the workspace.");
    }

    /* ### do lock checks, once behavior is defined */

    /* Do the checkout */
    if ((err = (*vsn_hooks->checkout)(resource, 0 /*auto_checkout*/,
                                      is_unreserved, is_fork_ok,
                                      create_activity, activities,
                                      &working_resource)) != NULL) {
        err = dav_push_error(r->pool, HTTP_CONFLICT, 0,
                             apr_psprintf(r->pool,
                                          "Could not CHECKOUT resource %s.",
                                          ap_escape_html(r->pool, r->uri)),
                             err);
        return dav_handle_err(r, err, NULL);
    }

    /* set the Cache-Control header, per the spec */
    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

    /* if no working resource created, return OK,
     * else return CREATED with working resource URL in Location header
     */
    if (working_resource == NULL) {
        /* no body */
        ap_set_content_length(r, 0);
        return DONE;
    }

    /* return dav_created(r, working_resource->uri, "Checked-out resource", 0);*/
    return HTTP_OK;
}

/* handle the UNCHECKOUT method */
static int dav_method_uncheckout(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_error *err;
    int result;

    /* If no versioning provider, decline the request */
    if (vsn_hooks == NULL)
        return DECLINED;

    if ((result = ap_discard_request_body(r)) != OK) {
        return result;
    }

    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    /* Check the state of the resource: must be a file or collection,
     * must be versioned, and must be checked out.
     */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR) {
        return dav_error_response(r, HTTP_CONFLICT,
                                  "Cannot uncheckout this type of resource.");
    }

    if (!resource->versioned) {
        return dav_error_response(r, HTTP_CONFLICT,
                                  "Cannot uncheckout unversioned resource.");
    }

    if (!resource->working) {
        return dav_error_response(r, HTTP_CONFLICT,
                                  "The resource is not checked out to the workspace.");
    }

    /* ### do lock checks, once behavior is defined */

    /* Do the uncheckout */
    if ((err = (*vsn_hooks->uncheckout)(resource)) != NULL) {
        err = dav_push_error(r->pool, HTTP_CONFLICT, 0,
                             apr_psprintf(r->pool,
                                          "Could not UNCHECKOUT resource %s.",
                                          ap_escape_html(r->pool, r->uri)),
                             err);
        return dav_handle_err(r, err, NULL);
    }

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    /* no body */
    ap_set_content_length(r, 0);

    return DONE;
}

/* handle the CHECKIN method */
static int dav_method_checkin(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    dav_resource *new_version;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_error *err;
    int result;
    apr_xml_doc *doc;
    int keep_checked_out = 0;

    /* If no versioning provider, decline the request */
    if (vsn_hooks == NULL)
        return DECLINED;

    if (!(doc = (apr_xml_doc *)apr_table_get(r->notes, "parsed_xml_body"))) {
        if ((result = ap_xml_parse_input(r, &doc)) != OK)
            return result;
        apr_table_setn(r->notes, "parsed_xml_body", (char *)doc);
    }

    if (doc != NULL) {
        if (!dav_validate_root(doc, "checkin")) {
            /* This supplies additional information for the default msg. */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "The request body, if present, must be a "
                          "DAV:checkin element.");
            return HTTP_BAD_REQUEST;
        }

        keep_checked_out = dav_find_child(doc->root, "keep-checked-out") != NULL;
    }

    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    /* Check the state of the resource: must be a file or collection,
     * must be versioned, and must be checked out.
     */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR) {
        return dav_error_response(r, HTTP_CONFLICT,
                                  "Cannot checkin this type of resource.");
    }

    if (!resource->versioned) {
        return dav_error_response(r, HTTP_CONFLICT,
                                  "Cannot checkin unversioned resource.");
    }

    if (!resource->working) {
        return dav_error_response(r, HTTP_CONFLICT,
                                  "The resource is not checked out.");
    }

    /* ### do lock checks, once behavior is defined */

    /* Do the checkin */
    if ((err = (*vsn_hooks->checkin)(resource, keep_checked_out, &new_version))
        != NULL) {
        err = dav_push_error(r->pool, HTTP_CONFLICT, 0,
                             apr_psprintf(r->pool,
                                          "Could not CHECKIN resource %s.",
                                          ap_escape_html(r->pool, r->uri)),
                             err);
        return dav_handle_err(r, err, NULL);
    }

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    return dav_created(r, new_version->uri, "Version", 0);
}

static int dav_method_update(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    /* ### permissions for UPDATE method have not defined in specification */
    dav_resource *resource = dav_r->resource;
    dav_resource *version = NULL;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    apr_xml_doc *doc;
    apr_xml_elem *child;
    int is_label = 0;
    int depth;
    int result;
    apr_size_t tsize;
    const char *target;
    dav_response *multi_response;
    dav_error *err;

    /* If no versioning provider, or UPDATE not supported,
     * decline the request */
    if (vsn_hooks == NULL || vsn_hooks->update == NULL)
        return DECLINED;

    if ((depth = dav_get_depth(r, 0)) < 0) {
        /* dav_get_depth() supplies additional information for the
         * default message. */
        return HTTP_BAD_REQUEST;
    }

    /* parse the request body */
    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
        return result;
    }

    if (doc == NULL || !dav_validate_root(doc, "update")) {
        /* This supplies additional information for the default message. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The request body does not contain "
                      "an \"update\" element.");
        return HTTP_BAD_REQUEST;
    }

    /* check for label-name or version element, but not both */
    if ((child = dav_find_child(doc->root, "label-name")) != NULL)
        is_label = 1;
    else if ((child = dav_find_child(doc->root, "version")) != NULL) {
        /* get the href element */
        if ((child = dav_find_child(child, "href")) == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "The version element does not contain "
                          "an \"href\" element.");
            return HTTP_BAD_REQUEST;
        }
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The \"update\" element does not contain "
                      "a \"label-name\" or \"version\" element.");
        return HTTP_BAD_REQUEST;
    }

    /* a depth greater than zero is only allowed for a label */
    if (!is_label && depth != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Depth must be zero for UPDATE with a version");
        return HTTP_BAD_REQUEST;
    }

    /* get the target value (a label or a version URI) */
    apr_xml_to_text(r->pool, child, APR_XML_X2T_INNER, doc->namespaces, NULL,
                    &target, &tsize);
    if (tsize == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "A \"label-name\" or \"href\" element does not contain "
                      "any content.");
        return HTTP_BAD_REQUEST;
    }

    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    /* ### need a general mechanism for reporting precondition violations
     * ### (should be returning XML document for 403/409 responses)
     */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR
        || !resource->versioned || resource->working) {
        return dav_error_response(r, HTTP_CONFLICT,
                                  "<DAV:must-be-checked-in-version-controlled-resource>");
    }

    /* if target is a version, resolve the version resource */
    /* ### dav_lookup_uri only allows absolute URIs; is that OK? */
    if (!is_label) {
        /* resolve version resource */
        err = dav_get_resource_from_uri(target, r, 0 , NULL, &version);
        if (err != NULL)
            return dav_handle_err(r, err, NULL);

        /* NULL out target, since we're using a version resource */
        target = NULL;
    }

    /* do the UPDATE operation */
    err = (*vsn_hooks->update)(resource, version, target, depth, &multi_response);

    if (err != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             apr_psprintf(r->pool,
                                          "Could not UPDATE %s.",
                                          ap_escape_html(r->pool, r->uri)),
                             err);
        return dav_handle_err(r, err, multi_response);
    }

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    /* set the Cache-Control header, per the spec */
    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

    /* no body */
    ap_set_content_length(r, 0);

    return DONE;
}

/* context maintained during LABEL treewalk */
typedef struct dav_label_walker_ctx
{
    /* input: */
    dav_walk_params w;

    /* label being manipulated */
    const char *label;

    /* label operation */
    int label_op;
#define DAV_LABEL_ADD           1
#define DAV_LABEL_SET           2
#define DAV_LABEL_REMOVE        3

    /* version provider hooks */
    const dav_hooks_vsn *vsn_hooks;

} dav_label_walker_ctx;

static dav_error * dav_label_walker(dav_walk_resource *wres, int calltype)
{
    dav_label_walker_ctx *ctx = wres->walk_ctx;
    dav_error *err = NULL;

    /* Check the state of the resource: must be a version or
     * non-checkedout version selector
     */
    /* ### need a general mechanism for reporting precondition violations
     * ### (should be returning XML document for 403/409 responses)
     */
    if (wres->resource->type != DAV_RESOURCE_TYPE_VERSION &&
        (wres->resource->type != DAV_RESOURCE_TYPE_REGULAR
         || !wres->resource->versioned)) {
        err = dav_new_error(ctx->w.pool, HTTP_CONFLICT, 0,
                            "<DAV:must-be-version-or-version-selector/>");
    }
    else if (wres->resource->working) {
        err = dav_new_error(ctx->w.pool, HTTP_CONFLICT, 0,
                            "<DAV:must-not-be-checked-out/>");
    }
    else {
        /* do the label operation */
        if (ctx->label_op == DAV_LABEL_REMOVE)
            err = (*ctx->vsn_hooks->remove_label)(wres->resource, ctx->label);
        else
            err = (*ctx->vsn_hooks->add_label)(wres->resource, ctx->label,
                                               ctx->label_op == DAV_LABEL_SET);
    }

    if (err != NULL) {
        /* ### need utility routine to add response with description? */
        dav_add_response(wres, err->status, NULL);
        wres->response->desc = err->desc;
    }

    return NULL;
}

static int dav_method_label(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    apr_xml_doc *doc;
    apr_xml_elem *child;
    int depth;
    int result;
    apr_size_t tsize;
    dav_error *err;
    dav_label_walker_ctx ctx = { { 0 } };
    dav_response *multi_status;

    /* If no versioning provider, or the provider doesn't support
     * labels, decline the request */
    if (vsn_hooks == NULL || vsn_hooks->add_label == NULL)
        return DECLINED;

    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    if ((depth = dav_get_depth(r, 0)) < 0) {
        /* dav_get_depth() supplies additional information for the
         * default message. */
        return HTTP_BAD_REQUEST;
    }

    /* parse the request body */
    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
        return result;
    }

    if (doc == NULL || !dav_validate_root(doc, "label")) {
        /* This supplies additional information for the default message. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The request body does not contain "
                      "a \"label\" element.");
        return HTTP_BAD_REQUEST;
    }

    /* check for add, set, or remove element */
    if ((child = dav_find_child(doc->root, "add")) != NULL) {
        ctx.label_op = DAV_LABEL_ADD;
    }
    else if ((child = dav_find_child(doc->root, "set")) != NULL) {
        ctx.label_op = DAV_LABEL_SET;
    }
    else if ((child = dav_find_child(doc->root, "remove")) != NULL) {
        ctx.label_op = DAV_LABEL_REMOVE;
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The \"label\" element does not contain "
                      "an \"add\", \"set\", or \"remove\" element.");
        return HTTP_BAD_REQUEST;
    }

    /* get the label string */
    if ((child = dav_find_child(child, "label-name")) == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The label command element does not contain "
                      "a \"label-name\" element.");
        return HTTP_BAD_REQUEST;
    }

    apr_xml_to_text(r->pool, child, APR_XML_X2T_INNER, doc->namespaces, NULL,
                    &ctx.label, &tsize);
    if (tsize == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "A \"label-name\" element does not contain "
                      "a label name.");
        return HTTP_BAD_REQUEST;
    }

    /* do the label operation walk */
    ctx.w.walk_type = DAV_WALKTYPE_NORMAL;
    ctx.w.func = dav_label_walker;
    ctx.w.walk_ctx = &ctx;
    ctx.w.pool = r->pool;
    ctx.w.root = resource;
    ctx.vsn_hooks = vsn_hooks;

    err = (*resource->hooks->walk)(&ctx.w, depth, &multi_status);

    if (err != NULL) {
        /* some sort of error occurred which terminated the walk */
        err = dav_push_error(r->pool, err->status, 0,
                             "The LABEL operation was terminated prematurely.",
                             err);
        return dav_handle_err(r, err, multi_status);
    }

    if (multi_status != NULL) {
        /* One or more resources had errors. If depth was zero, convert
         * response to simple error, else make sure there is an
         * overall error to pass to dav_handle_err()
         */
        if (depth == 0) {
            err = dav_new_error(r->pool, multi_status->status, 0, multi_status->desc);
            multi_status = NULL;
        }
        else {
            err = dav_new_error(r->pool, HTTP_MULTI_STATUS, 0,
                                "Errors occurred during the LABEL operation.");
        }

        return dav_handle_err(r, err, multi_status);
    }

    /* set the Cache-Control header, per the spec */
    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

    /* no body */
    ap_set_content_length(r, 0);

    return DONE;
}

static int dav_method_report(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    int result;
    apr_xml_doc *doc;
    dav_error *err;

    /* If no versioning provider, decline the request */
    if (vsn_hooks == NULL)
        return DECLINED;

    if ((result = ap_xml_parse_input(r, &doc)) != OK)
        return result;
    if (doc == NULL) {
        /* This supplies additional information for the default msg. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The request body must specify a report.");
        return HTTP_BAD_REQUEST;
    }

#if 0
    int label_allowed;
    /** TODO: investigate label_allowed */
    if(resource == NULL) {
        /* Ask repository module to resolve the resource.
         * First determine whether a Target-Selector header is allowed
         * for this report.
         */
        label_allowed = (*vsn_hooks->report_label_header_allowed)(doc);
        err = dav_get_resource(r, label_allowed, 0 /* use_checked_in */,
                               &resource);
        if (err != NULL)
        return dav_handle_err(r, err, NULL);
    }
#endif

    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    /* set up defaults for the report response */
    r->status = HTTP_OK;
    ap_set_content_type(r, DAV_XML_CONTENT_TYPE);

    /* run report hook */
    if ((err = (*vsn_hooks->deliver_report)(r, resource, doc,
                                            r->output_filters)) != NULL) {
        if (! r->sent_bodyct)
          /* No data has been sent to client yet;  throw normal error. */
          return dav_handle_err(r, err, NULL);

        /* If an error occurred during the report delivery, there's
           basically nothing we can do but abort the connection and
           log an error.  This is one of the limitations of HTTP; it
           needs to "know" the entire status of the response before
           generating it, which is just impossible in these streamy
           response situations. */
        err = dav_push_error(r->pool, err->status, 0,
                             "Provider encountered an error while streaming"
                             " a REPORT response.", err);
        dav_log_err(r, err, APLOG_ERR);
        r->connection->aborted = 1;
        return DONE;
    }

    return DONE;
}

static int dav_method_make_workspace(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_error *err;
    apr_xml_doc *doc;
    int result;

    /* if no versioning provider, or the provider does not support workspaces,
     * decline the request
     */
    if (vsn_hooks == NULL || vsn_hooks->make_workspace == NULL)
        return DECLINED;

    /* parse the request body (must be a mkworkspace element) */
    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
        return result;
    }

    if (doc == NULL
        || !dav_validate_root(doc, "mkworkspace")) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The request body does not contain "
                      "a \"mkworkspace\" element.");
        return HTTP_BAD_REQUEST;
    }

    /* Check request preconditions */

    /* ### need a general mechanism for reporting precondition violations
     * ### (should be returning XML document for 403/409 responses)
     */

    /* resource must not already exist */
    if (resource->exists) {
        err = dav_new_error(r->pool, HTTP_CONFLICT, 0,
                            "<DAV:resource-must-be-null/>");
        return dav_handle_err(r, err, NULL);
    }

    /* ### what about locking? */

    /* attempt to create the workspace */
    if ((err = (*vsn_hooks->make_workspace)(resource, doc)) != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             apr_psprintf(r->pool,
                                          "Could not create workspace %s.",
                                          ap_escape_html(r->pool, r->uri)),
                             err);
        return dav_handle_err(r, err, NULL);
    }

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    /* set the Cache-Control header, per the spec */
    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

    /* return an appropriate response (HTTP_CREATED) */
    return dav_created(r, resource->uri, "Workspace", 0 /*replaced*/);
}

static int dav_is_allow_method_make_workspace(dav_request *dav_r, 
                                              const dav_hooks_acl *acl_hook, 
                                              const dav_principal *principal)
{
    int retVal = TRUE;
    dav_resource *resource = dav_r->resource;
    dav_error *err = NULL;
    
    if (acl_hook != NULL) {
	const dav_hooks_repository *repos_hooks = resource->hooks;
	dav_resource *parent_resource = NULL;
	
        err = (*repos_hooks->get_parent_resource)(resource, &parent_resource);
	
        if (err == NULL && parent_resource && parent_resource->exists) {
	    retVal = (*acl_hook->is_allow)(principal, parent_resource, 
                                           DAV_PERMISSION_WRITE_CONTENT);

            /* percolate the need-privileges error tag */
            if(!retVal) resource->err = parent_resource->err; 
	}    
    }

    return retVal;
}

static int dav_method_make_activity(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_error *err;
    int result;

    /* if no versioning provider, or the provider does not support activities,
     * decline the request
     */
    if (vsn_hooks == NULL || vsn_hooks->make_activity == NULL)
        return DECLINED;

    /* MKACTIVITY does not have a defined request body. */
    if ((result = ap_discard_request_body(r)) != OK) {
        return result;
    }

    /* Check request preconditions */

    /* ### need a general mechanism for reporting precondition violations
     * ### (should be returning XML document for 403/409 responses)
     */

    /* resource must not already exist */
    if (resource->exists) {
        err = dav_new_error(r->pool, HTTP_CONFLICT, 0,
                            "<DAV:resource-must-be-null/>");
        return dav_handle_err(r, err, NULL);
    }

    /* the provider must say whether the resource can be created as
       an activity, i.e. whether the location is ok.  */
    if (vsn_hooks->can_be_activity != NULL
        && !(*vsn_hooks->can_be_activity)(resource)) {
      err = dav_new_error(r->pool, HTTP_FORBIDDEN, 0,
                          "<DAV:activity-location-ok/>");
      return dav_handle_err(r, err, NULL);
    }

    /* ### what about locking? */

    /* attempt to create the activity */
    if ((err = (*vsn_hooks->make_activity)(resource)) != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             apr_psprintf(r->pool,
                                          "Could not create activity %s.",
                                          ap_escape_html(r->pool, r->uri)),
                             err);
        return dav_handle_err(r, err, NULL);
    }

    /* set the Cache-Control header, per the spec */
    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

    /* return an appropriate response (HTTP_CREATED) */
    return dav_created(r, resource->uri, "Activity", 0 /*replaced*/);
}

static int dav_method_baseline_control(dav_request *dav_r)
{
    return HTTP_METHOD_NOT_ALLOWED;
}

static int dav_is_allow_method_baseline_control(dav_request *dav_r, 
                                                const dav_hooks_acl *acl_hook, 
                                                const dav_principal *principal)
{
    int retVal = TRUE;
    dav_resource *resource = dav_r->resource;

    if( resource->exists && acl_hook != NULL) { 
        retVal = (*acl_hook->is_allow)(principal, resource, 
                                       DAV_PERMISSION_WRITE_CONTENT);
        retVal = retVal && (*acl_hook->is_allow)(principal, resource, 
                                                 DAV_PERMISSION_WRITE_PROPERTIES);
    }
    
    return retVal;
}

static int dav_method_merge(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    dav_resource *source_resource;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_error *err;
    int result;
    apr_xml_doc *doc;
    apr_xml_elem *source_elem;
    apr_xml_elem *href_elem;
    apr_xml_elem *prop_elem;
    const char *source;
    int no_auto_merge;
    int no_checkout;

    /* If no versioning provider, decline the request */
    if (vsn_hooks == NULL)
        return DECLINED;

    if ((result = ap_xml_parse_input(r, &doc)) != OK)
        return result;

    if (doc == NULL || !dav_validate_root(doc, "merge")) {
        /* This supplies additional information for the default msg. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The request body must be present and must be a "
                      "DAV:merge element.");
        return HTTP_BAD_REQUEST;
    }

    if ((source_elem = dav_find_child(doc->root, "source")) == NULL) {
        /* This supplies additional information for the default msg. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The DAV:merge element must contain a DAV:source "
                      "element.");
        return HTTP_BAD_REQUEST;
    }
    if ((href_elem = dav_find_child(source_elem, "href")) == NULL) {
        /* This supplies additional information for the default msg. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The DAV:source element must contain a DAV:href "
                      "element.");
        return HTTP_BAD_REQUEST;
    }
    source = dav_xml_get_cdata(href_elem, r->pool, 1 /* strip_white */);
    
    err = dav_get_resource_from_uri(source, r, 0 , NULL, &source_resource);
    if (err != NULL)
        return dav_handle_err(r, err, NULL);

    no_auto_merge = dav_find_child(doc->root, "no-auto-merge") != NULL;
    no_checkout = dav_find_child(doc->root, "no-checkout") != NULL;

    prop_elem = dav_find_child(doc->root, "prop");

    /* ### check RFC. I believe the DAV:merge element may contain any
       ### element also allowed within DAV:checkout. need to extract them
       ### here, and pass them along.
       ### if so, then refactor the CHECKOUT method handling so we can reuse
       ### the code. maybe create a structure to hold CHECKOUT parameters
       ### which can be passed to the checkout() and merge() hooks. */

    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    /* ### check the source and target resources flags/types */

    /* ### do lock checks, once behavior is defined */

    /* set the Cache-Control header, per the spec */
    /* ### correct? */
    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

    /* Initialize these values for a standard MERGE response. If the MERGE
       is going to do something different (i.e. an error), then it must
       return a dav_error, and we'll reset these values properly. */
    r->status = HTTP_OK;
    ap_set_content_type(r, "text/xml");

    /* ### should we do any preliminary response generation? probably not,
       ### because we may have an error, thus demanding something else in
       ### the response body. */

    /* Do the merge, including any response generation. */
    if ((err = (*vsn_hooks->merge)(resource, source_resource,
                                   no_auto_merge, no_checkout,
                                   prop_elem,
                                   r->output_filters)) != NULL) {
        /* ### is err->status the right error here? */
        err = dav_push_error(r->pool, err->status, 0,
                             apr_psprintf(r->pool,
                                          "Could not MERGE resource \"%s\" "
                                          "into \"%s\".",
                                          ap_escape_html(r->pool, source),
                                          ap_escape_html(r->pool, r->uri)),
                             err);
        return dav_handle_err(r, err, NULL);
    }

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    /* the response was fully generated by the merge() hook. */
    /* ### urk. does this prevent logging? need to check... */
    return DONE;
}

static int dav_is_allow_method_merge(dav_request *dav_r, 
                                     const dav_hooks_acl *acl_hook, 
                                     const dav_principal *principal)
{
    int retVal = TRUE;
    dav_resource *resource = dav_r->resource;

    if(resource->exists && acl_hook != NULL) 
        retVal = (*acl_hook->is_allow)(principal, resource,
                                       DAV_PERMISSION_WRITE_CONTENT);

    return retVal;
}

DAV_DECLARE(dav_error *) dav_get_resource_from_uri(const char *uri, request_rec *r,
                                                   int flags,
                                                   request_rec **p_rec,
                                                   dav_resource **p_resource)
{
    dav_lookup_result lookup;
    dav_error *err = NULL;
    int must_be_absolute = flags & MUST_BE_ABSOLUTE;
    int allow_cross_domain = flags & ALLOW_CROSS_DOMAIN;

    lookup = dav_lookup_uri(uri, r, must_be_absolute, allow_cross_domain);
    if (lookup.rnew == NULL) {
        if (lookup.err.status == HTTP_BAD_GATEWAY)
            return dav_new_error(r->pool, HTTP_FORBIDDEN, 0,
                                 "Cross server operations are not "
                                 "allowed by this server.");
        return dav_new_error(r->pool, lookup.err.status, 0, lookup.err.desc);
    }
    if (lookup.rnew->status != HTTP_OK) {
        const char *auth = apr_table_get(lookup.rnew->err_headers_out,
                "WWW-Authenticate");
        if (lookup.rnew->status == HTTP_UNAUTHORIZED && auth != NULL) {
            /* propagate the WWW-Authorization header up from the
             * subreq so the client sees it. */
            apr_table_set(r->err_headers_out, "WWW-Authenticate",
                    apr_pstrdup(r->pool, auth));
        }
        return dav_new_error
          (r->pool, lookup.rnew->status, 0,
           apr_psprintf(r->pool, "URI %s had an error.", uri));
    }

    if (p_rec) 
        *p_rec = lookup.rnew;
    if (p_resource)
        err = dav_get_resource(lookup.rnew, 0 /* label_allowed */, 
                               0 /* use_checked_in */, p_resource);
    return err;
}

static int dav_is_allow_method_bind(dav_request *dav_r, 
                                    const dav_hooks_acl *acl_hook,
                                    const dav_principal *principal)
{
    request_rec *r = dav_r->request;
    int retVal = TRUE;
    dav_resource *resource = dav_r->resource, *binding;
    dav_error *err;
    const char *segment_str, *new_uri;
    apr_xml_doc *doc;
    apr_xml_elem *child;
    request_rec *binding_rec;

    if(resource->exists && acl_hook != NULL) 
        retVal = (*acl_hook->is_allow)(principal, resource,
                                       DAV_PERMISSION_BIND);

    if(!retVal) return retVal;

    if (!(doc = (apr_xml_doc *)apr_table_get(r->notes, "parsed_xml_body"))) {
        if (ap_xml_parse_input(r, &doc) != OK)
            return retVal;
        apr_table_setn(r->notes, "parsed_xml_body", (char *)doc);
    }

    if(!doc) return retVal;

    if ((child = dav_find_child(doc->root, "segment")) != NULL) {
        apr_size_t ssize; /* segment string size */
        /* Read Segment element */
        apr_xml_to_text(r->pool, child, APR_XML_X2T_INNER, doc->namespaces, NULL,
                        &segment_str, &ssize);
        if (ssize == 0) return retVal;
    } 
    else return retVal;
    
    /* get the destination URI */
    new_uri = apr_psprintf(r->pool, "%s/%s", r->unparsed_uri, segment_str);
    err = dav_get_resource_from_uri(new_uri, r, 0 , 
                                    &binding_rec, &binding);
    if (err) return retVal;

    /* check if destination bind exists */
    if(binding->exists && acl_hook)
        retVal = (*acl_hook->is_allow)(principal, resource, DAV_PERMISSION_UNBIND);

    return retVal;
}

static int dav_is_allow_method_rebind(dav_request *dav_r,
                                      const dav_hooks_acl *acl_hook,
                                      const dav_principal *principal)
{
    request_rec *r = dav_r->request;
    int retVal = TRUE;
    dav_resource *resource = dav_r->resource;
    dav_error *err;
    apr_xml_doc *doc;
    apr_xml_elem *child;
    const char *target_href, *segment_str, *new_uri;
    request_rec *old_binding_rec, *binding_rec;
    dav_resource *binding, *old_binding, *parent_resource;

    if(resource->exists && acl_hook != NULL) 
        retVal = (*acl_hook->is_allow)(principal, resource,
                                       DAV_PERMISSION_BIND);

    if(!retVal) return retVal;

    if (!(doc = (apr_xml_doc *)apr_table_get(r->notes, "parsed_xml_body"))) {
        if (ap_xml_parse_input(r, &doc) != OK)
            return retVal;
        apr_table_setn(r->notes, "parsed_xml_body", (char *)doc);
    }

    if(!doc) return retVal;

    if ((child = dav_find_child(doc->root, "segment")) != NULL) {
        apr_size_t ssize; /* segment string size */
        /* Read Segment element */
        apr_xml_to_text(r->pool, child, APR_XML_X2T_INNER, doc->namespaces, NULL,
                        &segment_str, &ssize);
        if (ssize == 0) return retVal;
    } 
    else return retVal;
    
    /* get the destination URI */
    new_uri = apr_psprintf(r->pool, "%s/%s", r->unparsed_uri, segment_str);
    err = dav_get_resource_from_uri(new_uri, r, 0, 
                                    &binding_rec, &binding);
    if (err) return retVal;

    /* check if destination bind exists */
    if(binding->exists && acl_hook)
        retVal = (*acl_hook->is_allow)(principal, resource, DAV_PERMISSION_UNBIND);
    if(!retVal) return retVal;

    if ((child = dav_find_child(doc->root, "href")) != NULL) {
        /* Read Href element */
        apr_size_t hsize;
        apr_xml_to_text(r->pool, child, APR_XML_X2T_INNER, doc->namespaces, NULL,
                        &target_href, &hsize);
        if (hsize == 0) return retVal;
    }
    else return retVal;

    err = dav_get_resource_from_uri(target_href, r, 0, 
                                    &old_binding_rec, &old_binding);
    if (err) return retVal;

    err = (*old_binding->hooks->get_parent_resource)(old_binding, &parent_resource); 
    if(err) return retVal;

    if(parent_resource->exists && acl_hook != NULL) 
        retVal = (*acl_hook->is_allow)(principal, parent_resource, 
                                       DAV_PERMISSION_UNBIND);
    
    return retVal;
}

static int dav_is_allow_method_unbind(dav_request *dav_r,
                                      const dav_hooks_acl *acl_hook,
                                      const dav_principal *principal)
{
    int retVal = TRUE;
    dav_resource *resource = dav_r->resource;

    if(resource->exists && acl_hook != NULL) 
        retVal = (*acl_hook->is_allow)(principal, resource,
                                       DAV_PERMISSION_UNBIND);
    
    return retVal;
}

static int dav_method_rebind(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    request_rec *binding_rec, *old_binding_rec;
    dav_resource *base_resource = dav_r->resource, *binding, *old_binding;
    const dav_hooks_binding *binds_hooks = DAV_GET_HOOKS_BINDING(r);
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    dav_lockdb *lockdb;
    dav_auto_version_info src_av_info, dst_av_info;
    apr_xml_doc *doc;
    apr_xml_elem *child;
    const char *segment_str, *new_uri, *target_href;
    int overwrite;
    dav_response *multi_response = NULL;
    dav_error *err, *err2, *err3;
    int resource_state;

    /* If no bindings provider, decline the request */
    if (binds_hooks == NULL)
        return DECLINED;

    if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb)) != NULL) {
        /* The resource creation was successful, but the locking failed. */
        err = dav_push_error(r->pool, err->status, 0,
                             "The BIND was successful, but there "
                             "was a problem opening the lock database "
                             "which prevents inheriting locks from the "
                             "parent resources.",
                             err);
        return dav_handle_err(r, err, NULL);
    }

    if (!base_resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    if (!base_resource->collection)
        return dav_error_response(r, HTTP_PRECONDITION_FAILED,
                                  "DAV:rebind-into-collection");

    if (!(doc = (apr_xml_doc *)apr_table_get(r->notes, "parsed_xml_body"))) {
        if (ap_xml_parse_input(r, &doc) != OK)
            return HTTP_BAD_REQUEST;
        apr_table_setn(r->notes, "parsed_xml_body", (char *)doc);
    }

    if (doc == NULL)
        return HTTP_BAD_REQUEST;

    if (dav_validate_root(doc, "rebind") != TRUE) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The root element \"rebind\" was not found.");
        return HTTP_BAD_REQUEST;
    }

    if ((child = dav_find_child(doc->root, "segment")) != NULL) {
        apr_size_t ssize; /* segment string size */
        /* Read Segment element */
        apr_xml_to_text(r->pool, child, APR_XML_X2T_INNER, doc->namespaces, NULL,
                        &segment_str, &ssize);
        if (ssize == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "\"segment\" does not contain a segment name");
            return HTTP_BAD_REQUEST;
        }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The \"rebind\" element does not contain one of "
                      "the required child element \"segment\"");
        return HTTP_BAD_REQUEST;
    }
    
    /* get the destination URI */
    new_uri = apr_psprintf(r->pool, "%s/%s", r->unparsed_uri, segment_str);
    err = dav_get_resource_from_uri(new_uri, r, 0, 
                                    &binding_rec, &binding);
    if (err) dav_handle_err(r, err, NULL);

    /* are the two resources handled by the same repository? */
    if (base_resource->hooks != binding->hooks) {
        /* ### this message exposes some backend config, but screw it... */
        return dav_error_response(r, HTTP_BAD_GATEWAY,
                                  "Destination URI is handled by a "
                                  "different repository than the source URI. "
                                  "BIND between repositories is not possible.");
    }

    /* get and parse the overwrite header value */
    if ((overwrite = dav_get_overwrite(r)) < 0) {
        /* dav_get_overwrite() supplies additional information for the
         * default message. */
        return HTTP_BAD_REQUEST;
    }

    /* quick failure test: if dest exists and overwrite is false. */
    if (binding->exists && !overwrite) {
        return dav_error_response(r, HTTP_PRECONDITION_FAILED,
                                  "DAV:can-overwrite");
    } else /* Reuse overwrite variable to indicate OK or CREATED */
        overwrite = binding->exists;

    if ((child = dav_find_child(doc->root, "href")) != NULL) {
        /* Read Href element */
        apr_size_t hsize;
        apr_xml_to_text(r->pool, child, APR_XML_X2T_INNER, doc->namespaces, NULL,
                        &target_href, &hsize);
        if (hsize == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "The \"href\" element does not contain a URI.");
            return HTTP_BAD_REQUEST;
        }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The \"rebind\" element does not contain "
                      "the required child element \"href\"");
        return HTTP_BAD_REQUEST;
    }

    err = dav_get_resource_from_uri(target_href, r, 0, 
                                    &old_binding_rec, &old_binding);
    if (err) return dav_handle_err(r, err, NULL);
    if (!old_binding->exists)
        return dav_error_response(old_binding_rec, HTTP_PRECONDITION_FAILED,
                                  "DAV:rebind-source-exists");

    /* are the two resources handled by the same repository? */
    if (old_binding->hooks != base_resource->hooks) {
        /* ### this message exposes some backend config, but screw it... */
        return dav_error_response(r, HTTP_BAD_GATEWAY,
                                  "Destination URI is handled by a "
                                  "different repository than the source URI. "
                                  "BIND between repositories is not possible.");
    }

    dav_lock *lrl_to_refresh=NULL, *lrl_to_delete=NULL, *lock_i=NULL;
    dav_bind bind = { 0 }, unbind = { 0 };
    bind.cur_resource = binding;
    bind.collection = base_resource;
    bind.bind_name = basename(bind.cur_resource->uri);
    bind.new_resource = old_binding;
    unbind.cur_resource = old_binding;
    resource_state = dav_get_resource_state(r, base_resource);
    err = dav_validate_request
      (r, DAV_INFINITY, lockdb, &bind, old_binding->exists ? &unbind : NULL,
       DAV_VALIDATE_BIND | (old_binding->exists ? DAV_VALIDATE_UNBIND : 0),
       resource_state, &multi_response, &lrl_to_refresh, &lrl_to_delete);

    if (err) return dav_handle_err(r, err, NULL);

    if (lockdb != NULL) {
        int ret;
        ret = dav_unlock(r, old_binding, NULL);
        if (ret != OK)
            return ret;
    }

    /* prepare the source collection for modification */
    if ((err = dav_auto_checkout(old_binding_rec, old_binding, 1,
                                 &src_av_info)) != NULL) {
        /* could not make source writable */
        return dav_handle_err(r, err, NULL);
    }

    /* prepare the destination collection for modification */
    if ((err = dav_auto_checkout(binding_rec, binding, 1 /* parent_only */,
                                 &dst_av_info)) != NULL) {
        /* undo the source collection checkout */
        dav_auto_checkin(old_binding_rec, NULL, 1, 0, &src_av_info);
        /* could not make destination writable */
        return dav_handle_err(r, err, NULL);
    }

    if (!err)
        err = (*binds_hooks->rebind_resource)(base_resource, segment_str, 
                                              old_binding, binding);

    /* restore parent collection states */
    err2 = dav_auto_checkin(old_binding_rec, NULL, 
                            err != NULL, 0, &src_av_info);

    err3 = dav_auto_checkin(binding_rec, NULL,
                            err != NULL /* undo if error */,
                            0 /* unlock */, &dst_av_info);

    /* check for error from remove/rebind operations */
    if (err != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             apr_psprintf(r->pool,
                                          "Could not BIND %s.",
                                          ap_escape_html(r->pool, r->uri)),
                             err);
        return dav_handle_err(r, err, multi_response);
    }

    /* check for errors from reverting writability */
    if (err2 != NULL || err3 != NULL) {
        /* just log a warning */
        err = dav_push_error(r->pool, err2->status, 0,
                             "The BIND was successful, but there was a "
                             "problem automatically checking in the "
                             "source parent collection.",
                             err2);
        dav_log_err(r, err, APLOG_WARNING);
    }

    /* if the resource is lockable, let lock system know of new resource */
    if (lockdb != NULL) {
        for (lock_i = lrl_to_delete; lock_i && !err; lock_i = lock_i->next)
            err = (*lockdb->hooks->remove_lock)(lockdb, NULL, lock_i->locktoken);
        for (lock_i = lrl_to_refresh; lock_i && !err; lock_i = lock_i->next)
            err = (*lockdb->hooks->remove_lock)(lockdb, NULL, lock_i->locktoken);

        if (!err && lrl_to_refresh)
            err = (*lockdb->hooks->refresh_locks)(lockdb, binding, lrl_to_refresh, 1);

        if (err) return dav_handle_err(r, err, NULL);

        /* notify lock system that we have created/replaced a resource */
        err = dav_notify_created(r, lockdb, binding, DAV_RESOURCE_NULL , 0);

        (*locks_hooks->close_lockdb)(lockdb);

        if (err != NULL) {
            /* The dir creation was successful, but the locking failed. */
            err = dav_push_error(r->pool, err->status, 0,
                                 "The BIND was successful, but there "
                                 "was a problem updating its lock "
                                 "information.",
                                 err);
            return dav_handle_err(r, err, NULL);
        }
    }
 
    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    if (overwrite) {
        r->status = HTTP_OK;
        return DONE;
    }
    return dav_created(r, binding_rec->uri, "Binding", 0);
}

static int dav_method_unbind(dav_request *dav_r)
{
    request_rec *r = dav_r->request, *resource_rec;
    dav_resource *base_resource = dav_r->resource, *resource;
    const dav_hooks_binding *bind_hooks = DAV_GET_HOOKS_BINDING(r);
    dav_lockdb *lockdb = NULL;
    dav_auto_version_info av_info = { 0 };
    apr_xml_doc *doc;
    apr_xml_elem *child;
    const char *segment = NULL, *segment_uri = NULL;
    dav_error *err, *err2;
    dav_response *multi_response = NULL;
    int result;
    int resource_state;

    /* If no bindings provider, decline the request */
    if (bind_hooks == NULL)
        return DECLINED;

    if ((err = dav_open_lockdb(r, 0, &lockdb)) != NULL) {
        /* ### add a higher-level description? */
        return dav_handle_err(r, err, NULL);
    }

    if (!base_resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    if (!base_resource->collection)
        return dav_error_response(r, HTTP_PRECONDITION_FAILED,
                                  "(DAV:unbind-from-collection)");

    if (!(doc = (apr_xml_doc *)apr_table_get(r->notes, "parsed_xml_body"))) {
        if (ap_xml_parse_input(r, &doc) != OK)
            return HTTP_BAD_REQUEST;
        apr_table_setn(r->notes, "parsed_xml_body", (char *)doc);
    }

    if (doc == NULL)
        return HTTP_BAD_REQUEST;

    if (dav_validate_root(doc, "unbind") != TRUE) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The root element \"unbind\" was not found.");
        return HTTP_BAD_REQUEST;
    }

    if ((child = dav_find_child(doc->root, "segment")) != NULL) {
        apr_size_t ssize; /* segment string size */
        /* Read Segment element */
        apr_xml_to_text(r->pool, child, APR_XML_X2T_INNER, doc->namespaces, NULL,
                        &segment, &ssize);
        if (ssize == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "\"segment\" does not contain a segment name");
            return HTTP_BAD_REQUEST;
        }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The \"unbind\" element does not contain one of "
                      "the required child element \"segment\"");
        return HTTP_BAD_REQUEST;
    }
    
    /* get the complete URI of the resource being unbound */
    segment_uri = apr_psprintf(r->pool, "%s/%s?no_rewrite", base_resource->uri,
                               segment);
    err = dav_get_resource_from_uri(segment_uri, r, 0, 
                                    &resource_rec, &resource);
    if (err) return dav_handle_err(r, err, NULL);

    if (!resource->exists)
        return dav_error_response(r, HTTP_PRECONDITION_FAILED,
                                  "(DAV:unbind-source-exists)");

    /* are the two resources handled by the same repository? */
    if (base_resource->hooks != resource->hooks) {
        /* ### this message exposes some backend config, but screw it... */
        return dav_error_response(r, HTTP_BAD_GATEWAY,
                                  "Destination URI is handled by a "
                                  "different repository than the source URI. "
                                  "BIND between repositories is not possible.");
    }

    dav_lock *lrl_to_delete = NULL, *li = NULL;
    dav_bind unbind = { 0 };
    unbind.collection = base_resource;
    unbind.bind_name = segment;
    unbind.cur_resource = resource;
    resource_state = dav_get_resource_state(r, resource);
    err = dav_validate_request
      (r, DAV_INFINITY, lockdb, NULL, &unbind, DAV_VALIDATE_UNBIND, resource_state,
       &multi_response, NULL, &lrl_to_delete);
    if (err) return dav_handle_err(r, err, multi_response);

    if ((result = dav_unlock(r, resource, NULL)) != OK) {
        return result;
    }

    /* prepare the parent collection for modification */
    if ((err = dav_auto_checkout(resource_rec, resource, 1 /* parent_only */,
                                 &av_info)) != NULL) {
        /* could not make destination writable */
        return dav_handle_err(r, err, NULL);
    }

    err = (*bind_hooks->unbind_resource)(resource, base_resource, segment);

    if (!err) 
        for (li = lrl_to_delete; li && !err; li = li->next)
            err = (*lockdb->hooks->remove_lock)(lockdb, NULL, li->locktoken);

    if (lockdb != NULL)
        (*lockdb->hooks->close_lockdb)(lockdb);
        
    /* restore parent collection states */
    err2 = dav_auto_checkin(r, NULL,
                            err != NULL /* undo if error */,
                            0 /* unlock */, &av_info);

    /* check for error from remove/bind operations */
    if (err != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             apr_psprintf(r->pool,
                                          "Could not BIND %s.",
                                          ap_escape_html(r->pool, r->uri)),
                             err);
        return dav_handle_err(r, err, multi_response);
    }

    /* check for errors from reverting writability */
    if (err2 != NULL) {
        /* just log a warning */
        err = dav_push_error(r->pool, err2->status, 0,
                             "The BIND was successful, but there was a "
                             "problem automatically checking in the "
                             "source parent collection.",
                             err2);
        dav_log_err(r, err, APLOG_WARNING);
    }

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    return HTTP_OK;
}

static int dav_method_bind(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *binding_parent = dav_r->resource, *resource, *binding;
    request_rec *binding_rec;
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    const dav_hooks_binding *binding_hooks = DAV_GET_HOOKS_BINDING(r);
    int overwrite;
    dav_auto_version_info av_info = { 0 };
    apr_xml_doc *doc;
    apr_xml_elem *child;
    const char *segment_str, *dest, *target_href;
    dav_response *multi_response = NULL;
    dav_error *err, *err2;
    int resource_state;

    /* If no bindings provider, decline the request */
    if (binding_hooks == NULL)
        return DECLINED;

    if (!binding_parent->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    if (!binding_parent->collection) {
        err = dav_new_error_tag
          (r->pool, HTTP_CONFLICT, 0, "Request-URI not a collection",
           NULL, "binding-into-collection", NULL, NULL);
        return dav_handle_err(r, err, NULL);
    }

    if (!(doc = (apr_xml_doc *)apr_table_get(r->notes, "parsed_xml_body"))) {
        if (ap_xml_parse_input(r, &doc) != OK)
            return HTTP_BAD_REQUEST;
        apr_table_setn(r->notes, "parsed_xml_body", (char *)doc);
    }

    if (doc == NULL)
        return HTTP_BAD_REQUEST;

    if (dav_validate_root(doc, "bind") != TRUE) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The root element \"bind\" was not found.");
        return HTTP_BAD_REQUEST;
    }

    if ((child = dav_find_child(doc->root, "segment")) != NULL) {
        apr_size_t ssize; /* segment string size */
        /* Read Segment element */
        apr_xml_to_text(r->pool, child, APR_XML_X2T_INNER, doc->namespaces, NULL,
                        &segment_str, &ssize);
        if (ssize == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "\"segment\" does not contain a segment name");
            return HTTP_BAD_REQUEST;
        }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The \"bind\" element does not contain one of "
                      "the required child element \"segment\"");
        return HTTP_BAD_REQUEST;
    }
    
    /* get the destination URI */
    dest = apr_psprintf(r->pool, "%s/%s", r->unparsed_uri, segment_str);
    err = dav_get_resource_from_uri(dest, r, 0, 
                                    &binding_rec, &binding);
    if (err) dav_handle_err(r, err, NULL);

    /* are the two resources handled by the same repository? */
    if (binding_parent->hooks != binding->hooks) {
        /* ### this message exposes some backend config, but screw it... */
        return dav_error_response(r, HTTP_BAD_GATEWAY,
                                  "Destination URI is handled by a "
                                  "different repository than the source URI. "
                                  "BIND between repositories is not possible.");
    }

    /* get and parse the overwrite header value */
    if ((overwrite = dav_get_overwrite(r)) < 0) {
        /* dav_get_overwrite() supplies additional information for the
         * default message. */
        return HTTP_BAD_REQUEST;
    }

    /* quick failure test: if dest exists and overwrite is false. */
    if (binding->exists && !overwrite) {
        return dav_error_response(r, HTTP_PRECONDITION_FAILED,
                                  "Destination is not empty and "
                                  "Overwrite is not \"T\"");
    } else /* Reusing overwrite variable to indicate OK or CREATED */
        overwrite = binding->exists; 

    if ((child = dav_find_child(doc->root, "href")) != NULL) {
        /* Read Href element */
        apr_size_t hsize;
        apr_xml_to_text(r->pool, child, APR_XML_X2T_INNER, doc->namespaces, NULL,
                        &target_href, &hsize);
        if (hsize == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "The \"href\" element does not contain a URI.");
            return HTTP_BAD_REQUEST;
        }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "The \"bind\" element does not contain "
                      "the required child element \"href\"");
        return HTTP_BAD_REQUEST;
    }

    if ((err = dav_get_resource_from_uri(target_href, r, 0, NULL, &resource)))
        return dav_handle_err(r, err, NULL);

    if (!resource->exists) {
        err = dav_new_error_tag(r->pool, HTTP_CONFLICT, 0, "href doesn't exist",
                                NULL, "bind-source-exists", NULL, NULL);
        return dav_handle_err(r, err, NULL);
    }

    /* are the two resources handled by the same repository? */
    if (resource->hooks != binding_parent->hooks) {
        /* ### this message exposes some backend config, but screw it... */
        return dav_error_response(r, HTTP_BAD_GATEWAY,
                                  "Destination URI is handled by a "
                                  "different repository than the source URI. "
                                  "BIND between repositories is not possible.");
    }

    dav_lock *lrl_to_refresh=NULL, *lrl_to_delete=NULL;
    dav_bind bind = { 0 };
    bind.cur_resource = binding;
    bind.new_resource = resource;
    resource_state = dav_get_resource_state(r, resource);
    err = dav_validate_request
      (r, DAV_INFINITY, NULL, &bind, NULL, DAV_VALIDATE_BIND, resource_state,
       &multi_response, &lrl_to_refresh, &lrl_to_delete);
    if (err) return dav_handle_err(r, err, multi_response);

    /* prepare the destination collection for modification */
    if ((err = dav_auto_checkout(r, binding, 1 /* parent_only */,
                                 &av_info)) != NULL) {
        /* could not make destination writable */
        return dav_handle_err(r, err, NULL);
    }

    /* If target exists, remove it first (we know Ovewrite must be TRUE).
     * Then try to bind to the resource.
     */
    if (binding->exists)
        err = (*resource->hooks->remove_resource)(binding, &multi_response);

    if (err == NULL) {
        err = (*binding_hooks->bind_resource)
          (resource, binding_parent, segment_str, binding);
    }

    /* restore parent collection states */
    err2 = dav_auto_checkin(r, NULL,
                            err != NULL /* undo if error */,
                            0 /* unlock */, &av_info);

    /* check for error from remove/bind operations */
    if (err != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             apr_psprintf(r->pool,
                                          "Could not BIND %s.",
                                          ap_escape_html(r->pool, r->uri)),
                             err);
        return dav_handle_err(r, err, multi_response);
    }

    /* check for errors from reverting writability */
    if (err2 != NULL) {
        /* just log a warning */
        err = dav_push_error(r->pool, err2->status, 0,
                             "The BIND was successful, but there was a "
                             "problem automatically checking in the "
                             "source parent collection.",
                             err2);
        dav_log_err(r, err, APLOG_WARNING);
    }

    /* if the resource is lockable, let lock system know of new resource */
    if (locks_hooks != NULL) {
        dav_lockdb *lockdb;
        dav_lock *li;

        if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb)) != NULL) {
            /* The resource creation was successful, but the locking failed. */
            err = dav_push_error(r->pool, err->status, 0,
                                 "The BIND was successful, but there "
                                 "was a problem opening the lock database "
                                 "which prevents inheriting locks from the "
                                 "parent resources.",
                                 err);
            return dav_handle_err(r, err, NULL);
        }

        for (li = lrl_to_delete; li && !err; li = li->next)
            err = (*lockdb->hooks->remove_lock)(lockdb, NULL, li->locktoken);
        for (li = lrl_to_refresh; li && !err; li = li->next)
            err = (*lockdb->hooks->remove_lock)(lockdb, NULL, li->locktoken);

        if (!err && lrl_to_refresh)
            err = (*lockdb->hooks->refresh_locks)(lockdb, resource,
                                                  lrl_to_refresh, 1);

        /* notify lock system that we have created/replaced a resource */
        if (!err)
            err = dav_notify_created(r, lockdb, binding, DAV_RESOURCE_NULL , 0);

        (*locks_hooks->close_lockdb)(lockdb);

        if (err != NULL) {
            /* The dir creation was successful, but the locking failed. */
            err = dav_push_error(r->pool, err->status, 0,
                                 "The BIND was successful, but there "
                                 "was a problem updating its lock "
                                 "information.",
                                 err);
            return dav_handle_err(r, err, NULL);
        }
    }
 
    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    /* return an appropriate response (HTTP_OK or HTTP_CREATED) */
    if (overwrite) {
        r->status = HTTP_OK;
        return DONE;
    }
    return dav_created(r, binding_rec->uri, "Binding", 0);
}

static dav_redirectref_lifetime parse_lifetime(apr_xml_elem *root)
{
    apr_xml_elem *lifetime_elem;
    dav_redirectref_lifetime t;

    if ((lifetime_elem = dav_find_child(root, "redirect-lifetime")) == NULL) 
        t = DAV_REDIRECTREF_NULL;
    else if (dav_find_child(lifetime_elem, "temporary")) 
        t = DAV_REDIRECTREF_TEMPORARY;
    else if (dav_find_child(lifetime_elem, "permanent"))
        t = DAV_REDIRECTREF_PERMANENT;
    else
        t = DAV_REDIRECTREF_INVALID;

    return t;
}

static int dav_method_mkredirectref(dav_request *dav_r) 
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    dav_resource *parent_resource = dav_r->parent_resource;
    dav_error *err;
    const dav_hooks_redirect *redirect_hooks = dav_get_redirect_hooks(r);
    const dav_hooks_transaction *xaction_hooks = dav_get_transaction_hooks(r);
    apr_xml_doc *doc;
    int result;
    dav_redirectref_lifetime t;
    int legal_reftarget = 0;

    /* if there is no redirect provider, decline request */
    if (redirect_hooks == NULL)
        return DECLINED;

    /* precondition: resource-must-be-null */
    if (resource->exists) {
        err = dav_new_error_tag(r->pool, HTTP_CONFLICT, 0, 
                                "A resource already exists at the request-uri",
                                NULL, "resource-must-be-null", NULL, NULL);
        return dav_handle_err(r, err, NULL);
    }

    /* precondition: parent-resource-must-be-non-null */
    if (parent_resource == NULL || !parent_resource->exists || 
        !parent_resource->collection) {
        err = dav_new_error_tag(r->pool, HTTP_CONFLICT, 0,
                                "Parent collection does not exist.", NULL, 
                                "parent-resource-must-be-non-null", NULL, NULL);
        return dav_handle_err(r, err, NULL);
    }

    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
        return result;
    }

    if (doc == NULL || !dav_validate_root(doc, "mkredirectref")) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "The request body does"
                      " not contain a \"mkredirectref\" element.");
        return HTTP_BAD_REQUEST;
    }

    /*  
        parse redirect-lifetime 
        precondition: redirect-lifetime-supported
    */
    apr_xml_elem *href_elem, *reftarget_elem;
    t = parse_lifetime(doc->root);

    if (t == DAV_REDIRECTREF_INVALID) {
        err = dav_new_error_tag(r->pool, HTTP_CONFLICT, 0,
                                "redirect-lifetime supplied is not supported.",
                                NULL, "redirect-lifetime-supported", NULL, NULL);
        return dav_handle_err(r, err, NULL);
    }
    
    /* 
        if the client does not specify a redirect-lifetime,
        default to temporary.
    */

    if (t == DAV_REDIRECTREF_NULL) {
        t = DAV_REDIRECTREF_TEMPORARY;
    }

    /* parse reftarget */
    const char *reftarget;

    if ((reftarget_elem = dav_find_child(doc->root, "reftarget")) == NULL) 
        return HTTP_BAD_REQUEST;

    if ((href_elem = dav_find_child(reftarget_elem, "href"))) {
        reftarget = dav_xml_get_cdata(href_elem, r->pool, 1);
        apr_uri_t uptr;
        if ((result = apr_uri_parse(r->pool, reftarget, &uptr)) == APR_SUCCESS)
            legal_reftarget = 1;
    }

    /* precondition: legal-reftarget */
    if (!legal_reftarget) {
        err = dav_new_error_tag(r->pool, HTTP_CONFLICT, 0, 
                                "Illegal reftarget.", NULL, "legal-reftarget",
                                NULL, NULL);
        return dav_handle_err(r, err, NULL);
    }

    /* create the redirect reference resource */
    if ((err = redirect_hooks->create_redirectref(resource, reftarget, t))) {
        if (xaction_hooks && dav_r->trans) 
            xaction_hooks->mode_set(dav_r->trans, DAV_TRANSACTION_ROLLBACK);

        return dav_handle_err(r, err, NULL);
    }

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    return dav_created(r, r->uri, "Redirect Reference", 0);
}

static int dav_is_allow_method_updateredirectref(
    dav_request *dav_r, 
    const dav_hooks_acl *acl_hook, 
    const dav_principal *principal
){
    int retVal = TRUE;
    dav_resource *resource = dav_r->resource;
    
    if (resource->exists && acl_hook != NULL) {
	retVal = (*acl_hook->is_allow)(principal, resource, 
                                       DAV_PERMISSION_WRITE_CONTENT);
    }

    return retVal;
}

static int dav_method_updateredirectref(dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    dav_resource *resource = dav_r->resource;
    dav_error *err;
    const dav_hooks_redirect *redirect_hooks = dav_get_redirect_hooks(r);
    apr_xml_doc *doc;
    int result;

    /* if there is no redirect provider, decline request */
    if (redirect_hooks == NULL)
        return DECLINED;

    /* precondition: must-be-redirectref */
    if (resource->type != DAV_RESOURCE_TYPE_REDIRECTREF) {
        err = dav_new_error_tag(r->pool, HTTP_CONFLICT, 0,
                                "request-uri is not a redirect reference.",
                                NULL, "must-be-redirectref", NULL, NULL);
        return dav_handle_err(r, err, NULL);
    }

    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
        return result;
    }

    if (doc == NULL || !dav_validate_root(doc, "updateredirectref")) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "The request body does"
                      " not contain a \"mkredirectref\" element.");
        return HTTP_BAD_REQUEST;
    }

    /* precondition: redirect-lifetime-supported */
    dav_redirectref_lifetime t = parse_lifetime(doc->root);
    if (t == DAV_REDIRECTREF_INVALID) {
        err = dav_new_error_tag(r->pool, HTTP_CONFLICT, 0,
                                "redirect-lifetime supplied is not supported.",
                                NULL, "redirect-lifetime-supported", NULL, NULL);
        return dav_handle_err(r, err, NULL);
    }

    /* parse reftarget */
    const char *reftarget;
    apr_xml_elem *reftarget_elem, *href_elem;
    int legal_reftarget = 1;

    if ((reftarget_elem = dav_find_child(doc->root, "reftarget")) != NULL) { 
        if ((href_elem = dav_find_child(reftarget_elem, "href"))) {
            reftarget = dav_xml_get_cdata(href_elem, r->pool, 1);
            apr_uri_t uptr;
            if ((result = apr_uri_parse(r->pool, reftarget, &uptr)) != APR_SUCCESS)
                legal_reftarget = 0;
        }
        else {
            legal_reftarget = 0;
        }
    }

    /* precondition: legal-reftarget */
    if (!legal_reftarget) {
        err = dav_new_error_tag(r->pool, HTTP_CONFLICT, 0, 
                                "Illegal reftarget.", NULL, "legal-reftarget",
                                NULL, NULL);
        return dav_handle_err(r, err, NULL);
    }

    /* update redirect reference */
    if ((err = redirect_hooks->update_redirectref(resource, reftarget, t))) {
        const dav_hooks_transaction *xaction_hooks = dav_get_transaction_hooks(r);
        if (xaction_hooks && dav_r->trans) 
            xaction_hooks->mode_set(dav_r->trans, DAV_TRANSACTION_ROLLBACK);

        return dav_handle_err(r, err, NULL);
    }

    /* end transaction here, if one was started */
    if(dav_r->trans)
        if((err = dav_transaction_end(r, dav_r->trans)))
            return dav_handle_err(r, err, NULL);

    return HTTP_OK;
}

int dav_method_handle(dav_method *m, dav_request *dav_r)
{
    request_rec *r = dav_r->request;
    int retVal;
    dav_error *err = NULL;

    if (m) {
        int xaction_error = 0;

        /* start a transaction if the method is transactional */
        if(m->is_transactional) 
            dav_transaction_start(r, &(dav_r->trans));
        
        retVal = (*m->handle)(dav_r);
        
        /* end the transaction if started */
        if(dav_r->trans) {
            err = dav_transaction_end(r, dav_r->trans);
            if (apr_table_get(r->notes, "xaction_error")) {
                xaction_error = 1;
                apr_table_setn(r->notes, "xaction_error", NULL);
            }
        }

        /* send transaction 5xx errors only if 
         * we were going to send 2xx otherwise. */
        if(!xaction_error && err && ap_is_HTTP_SUCCESS(retVal)) {
            retVal = dav_handle_err(r, err, NULL);
        }

        return xaction_error ? HTTP_SERVICE_UNAVAILABLE : retVal;
    }

    return DECLINED;
}

int dav_is_method_allow(dav_method *m, dav_request *dav_r,
                        const dav_hooks_acl *acl_hook,
                        const dav_principal *principal)
{
    if (m)
	return (*m->is_allow)(dav_r, acl_hook, principal);
    return FALSE;
}

/*
 * Response handler for DAV resources
 */

dav_method *make_get_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_get;
    retVal->is_allow = dav_is_allow_method_get;
    retVal->label_allowed = 1;
    retVal->use_checked_in = 0;

    return retVal;
}

static dav_method *make_put_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_put;
    retVal->is_allow = dav_is_allow_method_put;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;

    return retVal;
}

static dav_method *make_post_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_post;
    retVal->is_allow = dav_is_allow_method_get;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    
    return retVal;
}

static dav_method *make_delete_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_delete;
    retVal->is_allow = dav_is_allow_method_delete;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;

    return retVal;
}

static dav_method *make_options_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_options;
    retVal->is_allow = dav_is_allow_method_get;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    
    return retVal;
}

static dav_method *make_propfind_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_propfind;
    retVal->is_allow = dav_is_allow_method_propfind;
    retVal->label_allowed = 1;
    retVal->use_checked_in = 0;
    
    return retVal;
}

static dav_method *make_proppatch_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_proppatch;
    retVal->is_allow = dav_is_allow_method_proppatch;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;

    return retVal;
}

static dav_method *make_mkcol_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_mkcol;
    retVal->is_allow = dav_is_allow_method_mkcol;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;

    return retVal;
}

static dav_method *make_copy_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_copymove;
    retVal->is_allow = dav_is_allow_method_copy;
    retVal->label_allowed = 1;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;

    return retVal;
}

static dav_method *make_move_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_copymove;
    retVal->is_allow = dav_is_allow_method_move;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_lock_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_lock;
    retVal->is_allow = dav_is_allow_method_lock;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_unlock_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_unlock;
    retVal->is_allow = dav_is_allow_method_unlock;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_vsn_control_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_vsn_control;
    retVal->is_allow = dav_is_allow_method_proppatch;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_checkout_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_checkout;
    retVal->is_allow = dav_is_allow_method_proppatch;
    retVal->label_allowed = 1;
    retVal->use_checked_in = 0; /** TODO: investigate this */
    
    return retVal;
}

static dav_method *make_uncheckout_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_uncheckout;
    retVal->is_allow = dav_is_allow_method_proppatch;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_checkin_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_checkin;
    retVal->is_allow = dav_is_allow_method_proppatch;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_update_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_update;
    retVal->is_allow = NULL; /* TODO */
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_label_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_label;
    retVal->is_allow = NULL; /* TODO */
    retVal->label_allowed = 1;
    retVal->use_checked_in = 0;
    
    return retVal;
}

static dav_method *make_report_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_report;
    retVal->is_allow = dav_is_allow_method_get;
    retVal->label_allowed = 0;  /** TODO: investigate this */
    retVal->use_checked_in = 0;
    
    return retVal;
}

static dav_method *make_make_workspace_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_make_workspace;
    retVal->is_allow = dav_is_allow_method_make_workspace;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_make_activity_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_make_activity;
    retVal->is_allow = dav_is_allow_method_make_workspace;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;

    return retVal;
}

static dav_method *make_baseline_control_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_baseline_control;
    retVal->is_allow = dav_is_allow_method_baseline_control;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_merge_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_merge;
    retVal->is_allow = dav_is_allow_method_merge;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_bind_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    retVal->handle = dav_method_bind;
    retVal->is_allow = dav_is_allow_method_bind;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_rebind_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    retVal->handle = dav_method_rebind;
    retVal->is_allow = dav_is_allow_method_rebind;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_unbind_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    retVal->handle = dav_method_unbind;
    retVal->is_allow = dav_is_allow_method_unbind;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_search_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_search;
    retVal->is_allow = dav_is_allow_method_get;
    retVal->label_allowed = 1;
    retVal->use_checked_in = 0;
    
    return retVal;
}

static dav_method *make_acl_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_acl;
    retVal->is_allow = dav_is_allow_method_acl;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_mkredirectref_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_mkredirectref;
    retVal->is_allow = dav_is_allow_method_mkcol;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static dav_method *make_updateredirectref_method(apr_pool_t *p)
{
    dav_method *retVal;
    retVal = (dav_method *)apr_pcalloc(p, sizeof(*retVal));
    
    retVal->handle = dav_method_updateredirectref;
    retVal->is_allow = dav_is_allow_method_updateredirectref;
    retVal->label_allowed = 0;
    retVal->use_checked_in = 0;
    retVal->is_transactional = 1;
    
    return retVal;
}

static void dav_add_method(dav_all_methods *methods, int method_number, dav_method *m, apr_pool_t *p)
{
    int *buf;
    buf = (int *)apr_pcalloc(p, sizeof(*buf));
    *buf = method_number;
    apr_hash_set(methods->method_hash, buf, sizeof(*buf), m);
}

dav_all_methods *dav_all_methods_new(apr_pool_t *p)
{
    dav_all_methods *retVal;

    retVal = (dav_all_methods *)apr_pcalloc(p, sizeof(*retVal));
    retVal->method_hash = apr_hash_make(p);
    
    dav_add_method( retVal, M_GET, make_get_method(p), p );
    dav_add_method( retVal, M_PUT, make_put_method(p), p );
    dav_add_method( retVal, M_POST, make_post_method(p), p );
    dav_add_method( retVal, M_DELETE, make_delete_method(p), p );
    dav_add_method( retVal, M_OPTIONS, make_options_method(p), p );
    dav_add_method( retVal, M_PROPFIND, make_propfind_method(p), p );
    dav_add_method( retVal, M_PROPPATCH, make_proppatch_method(p), p );
    dav_add_method( retVal, M_MKCOL, make_mkcol_method(p), p );
    dav_add_method( retVal, M_COPY, make_copy_method(p), p );
    dav_add_method( retVal, M_MOVE, make_move_method(p), p );
    dav_add_method( retVal, M_LOCK, make_lock_method(p), p );
    dav_add_method( retVal, M_UNLOCK, make_unlock_method(p), p );
    dav_add_method( retVal, M_VERSION_CONTROL, make_vsn_control_method(p), p );
    dav_add_method( retVal, M_CHECKOUT, make_checkout_method(p), p );
    dav_add_method( retVal, M_UNCHECKOUT, make_uncheckout_method(p), p );
    dav_add_method( retVal, M_CHECKIN, make_checkin_method(p), p );
    dav_add_method( retVal, M_UPDATE, make_update_method(p), p );
    dav_add_method( retVal, M_LABEL, make_label_method(p), p );
    dav_add_method( retVal, M_REPORT, make_report_method(p), p );
    dav_add_method( retVal, M_MKWORKSPACE, make_make_workspace_method(p), p );
    dav_add_method( retVal, M_MKACTIVITY, make_make_activity_method(p), p );
    dav_add_method( retVal, M_BASELINE_CONTROL, make_baseline_control_method(p), p );
    dav_add_method( retVal, M_MERGE, make_merge_method(p), p );
    
    /* Register DAV methods */
    dav_methods[DAV_M_BIND] = ap_method_register(p, "BIND");
    dav_methods[DAV_M_UNBIND] = ap_method_register(p, "UNBIND");
    dav_methods[DAV_M_REBIND] = ap_method_register(p, "REBIND");
    dav_methods[DAV_M_SEARCH] = ap_method_register(p, "SEARCH");
    dav_methods[DAV_M_ACL] = ap_method_register(p, "ACL");
    dav_methods[DAV_M_MKREDIRECTREF] = ap_method_register(p, "MKREDIRECTREF");
    dav_methods[DAV_M_UPDATEREDIRECTREF] = 
                            ap_method_register(p, "UPDATEREDIRECTREF");
    

    /* BIND method */
    dav_add_method( retVal, dav_methods[DAV_M_BIND], make_bind_method(p), p );
    dav_add_method( retVal, dav_methods[DAV_M_UNBIND], 
                    make_unbind_method(p), p );
    dav_add_method( retVal, dav_methods[DAV_M_REBIND], 
                    make_rebind_method(p), p );

    /* DASL method */
    dav_add_method( retVal, dav_methods[DAV_M_SEARCH], 
                    make_search_method(p), p );

    /* ACL method */
    dav_add_method( retVal, dav_methods[DAV_M_ACL], make_acl_method(p), p );

    /* REDIRECT methods */
    dav_add_method( retVal, dav_methods[DAV_M_MKREDIRECTREF], 
                    make_mkredirectref_method(p), p );
    dav_add_method( retVal, dav_methods[DAV_M_UPDATEREDIRECTREF], 
                    make_updateredirectref_method(p), p );

    return retVal;
}

dav_method *dav_get_method(dav_all_methods *methods, request_rec *r)
{
    if (!methods) return NULL;
    return (dav_method *)apr_hash_get(methods->method_hash, 
                            &(r->method_number), sizeof(r->method_number));
}

static int dav_init_handler(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
                             server_rec *s)
{
    /* DBG0("dav_init_handler"); */

    /* Register DAV methods */
    dav_registered_methods = dav_all_methods_new(p);

    ap_add_version_component(p, "DAV/2");

    return OK;
}

static int dav_dispatch_method(request_rec *r)
{
    dav_method *method;
    const dav_hooks_acl *acl_hooks = dav_get_acl_hooks(r);
    const dav_hooks_redirect *redirect_hooks = dav_get_redirect_hooks(r);
    const dav_principal *principal;
    int is_allow = TRUE;
    dav_resource *resource;
    dav_error *err = NULL;
    dav_request *dav_r = apr_pcalloc(r->pool, sizeof(dav_request));
    int resource_state, result;

    dav_r->request = r;

    method = dav_get_method(dav_registered_methods, r);
    if(!method) {
    	return HTTP_NOT_IMPLEMENTED;
    }

    err = dav_get_resource(r, method->label_allowed, 
                           method->use_checked_in, &resource);

    if (err) return dav_handle_err(r, err, NULL);

    dav_r->resource = resource;
    dav_r->apply_to_redirectref = apply_to_redirectref(r);

    if (redirect_hooks && 
        resource->type == DAV_RESOURCE_TYPE_REDIRECTREF &&
        !dav_r->apply_to_redirectref) {
        const char *reftarget = redirect_hooks->get_reftarget(resource);
        dav_redirectref_lifetime t = redirect_hooks->get_lifetime(resource);
        /* set the redirect headers */
        apr_table_set(r->err_headers_out, "Location", reftarget);
        apr_table_set(r->err_headers_out, "Redirect-Ref", reftarget);

        if (t != DAV_REDIRECTREF_TEMPORARY) {
            return HTTP_MOVED_PERMANENTLY;
        }

        return HTTP_MOVED_TEMPORARILY;
    }
  
    if (acl_hooks)
    {
        principal = dav_principal_make_from_request(r);
        /* Bypassing acl's for PUT user (creating a new user) 
          is_allow = TRUE; */
        is_allow = dav_is_method_allow(method, dav_r, acl_hooks, principal);
    }

    if(!is_allow) {
        /**
         * According to Section 7.1.1 RFC2518bis,
         * If an HTTP method fails due to insufficient privileges, 
         * the response body to the "403 Forbidden" error MUST contain 
         * the <DAV:error> element, which in turn contains 
         * the <DAV:need-privileges> element, which contains one or more 
         * <DAV:resource> elements indicating which resource had insufficient 
         * privileges, and what the lacking privileges were.
         *
         * Assuming here, that dav_is_method_allow sets resource->err 
         * to the appropriate DAV:error element.
         */
	return dav_handle_err(r, resource->err, NULL);
    }

    /* set up the ETag header for If-* header checks */
    if ((err = (*resource->hooks->set_headers)(r, resource)) != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             "Unable to set up HTTP headers.", err);
        return dav_handle_err(r, err, NULL);
    }

    resource_state = dav_get_resource_state(r, resource);
    result = dav_meets_conditions(r, resource_state);

    apr_table_unset(r->headers_out, "ETag");

    if (result != OK) {
        return result;
    }

    return dav_method_handle(method, dav_r);
}

static int dav_handler(request_rec *r)
{
    int retVal, num_tries = 0, timeout = DAV_RETRY_MIN_TIMEOUT; 

    if (strcmp(r->handler, DAV_HANDLER_NAME) != 0)
        return DECLINED;

    /* Reject requests with an unescaped hash character, as these may
     * be more destructive than the user intended. */
    if (r->parsed_uri.fragment != NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                     "buggy client used un-escaped hash in Request-URI");
        return dav_error_response(r, HTTP_BAD_REQUEST,
                                  "The request was invalid: the URI included "
                                  "an un-escaped hash character");
    }

    /* ### do we need to do anything with r->proxyreq ?? */

    /*
     * ### anything else to do here? could another module and/or
     * ### config option "take over" the handler here? i.e. how do
     * ### we lock down this hierarchy so that we are the ultimate
     * ### arbiter? (or do we simply depend on the administrator
     * ### to avoid conflicting configurations?)
     */

    /*
     * Set up the methods mask, since that's one of the reasons this handler
     * gets called, and lower-level things may need the info.
     *
     * First, set the mask to the methods we handle directly.  Since by
     * definition we own our managed space, we unconditionally set
     * the r->allowed field rather than ORing our values with anything
     * any other module may have put in there.
     *
     * These are the HTTP-defined methods that we handle directly.
     */
    r->allowed = 0
        | (AP_METHOD_BIT << M_GET)
        | (AP_METHOD_BIT << M_PUT)
        | (AP_METHOD_BIT << M_DELETE)
        | (AP_METHOD_BIT << M_OPTIONS)
        | (AP_METHOD_BIT << M_INVALID);

    /*
     * These are the DAV methods we handle.
     */
    r->allowed |= 0
        | (AP_METHOD_BIT << M_COPY)
        | (AP_METHOD_BIT << M_LOCK)
        | (AP_METHOD_BIT << M_UNLOCK)
        | (AP_METHOD_BIT << M_MKCOL)
        | (AP_METHOD_BIT << M_MOVE)
        | (AP_METHOD_BIT << M_PROPFIND)
        | (AP_METHOD_BIT << M_PROPPATCH);

    /*
     * These are methods that we don't handle directly, but let the
     * server's default handler do for us as our agent.
     */
    r->allowed |= 0
        | (AP_METHOD_BIT << M_POST);

    /* ### hrm. if we return HTTP_METHOD_NOT_ALLOWED, then an Allow header
     * ### is sent; it will need the other allowed states; since the default
     * ### handler is not called on error, then it doesn't add the other
     * ### allowed states, so we must
     */

    /* ### we might need to refine this for just where we return the error.
     * ### also, there is the issue with other methods (see ISSUES)
     */

    /* keep a backup of request_rec */ 	 	 

    /* dispatch the appropriate method handler */
    retVal = dav_dispatch_method(r);
    while(retVal == HTTP_SERVICE_UNAVAILABLE && num_tries < DAV_REQ_MAX_TRIES) {
        /* revert to the original request_rec */

        /* if we got a 503, wait a moment, then retry */ 
        DBG3("Retrying transaction for %s: try(%d) timeout(%d)",
             r->method, num_tries, timeout);
        apr_sleep(timeout);
        retVal = dav_dispatch_method(r);

        /* exponential back-off */ 	 
        timeout *= 2;
        num_tries++;
    }

    /* Set Retry-After header for 503 response,
     * returned for e.g. upon a transaction deadlock*/
    if(retVal == HTTP_SERVICE_UNAVAILABLE) {
        apr_table_setn(r->err_headers_out, "Retry-After",
                       DAV_CLIENT_RETRY_MIN_TIMEOUT);
        if (r->expecting_100) {
            r->status = HTTP_SERVICE_UNAVAILABLE;
            expect_100_fixups(r);
            return DONE;
        }
    }

    return retVal;
}

static int dav_fixups(request_rec *r)
{
    dav_dir_conf *conf;

    /* quickly ignore any HTTP/0.9 requests which aren't subreqs. */
    if (r->assbackwards && !r->main) {
        return DECLINED;
    }

    conf = (dav_dir_conf *)ap_get_module_config(r->per_dir_config,
                                                &dav_module);

    /* if DAV is not enabled, then we've got nothing to do */
    if (conf->provider == NULL) {
        return DECLINED;
    }

    /* We are going to handle almost every request. In certain cases,
       the provider maps to the filesystem (thus, handle_get is
       FALSE), and core Apache will handle it. a For that case, we
       just return right away.  */
    if (r->method_number == M_GET) {
        /*
         * ### need some work to pull Content-Type and Content-Language
         * ### from the property database.
         */

        /*
         * If the repository hasn't indicated that it will handle the
         * GET method, then just punt.
         *
         * ### this isn't quite right... taking over the response can break
         * ### things like mod_negotiation. need to look into this some more.
         */
        if (!conf->provider->repos->handle_get) {
            return DECLINED;
        }

        if (r->main) {
            /* If this is a subrequest */
            const char *no_lookup = apr_table_get
              (r->main->subprocess_env, "DAV_NO_LOOKUP");
            if (!no_lookup || strcmp(no_lookup, "true")) {
                dav_resource *resource = NULL;
                dav_error *err = NULL;
                err = dav_get_resource(r, 0, 0, &resource);
                if (err || !resource->exists)
                    return HTTP_NOT_FOUND;
            }
        }
    }

    /* ### this is wrong.  We should only be setting the r->handler for the
     * requests that mod_dav knows about.  If we set the handler for M_POST
     * requests, then CGI scripts that use POST will return the source for the
     * script.  However, mod_dav DOES handle POST, so something else needs
     * to be fixed.
     */
    if (r->method_number != M_POST) {

        /* We are going to be handling the response for this resource. */
        r->handler = DAV_HANDLER_NAME;
        return OK;
    }

    return DECLINED;
}

static int dav_check_user_id(request_rec *r)
{
    dav_dir_conf *conf;
    conf = (dav_dir_conf *)ap_get_module_config(r->per_dir_config,
                                                &dav_module);
    /* if DAV is not enabled, then we've got nothing to do */
    if (conf->provider == NULL) {
        return DECLINED;
    }

    if (conf->allow_unauthenticated_access != 1) {
        return DECLINED;
    }

    if (apr_table_get(r->headers_in, (PROXYREQ_PROXY == r->proxyreq)
                      ? "Proxy-Authorization" : "Authorization")) {
        if (r->user && !strcmp(r->user, "unauthenticated")) {
            ap_note_auth_failure(r);
            return HTTP_UNAUTHORIZED;
        }
        return DECLINED;
    }

    if (r->user)
        return DECLINED;
    
    r->user = "unauthenticated";
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(dav_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id(dav_check_user_id, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_fixups(dav_fixups, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(dav_handler, NULL, NULL, APR_HOOK_MIDDLE);

    dav_hook_find_liveprop(dav_core_find_liveprop, NULL, NULL, APR_HOOK_LAST);
    dav_hook_insert_all_liveprops(dav_core_insert_all_liveprops,
                                  NULL, NULL, APR_HOOK_MIDDLE);

    dav_core_register_uris(p);
}

/*---------------------------------------------------------------------------
 *
 * Configuration info for the module
 */

static const command_rec dav_cmds[] =
{
    /* per directory/location */
    AP_INIT_TAKE1("DAV", dav_cmd_dav, NULL, ACCESS_CONF,
                  "specify the DAV provider for a directory or location"),

    /* per directory/location, or per server */
    AP_INIT_TAKE1("DAVMinTimeout", dav_cmd_davmintimeout, NULL,
                  ACCESS_CONF|RSRC_CONF,
                  "specify minimum allowed timeout"),

    /* per directory/location, or per server */
    AP_INIT_FLAG("DAVDepthInfinity", dav_cmd_davdepthinfinity, NULL,
                 ACCESS_CONF|RSRC_CONF,
                 "allow Depth infinity PROPFIND requests"),

    AP_INIT_FLAG("DAVUnauthenticatedAccess", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(dav_dir_conf, allow_unauthenticated_access), ACCESS_CONF,
                 "Disable this module's authorization and authentication hacks for this location"),

    AP_INIT_TAKE2("DAVResponseRewriteCond", dav_cmd_davresponserewritecond, NULL,
                  ACCESS_CONF|RSRC_CONF, "response uri rewrite condition"),

    AP_INIT_TAKE2("DAVResponseRewriteRule", dav_cmd_davresponserewriterule, NULL,
                  ACCESS_CONF|RSRC_CONF, "response uri rewrite rule"),

    { NULL }
};

module DAV_DECLARE_DATA dav_module =
{
    STANDARD20_MODULE_STUFF,
    dav_create_dir_config,      /* dir config creater */
    dav_merge_dir_config,       /* dir merger --- default is to override */
    dav_create_server_config,   /* server config */
    dav_merge_server_config,    /* merge server config */
    dav_cmds,                   /* command table */
    register_hooks,             /* register hooks */
};

APR_HOOK_STRUCT(
    APR_HOOK_LINK(gather_propsets)
    APR_HOOK_LINK(find_liveprop)
    APR_HOOK_LINK(insert_all_liveprops)
    )

APR_IMPLEMENT_EXTERNAL_HOOK_VOID(dav, DAV, gather_propsets,
                                 (apr_array_header_t *uris),
                                 (uris))

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(dav, DAV, int, find_liveprop,
                                      (const dav_resource *resource,
                                       const char *ns_uri, const char *name,
                                       const dav_hooks_liveprop **hooks),
                                      (resource, ns_uri, name, hooks), 0)

APR_IMPLEMENT_EXTERNAL_HOOK_VOID(dav, DAV, insert_all_liveprops,
                                 (request_rec *r, const dav_resource *resource,
                                  dav_prop_insert what, apr_text_header *phdr),
                                 (r, resource, what, phdr))
