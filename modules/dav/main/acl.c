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

#include "apr_strings.h"
#include "httpd.h"
#include "mod_dav.h"

dav_acl *dav_acl_new(apr_pool_t *p, const dav_resource *resource, 
                     const dav_principal *owner, const dav_principal *group)
{
    dav_acl *retVal = NULL;
    
    if (resource && owner && group)
    {
    retVal = (dav_acl *)apr_pcalloc(p, sizeof(*retVal));
	retVal->resource = resource;
	retVal->owner = owner;
	retVal->group = group;
	retVal->head_ace = NULL;
	retVal->pool = p;
    }
    
    return retVal;
}

int dav_clear_all_ace(dav_acl *acl)
{
    int retVal = 0;

    if (acl)
	acl->head_ace = NULL;

    return retVal;
}

const dav_resource *dav_get_acl_resource(const dav_acl *acl)
{
    const dav_resource *retVal = NULL;
    if (acl)
	retVal = acl->resource;
    return retVal;
}

const dav_principal *dav_get_acl_owner(const dav_acl *acl)
{
    const dav_principal *retVal = NULL;
    if (acl)
	retVal = acl->owner;
    return retVal;
}

const dav_principal *dav_get_acl_group(const dav_acl *acl)
{
    const dav_principal *retVal = NULL;
    if (acl)
	retVal = acl->group;
    return retVal;
}

int dav_set_acl_owner(dav_acl *acl, const dav_principal *owner)
{
    int retVal = 0;
    if (acl)
	acl->owner = owner;
    return retVal;
}

int dav_set_acl_group(dav_acl *acl, const dav_principal *group)
{
    int retVal = 0;
    if (acl)
	acl->group = group;
    return retVal;
}

int dav_get_ace_count(const dav_acl *acl)
{
    int retVal = 0;
    if (acl)
    {
	const ace_list *node;
	for(node = acl->head_ace; node; node = node->next, retVal++);
    }
    return retVal;
}

const dav_ace *dav_get_ace(const dav_acl *acl, int index)
{
    const dav_ace *retVal = NULL;
    if (acl)
    {
	const ace_list *node = acl->head_ace;
	int i = 0;
	for(; node && i < index; node = node->next, i++);
	
	retVal = node->node;
    }
    return retVal;
}

dav_ace_iterator *dav_acl_iterate(const dav_acl *acl)
{
    dav_ace_iterator *retVal = NULL;
    
    if (acl)
    {
        retVal = (dav_ace_iterator *)apr_pcalloc(acl->pool, sizeof(*retVal));
	retVal->owner_acl = acl;
	retVal->current_ace = acl->head_ace;
    }
    
    return retVal;
}

const dav_ace *dav_ace_iterator_next(dav_ace_iterator *iter)
{
    const dav_ace *retVal = NULL;
    if (iter && iter->current_ace)
    {
	retVal = iter->current_ace->node;
	iter->current_ace = iter->current_ace->next;
    }
    return retVal;
}

const dav_ace *dav_ace_iterator_peek(const dav_ace_iterator *iter)
{
    const dav_ace *retVal = NULL;
    if (iter && iter->current_ace)
	retVal = iter->current_ace->node;
    return retVal;
}

int dav_ace_iterator_more(const dav_ace_iterator *iter)
{
    int retVal = FALSE;
    if (iter && iter->owner_acl)
	retVal = iter->current_ace != NULL;
    return retVal;
}

int dav_ace_iterator_rewind(dav_ace_iterator *iter)
{
    int retVal = 0;
    if (iter && iter->owner_acl)
	iter->current_ace = iter->owner_acl->head_ace;
    else
	retVal = -1;
    return retVal;
}

int dav_add_ace(dav_acl *acl, const dav_ace *ace)
{
    int retVal = 0;
    if (acl && ace)
    {
	ace_list *newAceNode;
	newAceNode = (ace_list *)apr_pcalloc(acl->pool, sizeof(*newAceNode));
	newAceNode->node = ace;
        if (acl->head_ace == NULL)
            acl->head_ace = acl->tail_ace = newAceNode;
        else {
            acl->tail_ace->next = newAceNode;
            acl->tail_ace = newAceNode;
        }
    }
    return retVal;
}

dav_ace *dav_ace_new(apr_pool_t *p, const dav_principal *principal,
                     const dav_prop_name *property,
                     const dav_privileges *privileges, int is_deny, 
                     char *inherited, int is_protected)
{
    dav_ace *retVal = NULL;
    
    retVal = (dav_ace *)apr_pcalloc(p, sizeof(*retVal));
    retVal->principal = principal;
    retVal->property = property;
    retVal->privileges = privileges;
    retVal->is_deny = is_deny;
    retVal->is_protected = is_protected;
    retVal->inherited = inherited;
    
    return retVal;
}

const dav_principal *dav_get_ace_principal(const dav_ace *ace)
{
    const dav_principal *retVal = NULL;
    if (ace)
	retVal = ace->principal;
    return retVal;
}

const dav_privileges *dav_get_ace_privileges(const dav_ace *ace)
{
    const dav_privileges *retVal = NULL;
    if (ace)
	retVal = ace->privileges;
    return retVal;
}

const dav_prop_name *dav_get_ace_property(const dav_ace *ace)
{
    const dav_prop_name *retVal = NULL;
    if (ace)
	retVal = ace->property;
    return retVal;
}

const char *dav_get_ace_inherited(const dav_ace *ace)
{
    const char *retVal = NULL;
    if (ace)
        retVal = ace->inherited;
    return retVal;
}

void *dav_get_ace_info(const dav_ace *ace)
{
    void *retVal = NULL;
    if (ace)
        retVal = ace->info;
    return retVal;
}

void dav_set_ace_inherited(dav_ace *ace, char *inherited)
{
    ace->inherited = inherited;
    return;
}

void dav_set_ace_info(dav_ace *ace, void *info)
{
    ace->info = info;
    return;
}

int dav_is_deny_ace(const dav_ace *ace)
{
    int retVal = 0;
    if (ace)
	retVal = ace->is_deny;
    return retVal;
}

int dav_is_protected_ace(const dav_ace *ace)
{
    int retVal = 0;
    if (ace)
	retVal = ace->is_protected;
    return retVal;
}

dav_privileges *dav_privileges_new(apr_pool_t *p)
{
    dav_privileges *retVal = NULL;
    retVal = (dav_privileges *)apr_pcalloc(p, sizeof(*retVal));
    retVal->head_privilege = NULL;
    retVal->pool = p;
    return retVal;
}

int dav_add_privilege(dav_privileges *privileges, 
                      const dav_privilege* privilege)
{
    int retVal = 0;
    if (privileges && privilege)
    {
	privilege_list *newPrivilegeNode;
	newPrivilegeNode = (privilege_list *) 
            apr_pcalloc(privileges->pool, sizeof(*newPrivilegeNode));
	newPrivilegeNode->node = privilege;
	newPrivilegeNode->next = privileges->head_privilege;
	privileges->head_privilege = newPrivilegeNode;
    }
    return retVal;
}

int dav_get_privileges_count(const dav_privileges *privileges)
{
    int retVal = 0;
    if (privileges)
    {
	const privilege_list *node;
	for(node = privileges->head_privilege; node; node = node->next, retVal++);
    }
    return retVal;
}

dav_privilege *dav_privilege_new_by_name(apr_pool_t *p, const char *ns, 
                                         const char *name)
{
    dav_privilege *retVal = NULL;
    retVal = (dav_privilege *)apr_pcalloc(p, sizeof(*retVal));
    if (ns)
	retVal->ns = apr_pstrdup(p, ns);
    else
	retVal->ns = NULL;
	
    if (name)
	retVal->name = apr_pstrdup(p, name);
    else
	retVal->name = NULL;
	
    retVal->type = DAV_PERMISSION_UNKNOWN;
	
    return retVal;
}

dav_privilege *dav_privilege_new_by_type(apr_pool_t *p, 
                                         dav_acl_permission_type privType)
{
    dav_privilege *retVal = NULL;
    retVal = (dav_privilege *)apr_pcalloc(p, sizeof(*retVal));
    retVal->type = privType;

    if (privType == DAV_PERMISSION_READ)
    {
	retVal->ns = NULL;
	retVal->name = apr_pstrdup(p, DAV_PERMISSION_READ_SIGNATURE);
    }
    else if (privType == DAV_PERMISSION_WRITE)
    {
	retVal->ns = NULL;
	retVal->name = apr_pstrdup(p, DAV_PERMISSION_WRITE_SIGNATURE);
    }
    else if (privType == DAV_PERMISSION_WRITE_PROPERTIES)
    {
	retVal->ns = NULL;
	retVal->name = apr_pstrdup(p, DAV_PERMISSION_WRITE_PROPERTIES_SIGNATURE);
    }
    else if (privType == DAV_PERMISSION_WRITE_CONTENT)
    {
	retVal->ns = NULL;
	retVal->name = apr_pstrdup(p, DAV_PERMISSION_WRITE_CONTENT_SIGNATURE);
    }
    else if (privType == DAV_PERMISSION_UNLOCK)
    {
	retVal->ns = NULL;
	retVal->name = apr_pstrdup(p, DAV_PERMISSION_UNLOCK_SIGNATURE);
    }
    else if (privType == DAV_PERMISSION_READ_ACL)
    {
	retVal->ns = NULL;
	retVal->name = apr_pstrdup(p, DAV_PERMISSION_READ_ACL_SIGNATURE);
    }
    else if (privType == DAV_PERMISSION_READ_CURRENT_USER_PRIVILEGE_SET)
    {
	retVal->ns = NULL;
	retVal->name = apr_pstrdup(p, 
                DAV_PERMISSION_READ_CURRENT_USER_PRIVILEGE_SET_SIGNATURE);
    }
    else if (privType == DAV_PERMISSION_WRITE_ACL)
    {
	retVal->ns = NULL;
	retVal->name = apr_pstrdup(p, DAV_PERMISSION_WRITE_ACL_SIGNATURE);
    }
    else if (privType == DAV_PERMISSION_BIND)
    {
	retVal->ns = NULL;
	retVal->name = apr_pstrdup(p, DAV_PERMISSION_BIND_SIGNATURE);
    }
    else if (privType == DAV_PERMISSION_UNBIND)
    {
	retVal->ns = NULL;
	retVal->name = apr_pstrdup(p, DAV_PERMISSION_UNBIND_SIGNATURE);
    }
    else if (privType == DAV_PERMISSION_ALL)
    {
	retVal->ns = NULL;
	retVal->name = apr_pstrdup(p, DAV_PERMISSION_ALL_SIGNATURE);
    }
    else
    {
	retVal->ns = NULL;
	retVal->name = NULL;
    }
    
    return retVal;
}

dav_privilege *dav_privilege_new_by_xml(apr_pool_t *p, 
                                        apr_array_header_t *namespaces,
                                        const apr_xml_elem *privilegeXmlElem)
{
    dav_privilege *retVal = NULL;
    if (privilegeXmlElem)
    {
	apr_xml_elem *child = privilegeXmlElem->first_child;
        retVal = (dav_privilege *)apr_pcalloc(p, sizeof(*retVal));
	    
        if (child->name)
            retVal->name = apr_pstrdup(p, child->name);
        else
            retVal->name = NULL;
	if (child->ns != APR_XML_NS_DAV_ID) {
            retVal->ns = APR_ARRAY_IDX(namespaces, child->ns, const char *);
	}
    }
    
    return retVal;
}

const dav_privilege *dav_get_privilege(const dav_privileges *privileges, 
                                       int index)
{
    const dav_privilege *retVal = NULL;
    if (privileges)
    {
	const privilege_list *node = privileges->head_privilege;
	int i = 0;
	for(; node && i < index; node = node->next, i++);
	
	retVal = node->node;
    }
    return retVal;
}

const char *dav_get_privilege_name(const dav_privilege *privilege)
{
    const char *retVal = NULL;
    if (privilege)
	retVal = privilege->name;
    return retVal;
}

const char *dav_get_privilege_namespace(const dav_privilege *privilege)
{
    const char *retVal = NULL;
    if (privilege) {
	if (privilege->ns)
            retVal = privilege->ns;
        else retVal = "DAV:";
    }
    return retVal;
}

dav_privilege_iterator *dav_privilege_iterate(const dav_privileges *privileges)
{
    dav_privilege_iterator *retVal = NULL;
    
    if (privileges)
    {
        retVal = (dav_privilege_iterator *) 
            apr_pcalloc(privileges->pool, sizeof(*retVal));
	retVal->owner_privileges = privileges;
	retVal->current_privilege = privileges->head_privilege;
    }
    
    return retVal;
}

const dav_privilege *dav_privilege_iterator_next(dav_privilege_iterator *iter)
{
    const dav_privilege *retVal = NULL;
    if (iter && iter->current_privilege)
    {
	retVal = iter->current_privilege->node;
	iter->current_privilege = iter->current_privilege->next;
    }
    return retVal;
}

const dav_privilege *dav_privilege_iterator_peek(const dav_privilege_iterator *iter)
{
    const dav_privilege *retVal = NULL;
    if (iter && iter->current_privilege)
	retVal = iter->current_privilege->node;
    return retVal;
}

int dav_privilege_iterator_more(const dav_privilege_iterator *iter)
{
    int retVal = FALSE;
    if (iter && iter->owner_privileges)
	retVal = iter->current_privilege != NULL;
    return retVal;
}

int dav_privilege_iterator_rewind(dav_privilege_iterator *iter)
{
    int retVal = 0;
    if (iter && iter->owner_privileges)
	iter->current_privilege = iter->owner_privileges->head_privilege;
    else
	retVal = -1;
    return retVal;
}

dav_prop_name *dav_ace_property_new(apr_pool_t *pool, const char *ns, 
                                    const char *name)
{
    dav_prop_name *retVal = apr_pcalloc(pool, sizeof(*retVal));

    retVal->ns = ns;
    retVal->name = name;

    return retVal;
}
