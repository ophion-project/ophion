/*
 * include/propertyset.h
 * Copyright (c) 2020 Ariadne Conill <ariadne@dereferenced.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __OPHION_PROPERTYSET_H_GUARD
#define __OPHION_PROPERTYSET_H_GUARD

#include "ircd_defs.h"
#include "client.h"
#include "setup.h"

struct Property {
	char *name;
	char *value;
	time_t set_at;
	char *setter;

	rb_dlink_node prop_node;
};

enum PropMatchRequest {
	PROP_EXISTS,
	PROP_READ,
	PROP_WRITE,
};

struct PropMatch {
	const char *entity_name;
	void *entity;
	rb_dlink_list *prop_list;
	enum PropMatchRequest match_request;
};

struct Property *propertyset_add(rb_dlink_list *prop_list, const char *name, const char *value, struct Client *setter_p);
void propertyset_delete(rb_dlink_list *prop_list, const char *name);
struct Property *propertyset_find(const rb_dlink_list *prop_list, const char *name);
void propertyset_clear(rb_dlink_list *prop_list);

#endif
