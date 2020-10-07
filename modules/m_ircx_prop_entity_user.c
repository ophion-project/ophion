/*
 * modules/m_ircx_prop_entity_user.c
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

#include "stdinc.h"
#include "capability.h"
#include "client.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "monitor.h"
#include "numeric.h"
#include "s_assert.h"
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"
#include "supported.h"
#include "hash.h"
#include "propertyset.h"

static const char ircx_prop_entity_user_desc[] = "Provides IRCX PROP support for users";

static int h_prop_user_write;

mapi_hlist_av1 ircx_prop_entity_user_hlist[] = {
	{ "prop_user_write", &h_prop_user_write },
	{ NULL, NULL }
};

static void h_prop_burst_client(void *);
static void h_prop_match(void *);

mapi_hfn_list_av1 ircx_prop_entity_user_hfnlist[] = {
	{ "burst_client", (hookfn) h_prop_burst_client },
	{ "prop_match", (hookfn) h_prop_match },
	{ NULL, NULL }
};

static bool
can_write_to_user_property(struct Client *source_p, struct Client *target_p, const char *key)
{
	/* external writes should be done via TPROP */
	if (source_p != target_p)
		return false;

	hook_data_prop_activity prop_activity;

	prop_activity.client = source_p;
	prop_activity.target = target_p->name;
	prop_activity.prop_list = &target_p->user->prop_list;
	prop_activity.key = key;
	prop_activity.alevel = CHFL_ADMIN;
	prop_activity.approved = true;
	prop_activity.target_ptr = target_p;

	call_hook(h_prop_user_write, &prop_activity);

	return prop_activity.approved;
}

static void
h_prop_burst_client(void *vdata)
{
	hook_data_client *hclientinfo = vdata;
	struct Client *client_p = hclientinfo->client;
	struct Client *burst_p = hclientinfo->target;
	rb_dlink_node *it;

	if (burst_p->user == NULL)
		return;

	RB_DLINK_FOREACH(it, burst_p->user->prop_list.head)
	{
		struct Property *prop = it->data;

		/* :source TPROP target creationTS updateTS propName [:propValue] */
		sendto_one(client_p, ":%s TPROP %s %ld %ld %s :%s",
			use_id(&me), use_id(burst_p), burst_p->tsinfo, prop->set_at, prop->name, prop->value);
	}
}

static void
h_prop_match(void *vdata)
{
	struct PropMatch *prop_match = vdata;
	struct Client *target_p = find_client(prop_match->target_name);

	if (prop_match->target)
		return;

	if (target_p == NULL || target_p->user == NULL)
	{
		sendto_one_numeric(prop_match->source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), prop_match->target_name);
		return;
	}

	if (prop_match->match_request == PROP_WRITE)
		prop_match->match_grant =
			can_write_to_user_property(prop_match->source_p, target_p, prop_match->key) ? PROP_WRITE : PROP_READ;
	else
		prop_match->match_grant = prop_match->match_request;

	prop_match->redistribute = true;
	prop_match->creation_ts = target_p->tsinfo;
	prop_match->prop_list = &target_p->user->prop_list;
	prop_match->target = target_p;
}

DECLARE_MODULE_AV2(ircx_prop_entity_user, NULL, NULL, NULL, ircx_prop_entity_user_hlist, ircx_prop_entity_user_hfnlist, NULL, NULL, ircx_prop_entity_user_desc);
