/*
 * modules/m_ircx_prop_entity_account.c
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
#include "account.h"

static const char ircx_prop_entity_account_desc[] = "Provides IRCX PROP support for accounts";

static int h_prop_account_write;

mapi_hlist_av1 ircx_prop_entity_account_hlist[] = {
	{ "prop_account_write", &h_prop_account_write },
	{ NULL, NULL }
};

static void h_fn_burst_finished(void *);
static void h_prop_match(void *);
static void h_ircx_account_login(void *);

mapi_hfn_list_av1 ircx_prop_entity_account_hfnlist[] = {
	{ "burst_finished", (hookfn) h_fn_burst_finished },
	{ "prop_match", (hookfn) h_prop_match },
	{ "ircx_account_login", (hookfn) h_ircx_account_login },
	{ NULL, NULL }
};

static bool
can_write_to_account_property(struct Client *source_p, struct Account *target_p, const char *key)
{
	/* external writes should be done via TPROP */
	if (!MyClient(source_p))
		return false;

	hook_data_prop_activity prop_activity;

	prop_activity.client = source_p;
	prop_activity.target = target_p->name;
	prop_activity.prop_list = &target_p->prop_list;
	prop_activity.key = key;
	prop_activity.alevel = CHFL_ADMIN;
	prop_activity.approved = true;
	prop_activity.target_ptr = target_p;

	call_hook(h_prop_account_write, &prop_activity);

	return prop_activity.approved;
}

static inline void
burst_account(struct Client *client_p, struct Account *account_p)
{
	rb_dlink_node *it;

	RB_DLINK_FOREACH(it, account_p->prop_list.head)
	{
		struct Property *prop = it->data;

		/* :source TPROP target creationTS updateTS propName [:propValue] */
		sendto_one(client_p, ":%s TPROP account:%s %ld %ld %s :%s",
			use_id(&me), account_p->name, account_p->creation_ts, prop->set_at, prop->name, prop->value);
	}
}

static void
h_fn_burst_finished(void *vdata)
{
	hook_data_client *hclientinfo = vdata;
	struct Account *account_p;
	rb_radixtree_iteration_state iter;

	RB_RADIXTREE_FOREACH(account_p, &iter, account_dict)
		burst_account(hclientinfo->client, account_p);
}

static void
h_prop_match(void *vdata)
{
	struct PropMatch *prop_match = vdata;

	if (prop_match->target)
		return;

	if (strncmp(prop_match->target_name, "account:", 8))
		return;

	bool new = false;
	struct Account *target_p = account_find(prop_match->target_name + 8, true, &new);

	/* new record, and creation_ts is non-zero, so backdate the record */
	if (new && prop_match->creation_ts)
		target_p->creation_ts = prop_match->creation_ts;
	else if (prop_match->creation_ts < target_p->creation_ts)
	{
		target_p->creation_ts = prop_match->creation_ts;
		propertyset_clear(&target_p->prop_list);
	}

	if (target_p == NULL)
	{
		sendto_one_numeric(prop_match->source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), prop_match->target_name);
		return;
	}

	if (prop_match->match_request == PROP_WRITE)
		prop_match->match_grant =
			can_write_to_account_property(prop_match->source_p, target_p, prop_match->key) ? PROP_WRITE : PROP_READ;
	else
		prop_match->match_grant = prop_match->match_request;

	prop_match->redistribute = true;
	prop_match->creation_ts = target_p->creation_ts;
	prop_match->prop_list = &target_p->prop_list;
	prop_match->target = target_p;
}

static void
h_ircx_account_login(void *vdata)
{
	hook_data_account_login *hdata = vdata;

	/* remote users cannot really ever hit this code path, but its good to check */
	if (!MyClient(hdata->source_p) || !IsPerson(hdata->source_p))
		return;

	struct Client *client_p = hdata->source_p;
	rb_strlcpy(client_p->user->suser, hdata->account_name, sizeof client_p->user->suser);

	sendto_server(NULL, NULL, CAP_ENCAP, NOCAPS, ":%s ENCAP * LOGIN %s",
		      use_id(client_p), client_p->user->suser);
}

DECLARE_MODULE_AV2(ircx_prop_entity_account, NULL, NULL, NULL, ircx_prop_entity_account_hlist, ircx_prop_entity_account_hfnlist, NULL, NULL, ircx_prop_entity_account_desc);
