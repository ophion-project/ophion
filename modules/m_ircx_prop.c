/*
 * modules/m_ircx_prop.c
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

static const char ircx_prop_desc[] = "Provides IRCX PROP command";

static void m_prop(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message prop_msgtab = {
	"PROP", 0, 0, 0, 0,
	{mg_ignore, {m_prop, 2}, {m_prop, 2}, mg_ignore, mg_ignore, {m_prop, 2}}
};

/* :source TPROP target creationTS updateTS propName [:propValue] */
static void ms_tprop(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message tprop_msgtab = {
	"TPROP", 0, 0, 0, 0,
	{mg_ignore, mg_ignore, mg_ignore, {ms_tprop, 5}, mg_ignore, mg_ignore}
};

mapi_clist_av1 ircx_prop_clist[] = { &prop_msgtab, &tprop_msgtab, NULL };

static int h_prop_show;
static int h_prop_change;
static int h_prop_match;

mapi_hlist_av1 ircx_prop_hlist[] = {
	{ "prop_show", &h_prop_show },
	{ "prop_change", &h_prop_change },
	{ "prop_match", &h_prop_match },
	{ NULL, NULL }
};

static int
ircx_prop_init(void)
{
	add_isupport("MAXPROP", isupport_intptr, &ConfigChannel.max_prop);
	return 0;
}

static void
ircx_prop_deinit(void)
{
	delete_isupport("MAXPROP");
}

DECLARE_MODULE_AV2(ircx_prop, ircx_prop_init, ircx_prop_deinit, ircx_prop_clist, ircx_prop_hlist, NULL, NULL, NULL, ircx_prop_desc);

static void
handle_prop_list(const struct PropMatch *prop_match, struct Client *source_p, const char *keys, int alevel)
{
	rb_dlink_node *iter;

	RB_DLINK_FOREACH(iter, prop_match->prop_list->head)
	{
		struct Property *prop = iter->data;
		hook_data_prop_activity prop_activity;

		if (keys != NULL && rb_strcasestr(keys, prop->name) == NULL)
			continue;

		prop_activity.client = source_p;
		prop_activity.target = prop_match->target_name;
		prop_activity.prop_list = prop_match->prop_list;
		prop_activity.key = prop->name;
		prop_activity.alevel = alevel;
		prop_activity.approved = 1;
		prop_activity.target_ptr = prop_match->target;

		call_hook(h_prop_show, &prop_activity);

		if (!prop_activity.approved)
			continue;

		sendto_one_numeric(source_p, RPL_PROPLIST, form_str(RPL_PROPLIST),
			prop_match->target_name, prop->name, prop->value);
	}

	sendto_one_numeric(source_p, RPL_PROPEND, form_str(RPL_PROPEND), prop_match->target_name);
}

static void
handle_prop_upsert_or_delete(const struct PropMatch *prop_match, struct Client *source_p, const char *prop, const char *value)
{
	struct Property *property;
	hook_data_prop_activity prop_activity;

	propertyset_delete(prop_match->prop_list, prop);

	/* deletion: value is empty string */
	if (! *value)
	{
		sendto_one(source_p, ":%s!%s@%s PROP %s %s :", source_p->name, source_p->username, source_p->host,
			prop_match->target_name, prop);
		goto broadcast;
	}

	/* enforce MAXPROP on upsert */
	if (rb_dlink_list_length(prop_match->prop_list) >= ConfigChannel.max_prop)
	{
		sendto_one_numeric(source_p, ERR_PROP_TOOMANY, form_str(ERR_PROP_TOOMANY), prop_match->target_name);
		return;
	}

	property = propertyset_add(prop_match->prop_list, prop, value, source_p);

	sendto_one(source_p, ":%s!%s@%s PROP %s %s :%s", source_p->name, source_p->username, source_p->host,
		prop_match->target_name, property->name, property->value);

	// XXX: enforce CAP_IRCX
	// XXX: rewrite target to UID if needed

	// don't redistribute updates for local channels
	if (!prop_match->redistribute)
		goto broadcast;

	if (IsChanPrefix(*prop_match->target_name) && *prop_match->target_name == '&')
		goto broadcast;

	sendto_server(source_p, NULL, CAP_TS6, NOCAPS,
			":%s PROP %s %s :%s",
			use_id(source_p), prop_match->target_name,
			property->name, property->value);

	prop = property->name;
	value = property->value;

	// broadcast the property change to local members
broadcast:
	prop_activity.client = source_p;
	prop_activity.target = prop_match->target_name;
	prop_activity.prop_list = prop_match->prop_list;
	prop_activity.key = prop;
	prop_activity.value = value;
	prop_activity.alevel = CHFL_ADMIN;
	prop_activity.approved = 1;
	prop_activity.target_ptr = prop_match->target;

	call_hook(h_prop_change, &prop_activity);
}

/*
 * LIST: PROP target [filters] (parc <= 3)
 * SET: PROP target key :value (parc == 4)
 * DELETE: PROP target key : (parc == 4)
 */
static void
m_prop(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct PropMatch prop_match = {
		.target_name = parv[1],
		.match_request = parc <= 3 ? PROP_READ : PROP_WRITE,
		.source_p = source_p,
		.key = parv[2],
		.alevel = CHFL_PEON,
	};

	call_hook(h_prop_match, &prop_match);

	if (prop_match.prop_list == NULL)
		return;

	switch (parc)
	{
	case 2:
		handle_prop_list(&prop_match, source_p, NULL, prop_match.alevel);
		break;

	case 3:
		handle_prop_list(&prop_match, source_p, parv[2], prop_match.alevel);
		break;

	case 4:
		if (prop_match.match_grant != PROP_WRITE && MyClient(source_p))
		{
			sendto_one_numeric(source_p, ERR_PROPDENIED, form_str(ERR_PROPDENIED), parv[1]);
			return;
		}

		handle_prop_upsert_or_delete(&prop_match, source_p, parv[2], parv[3]);
		break;

	default:
		break;
	}
}

/*
 * TPROP
 *
 * parv[1] = target
 * parv[2] = creation TS
 * parv[3] = modification TS
 * parv[4] = key
 * parv[5] = value
 */
static void
ms_tprop(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct PropMatch prop_match = {
		.target_name = parv[1],
		.match_request = PROP_WRITE,
		.source_p = source_p,
		.key = parv[4],
		.alevel = CHFL_PEON,
	};

	time_t creation_ts = atol(parv[2]);
	time_t update_ts = atol(parv[3]);
	hook_data_prop_activity prop_activity;

	call_hook(h_prop_match, &prop_match);

	if (prop_match.prop_list == NULL)
		return;

	if (creation_ts > prop_match.creation_ts)
		return;

	/* do the upsert */
	struct Property *prop = propertyset_add(prop_match.prop_list, parv[4], parv[5], source_p);
	prop->set_at = update_ts;

	sendto_server(source_p, NULL, CAP_TS6, NOCAPS,
		":%s TPROP %s %ld %ld %s :%s",
		use_id(&me), parv[1], creation_ts, prop->set_at, prop->name, prop->value);

	// broadcast the property change to local members
	prop_activity.client = &me;
	prop_activity.target = prop_match.target_name;
	prop_activity.prop_list = prop_match.prop_list;
	prop_activity.key = prop->name;
	prop_activity.value = prop->value;
	prop_activity.alevel = CHFL_ADMIN;
	prop_activity.approved = 1;
	prop_activity.target_ptr = prop_match.target;

	call_hook(h_prop_change, &prop_activity);
}
