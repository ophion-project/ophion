/*
 * modules/m_ircx_prop_entity_channel.c
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

static const char ircx_prop_entity_channel_desc[] = "Provides IRCX PROP support for channels";

static int h_prop_chan_write;

mapi_hlist_av1 ircx_prop_entity_channel_hlist[] = {
	{ "prop_chan_write", &h_prop_chan_write },
	{ NULL, NULL }
};

static void h_prop_burst_channel(void *);
static void h_prop_channel_lowerts(void *);
static void h_prop_match(void *);

mapi_hfn_list_av1 ircx_prop_entity_channel_hfnlist[] = {
	{ "burst_channel", (hookfn) h_prop_burst_channel },
	{ "channel_lowerts", (hookfn) h_prop_channel_lowerts },
	{ "prop_match", (hookfn) h_prop_match, HOOK_LOWEST },
	{ NULL, NULL }
};

static bool
can_write_to_channel_property(struct Client *source_p, struct Channel *chptr, const char *key, int alevel)
{
	hook_data_prop_activity prop_activity;

	prop_activity.client = source_p;
	prop_activity.target = chptr->chname;
	prop_activity.prop_list = &chptr->prop_list;
	prop_activity.key = key;
	prop_activity.alevel = alevel;
	prop_activity.approved = alevel >= CHFL_CHANOP;
	prop_activity.target_ptr = chptr;

	call_hook(h_prop_chan_write, &prop_activity);

	return prop_activity.approved;
}

static void
h_prop_channel_lowerts(void *vdata)
{
	hook_data_channel *hchaninfo = vdata;
	struct Channel *chptr = hchaninfo->chptr;

	propertyset_clear(&chptr->prop_list);
}

static void
h_prop_match(void *vdata)
{
	struct PropMatch *prop_match = vdata;

	if (!IsChanPrefix(*prop_match->target_name))
		return;

	struct Channel *chan = find_channel(prop_match->target_name);
	struct membership *msptr = find_channel_membership(chan, prop_match->source_p);

	if (chan == NULL)
	{
		sendto_one_numeric(prop_match->source_p, ERR_NOSUCHCHANNEL, form_str(ERR_NOSUCHCHANNEL), prop_match->target_name);
		return;
	}

	if (msptr != NULL)
		prop_match->alevel = get_channel_access(prop_match->source_p, chan, msptr, MODE_ADD, NULL);

	if (prop_match->match_request == PROP_WRITE)
	{
		if (!MyClient(prop_match->source_p))
			prop_match->match_grant = PROP_WRITE;
		else
			prop_match->match_grant =
				can_write_to_channel_property(prop_match->source_p, chan, prop_match->key, prop_match->alevel) ? PROP_WRITE : PROP_READ;
	}
	else
		prop_match->match_grant = prop_match->match_request;

	prop_match->redistribute = *prop_match->target_name != '&';
}

static void
h_prop_burst_channel(void *vdata)
{
	hook_data_channel *hchaninfo = vdata;
	struct Channel *chptr = hchaninfo->chptr;
	struct Client *client_p = hchaninfo->client;
	rb_dlink_node *it;

	RB_DLINK_FOREACH(it, chptr->prop_list.head)
	{
		struct Property *prop = it->data;

		/* :source TPROP target creationTS updateTS propName [:propValue] */
		sendto_one(client_p, ":%s TPROP %s %ld %ld %s :%s",
			use_id(&me), chptr->chname, chptr->channelts, prop->set_at, prop->name, prop->value);
	}
}

DECLARE_MODULE_AV2(ircx_prop_entity_channel, NULL, NULL, NULL, ircx_prop_entity_channel_hlist, ircx_prop_entity_channel_hfnlist, NULL, NULL, ircx_prop_entity_channel_desc);
