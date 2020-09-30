/*
 * Copyright (c) 2005 William Pitcock <nenolod -at- nenolod.net>
 * and Jilles Tjoelker <jilles -at- stack.nl>
 * All rights reserved.
 *
 * Redistribution in both source and binary forms are permitted
 * provided that the above copyright notice remains unchanged.
 *
 * m_chghost.c: A module for handling spoofing dynamically.
 */

#include "stdinc.h"
#include "send.h"
#include "channel.h"
#include "client.h"
#include "defaults.h"
#include "ircd.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_serv.h"
#include "s_user.h"
#include "hash.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "whowas.h"
#include "monitor.h"

static const char chghost_desc[] = "Provides commands used to change and retrieve client hostnames";

static void me_realhost(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_chghost(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void me_chghost(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void mo_chghost(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message realhost_msgtab = {
	"REALHOST", 0, 0, 0, 0,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_realhost, 2}, mg_ignore}
};

struct Message chghost_msgtab = {
	"CHGHOST", 0, 0, 0, 0,
	{mg_ignore, mg_not_oper, {ms_chghost, 3}, {ms_chghost, 3}, {me_chghost, 3}, {mo_chghost, 3}}
};

mapi_clist_av1 chghost_clist[] = { &chghost_msgtab, &realhost_msgtab, NULL };

DECLARE_MODULE_AV2(chghost, NULL, NULL, chghost_clist, NULL, NULL, NULL, NULL, chghost_desc);

/* clean_host()
 *
 * input	- host to check
 * output	- false if erroneous, else true
 * side effects -
 */
static bool
clean_host(const char *host)
{
	int len = 0;
	const char *last_slash = 0;

	if (*host == '\0' || *host == ':')
		return false;

	for(; *host; host++)
	{
		len++;

		if(!IsHostChar(*host))
			return false;
		if(*host == '/')
			last_slash = host;
	}

	if(len > HOSTLEN)
		return false;

	if(last_slash && IsDigit(last_slash[1]))
		return false;

	return true;
}

/*
 * me_realhost
 * parv[1] = real host
 *
 * Yes this contains a little race condition if someone does a whois
 * in between the UID and REALHOST and use_whois_actually is enabled.
 * I don't think that's a big problem as the whole thing is a
 * race condition.
 */
static void
me_realhost(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	if (!IsPerson(source_p))
		return;

	del_from_hostname_hash(source_p->orighost, source_p);
	rb_strlcpy(source_p->orighost, parv[1], sizeof source_p->orighost);
	if (irccmp(source_p->host, source_p->orighost))
		SetDynSpoof(source_p);
	else
		ClearDynSpoof(source_p);
	add_to_hostname_hash(source_p->orighost, source_p);
}

static bool
do_chghost(struct Client *source_p, struct Client *target_p,
		const char *newhost, int is_encap)
{
	if (!clean_host(newhost))
	{
		sendto_realops_snomask(SNO_GENERAL, is_encap ? L_ALL : L_NETWIDE, "%s attempted to change hostname for %s to %s (invalid)",
				IsServer(source_p) ? source_p->name : get_oper_name(source_p),
				target_p->name, newhost);
		/* sending this remotely may disclose important
		 * routing information -- jilles */
		if (is_encap ? MyClient(target_p) : !ConfigServerHide.flatten_links)
			sendto_one_notice(target_p, ":*** Notice -- %s attempted to change your hostname to %s (invalid)",
					source_p->name, newhost);
		return false;
	}
	change_nick_user_host(target_p, target_p->name, target_p->username, newhost, 0, "Changing host");
	if (irccmp(target_p->host, target_p->orighost))
	{
		SetDynSpoof(target_p);
		if (MyClient(target_p))
			sendto_one_numeric(target_p, RPL_HOSTHIDDEN, "%s :is now your hidden host (set by %s)", target_p->host, source_p->name);
	}
	else
	{
		ClearDynSpoof(target_p);
		if (MyClient(target_p))
			sendto_one_numeric(target_p, RPL_HOSTHIDDEN, "%s :hostname reset by %s", target_p->host, source_p->name);
	}
	if (MyClient(source_p))
		sendto_one_notice(source_p, ":Changed hostname for %s to %s", target_p->name, target_p->host);
	if (!IsServer(source_p) && !IsService(source_p))
		sendto_realops_snomask(SNO_GENERAL, L_ALL, "%s changed hostname for %s to %s", get_oper_name(source_p), target_p->name, target_p->host);
	return true;
}

/*
 * ms_chghost
 * parv[1] = target
 * parv[2] = host
 */
static void
ms_chghost(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	struct Client *target_p;

	if (!(target_p = find_person(parv[1])))
		return;

	if (do_chghost(source_p, target_p, parv[2], 0))
	{
		sendto_server(client_p, NULL,
			CAP_EUID | CAP_TS6, NOCAPS, ":%s CHGHOST %s %s",
			use_id(source_p), use_id(target_p), parv[2]);
		sendto_server(client_p, NULL,
			CAP_TS6, CAP_EUID, ":%s ENCAP * CHGHOST %s :%s",
			use_id(source_p), use_id(target_p), parv[2]);
	}

	return;
}

/*
 * me_chghost
 * parv[1] = target
 * parv[2] = host
 */
static void
me_chghost(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	struct Client *target_p;

	if (!(target_p = find_person(parv[1])))
		return;

	do_chghost(source_p, target_p, parv[2], 1);
}

/*
 * mo_chghost
 * parv[1] = target
 * parv[2] = host
 */
static void
mo_chghost(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	struct Client *target_p;

	if(!IsOperAdmin(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS),
			   me.name, source_p->name, "admin");
		return;
	}

	if (!(target_p = find_named_person(parv[1])))
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK,
				form_str(ERR_NOSUCHNICK), parv[1]);
		return;
	}

	if (!clean_host(parv[2]))
	{
		sendto_one_notice(source_p, ":Hostname %s is invalid", parv[2]);
		return;
	}

	do_chghost(source_p, target_p, parv[2], 0);

	sendto_server(NULL, NULL,
		CAP_EUID | CAP_TS6, NOCAPS, ":%s CHGHOST %s %s",
		use_id(source_p), use_id(target_p), parv[2]);
	sendto_server(NULL, NULL,
		CAP_TS6, CAP_EUID, ":%s ENCAP * CHGHOST %s :%s",
		use_id(source_p), use_id(target_p), parv[2]);
}
