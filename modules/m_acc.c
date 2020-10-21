/*
 * modules/m_acc.c
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

static const char acc_desc[] = "Provides ACC command and ophion.dev/acc capability";

unsigned int CLICAP_ACC;

mapi_cap_list_av2 acc_cap_list[] = {
	{ MAPI_CAP_CLIENT, "ophion.dev/acc", NULL, &CLICAP_ACC },
	{ 0, NULL, NULL, NULL },
};

static void m_acc(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message acc_msgtab = {
	"ACC", 0, 0, 0, 0,
	{mg_unreg, {m_acc, 2}, mg_ignore, mg_ignore, mg_ignore, {m_acc, 2}}
};

mapi_clist_av1 acc_clist[] = {
	&acc_msgtab, NULL
};

DECLARE_MODULE_AV2(acc, NULL, NULL, acc_clist, NULL, NULL, acc_cap_list, NULL, acc_desc);

struct acc_cmd {
	const char *cmd;
	void (*func)(struct Client *source_p, int parc, const char *parv[]);
};

static void m_acc_ls(struct Client *source_p, int parc, const char *parv[]);
static void m_acc_register(struct Client *source_p, int parc, const char *parv[]);

static struct acc_cmd acc_cmdlist[] = {
	/* This list *MUST* be in alphabetical order */
	{"LS", m_acc_ls},
	{"REGISTER", m_acc_register},
};

/*
 * ACC LS - list available properties of the authentication layer.
 * Parameters: takes no parameters
 */
static void
m_acc_ls(struct Client *source_p, int parc, const char *parv[])
{
	char acc_subcmd_buf[BUFSIZE] = {};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(acc_cmdlist); i++)
	{
		rb_strlcat(acc_subcmd_buf, acc_cmdlist[i].cmd, sizeof acc_subcmd_buf);
		rb_strlcat(acc_subcmd_buf, " ", sizeof acc_subcmd_buf);
	}

	sendto_one(source_p, ":%s ACC LS * SUBCOMMANDS :%s", me.name, acc_subcmd_buf);
	sendto_one(source_p, ":%s ACC LS CREDTYPES :passphrase", me.name);
}

/*
 * ACC REGISTER - register an account with the authentication layer.
 * Parameters:
 *   parv[1] = "REGISTER"
 *   parv[2] = account name
 *   parv[3] = callback URI (ignored)
 *   parv[4] = credential type (must be a recognized credential -- passphrase or certfp)
 *   parv[5] = credential (or unspecified for certfp)
 */
static void
m_acc_register(struct Client *source_p, int parc, const char *parv[])
{
	if (!irccmp(parv[4], "passphrase"))
	{
		sendto_one(source_p, ":%s FAIL ACC REG_INVALID_CRED_TYPE %s %s :Credential type is invalid",
			   me.name, parv[2], parv[4]);
		return;
	}

	bool new_account = false;
	struct Account *account_p = account_find(parv[2], true, &new_account);

	/* account already exists? */
	if (account_p != NULL && !new_account)
	{
		sendto_one(source_p, ":%s FAIL ACC ACCOUNT_ALREADY_EXISTS %s :Account already exists",
			   me.name, parv[2]);
		return;
	}

	struct Property *prop = propertyset_add(&account_p->prop_list, "passphrase", parv[5], &me);

	sendto_server(NULL, NULL, CAP_TS6, NOCAPS, ":%s TPROP account:%s %ld %ld %s :%s",
		      use_id(&me), account_p->name, account_p->creation_ts, prop->set_at, prop->name, prop->value);

	sendto_one_numeric(source_p, RPL_REG_SUCCESS, form_str(RPL_REG_SUCCESS), parv[2]);

	/* XXX: log user in */
}

static int
acc_cmd_search(const char *command, struct acc_cmd *entry)
{
	return irccmp(command, entry->cmd);
}

static void
m_acc(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct acc_cmd *cmd;

	if(!(cmd = bsearch(parv[1], acc_cmdlist,
				sizeof(acc_cmdlist) / sizeof(struct acc_cmd),
				sizeof(struct acc_cmd), (void *) acc_cmd_search)))
	{
		sendto_one(source_p, ":%s FAIL ACC INVALID_ACC_SUBCMD :Invalid ACC subcommand", me.name);
		return;
	}

	(cmd->func)(source_p, parc, parv);
}
