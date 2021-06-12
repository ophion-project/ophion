/*
 * modules/m_register.c
 * Copyright (c) 2020, 2021 Ariadne Conill <ariadne@dereferenced.org>
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

static const char register_desc[] = "Provides REGISTER command and draft/account-registration capability";

unsigned int CLICAP_REGISTER;

static const char *
register_data(struct Client *client_p)
{
	(void) client_p;

	return "custom-accountname";
}

static struct ClientCapability register_cap = {
	.data = register_data,
	.flags = CLICAP_FLAGS_STICKY,
};

mapi_cap_list_av2 register_cap_list[] = {
	{ MAPI_CAP_CLIENT, "draft/account-registration", &register_cap, &CLICAP_REGISTER },
	{ 0, NULL, NULL, NULL },
};

static void m_register(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message register_msgtab = {
	"REGISTER", 0, 0, 0, 0,
	{mg_unreg, {m_register, 2}, mg_ignore, mg_ignore, mg_ignore, {m_register, 2}}
};

mapi_clist_av1 register_clist[] = {
	&register_msgtab, NULL
};

static int h_ircx_account_login;

mapi_hlist_av1 register_hlist[] = {
	{ "ircx_account_login", &h_ircx_account_login },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(register, NULL, NULL, register_clist, register_hlist, NULL, register_cap_list, NULL, register_desc);

static char saltChars[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	/* 0 .. 63, ascii - 64 */

/* Passphrase encryption routines:
 *
 * Based on mkpasswd.c, originally by Nelson Minar (minar@reed.edu)
 * You can use this code in any way as long as these names remain.
 */
static char *
generate_poor_salt(char *salt, int length)
{
	int i;

	srand(time(NULL));
	for(i = 0; i < length; i++)
		salt[i] = saltChars[rand() % 64];

	return (salt);
}

static char *
generate_random_salt(char *salt, int length)
{
	int fd, i;

	if((fd = open("/dev/urandom", O_RDONLY)) < 0)
		return (generate_poor_salt(salt, length));

	if(read(fd, salt, (size_t)length) != length)
	{
		close(fd);
		return (generate_poor_salt(salt, length));
	}

	for(i = 0; i < length; i++)
		salt[i] = saltChars[abs(salt[i]) % 64];

	close(fd);
	return (salt);
}

static char *
make_sha512_salt(int length)
{
	static char salt[21];
	if(length > 16)
	{
		printf("SHA512 salt length too long\n");
		exit(0);
	}
	salt[0] = '$';
	salt[1] = '6';
	salt[2] = '$';
	generate_random_salt(&salt[3], length);
	salt[length + 3] = '$';
	salt[length + 4] = '\0';
	return salt;
}

/*
 * REGISTER - register an account with the authentication layer.
 * Parameters:
 *   parv[1] = account name or "*"
 *   parv[2] = email or "*" (ignored)
 *   parv[3] = credential
 */
static void
m_register(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	bool new_account = false;
	const char *accountname = *parv[1] == '*' ? client_p->name : parv[1];
	struct Account *account_p = account_find(accountname, true, &new_account);

	/* account already exists? */
	if (account_p != NULL && !new_account)
	{
		sendto_one(source_p, ":%s FAIL REGISTER ACCOUNT_EXISTS %s :Account already exists",
			   me.name, accountname);
		return;
	}

	const char *salt = make_sha512_salt(16);
	const char *crypted_passphrase = rb_crypt(parv[3], salt);

	struct Property *prop = propertyset_add(&account_p->prop_list, "passphrase", crypted_passphrase, &me);

	sendto_server(NULL, NULL, CAP_TS6, NOCAPS, ":%s TPROP account:%s %ld %ld %s :%s",
		      use_id(&me), account_p->name, account_p->creation_ts, prop->set_at, prop->name, prop->value);

	sendto_one(source_p, ":%s REGISTER SUCCESS %s :Account created successfully",
		   me.name, accountname);

	hook_data_account_login req;

	req.source_p = source_p;
	req.account_name = account_p->name;

	call_hook(h_ircx_account_login, &req);
}