/*
 * Copyright (c) 2019 Aaron M.D. Jones
 * Copyright (c) 2021 Ariadne Conill
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * This software is provided 'as is' and without any warranty, express or
 * implied.  In no event shall the authors be liable for any damages arising
 * from the use of this software.
 */

#include "stdinc.h"
#include "client.h"
#include "sasl.h"
#include "hash.h"
#include "send.h"
#include "msg.h"
#include "modules.h"
#include "numeric.h"
#include "reject.h"
#include "s_serv.h"
#include "s_stats.h"
#include "string.h"
#include "s_newconf.h"
#include "s_conf.h"

#ifndef MINIMUM
#  define MINIMUM(a, b) (((a) < (b)) ? (a) : (b))
#endif

static const char sasl_desc[] = "Provides SASL authentication support";

static void m_authenticate(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message authenticate_msgtab = {
	"AUTHENTICATE", 0, 0, 0, 0,
	{{m_authenticate, 2}, {m_authenticate, 2}, mg_ignore, mg_ignore, mg_ignore, {m_authenticate, 2}}
};

mapi_clist_av1 sasl_clist[] = { &authenticate_msgtab, NULL };

static struct ClientCapability capdata_sasl = {
	.flags = CLICAP_FLAGS_STICKY,
};

static unsigned int CLICAP_SASL = 0;

mapi_cap_list_av2 sasl_cap_list[] = {
	{ MAPI_CAP_CLIENT, "sasl", &capdata_sasl, &CLICAP_SASL },
	{ 0, NULL, NULL, NULL },
};

static int h_sasl_start;

mapi_hlist_av1 sasl_hlist[] = {
	{ "sasl_start", &h_sasl_start },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(sasl_core, NULL, NULL, sasl_clist, sasl_hlist, NULL, sasl_cap_list, NULL, sasl_desc);

static void
end_session(struct Client *client_p)
{
	if (!MyClient(client_p))
		return;

	rb_free(client_p->localClient->sess);
	client_p->localClient->sess = NULL;
}

static void
m_authenticate(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if (!IsCapable(source_p, CLICAP_SASL))
		return;

	if (*parv[1] == ':' || strchr(parv[1], ' '))
	{
		exit_client(client_p, client_p, client_p, "Malformed AUTHENTICATE");
		return;
	}

	if(strlen(parv[1]) > 400)
	{
		sendto_one(source_p, form_str(ERR_SASLTOOLONG), me.name, EmptyString(source_p->name) ? "*" : source_p->name);
		return;
	}

	if (source_p->localClient->sess == NULL)
	{
		struct sasl_hook_data hdata = {
			.client = source_p,
			.name = parv[1],
		};

		call_hook(h_sasl_start, &hdata);

		/* we should have gotten a mechanism back in hdata.mech, if we didn't, fail the session */
		if (hdata.mech == NULL)
		{
			sendto_one(source_p, form_str(ERR_SASLFAIL), me.name, EmptyString(source_p->name) ? "*" : source_p->name);
			return;
		}

		source_p->localClient->sess = rb_malloc(sizeof(struct sasl_session));
		source_p->localClient->sess->mech = hdata.mech;
	}

	struct sasl_session *sess = source_p->localClient->sess;

	if (sess->mech == NULL)
	{
		end_session(source_p);

		sendto_one(source_p, form_str(ERR_SASLFAIL), me.name, EmptyString(source_p->name) ? "*" : source_p->name);
		return;
	}

	struct sasl_output_buf outbuf;
	enum sasl_mechanism_result ret;

	if (!sess->continuing)
		ret = sess->mech->start_fn(sess, &outbuf);
	else
	{
		int declen;
		unsigned char *decbuf = rb_base64_decode((const unsigned char *) parv[1], strlen(parv[1]), &declen);

		const struct sasl_input_buf inbuf = {
			.buf = decbuf,
			.len = declen,
		};

		ret = sess->mech->step_fn(sess, &inbuf, &outbuf);
	}

	unsigned char *encbuf = rb_base64_encode(outbuf.buf, outbuf.len);
	unsigned char *encbufptr = encbuf;
	size_t enclen = strlen((char *) encbuf);
	size_t encbuflast = SASL_MAXPACKET_B64;

	switch (ret)
	{
	case SASL_MRESULT_ERROR:
	case SASL_MRESULT_FAILURE:
		end_session(source_p);

		sendto_one(source_p, form_str(ERR_SASLFAIL), me.name, EmptyString(source_p->name) ? "*" : source_p->name);
		return;
	case SASL_MRESULT_CONTINUE:
		for (size_t encbufrem = enclen; encbufrem != 0; )
		{
			unsigned char encbufpart[SASL_MAXPACKET_B64];
			const size_t encbufptrlen = MINIMUM(SASL_MAXPACKET_B64, encbufrem);

			(void) memset(encbufpart, 0x00, sizeof encbufpart);
			(void) memcpy(encbufpart, encbufptr, encbufptrlen);

			sendto_one(source_p, "AUTHENTICATE %s", encbufpart);

			encbufptr += encbufptrlen;
			encbufrem -= encbufptrlen;
			encbuflast = encbufptrlen;
		}

		if (encbuflast == SASL_MAXPACKET_B64)
			sendto_one(source_p, "AUTHENTICATE +");

		break;
	case SASL_MRESULT_SUCCESS:
		end_session(source_p);

		sendto_one(source_p, form_str(RPL_SASLSUCCESS), me.name, EmptyString(source_p->name) ? "*" : source_p->name);
		break;
	}
}