/*
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

#ifndef OPHION_SASL_H
#define OPHION_SASL_H

#include "stdinc.h"
#include "client.h"

enum sasl_mechanism_result {
	SASL_MRESULT_ERROR = 1,
	SASL_MRESULT_FAILURE = 2,
	SASL_MRESULT_CONTINUE = 3,
	SASL_MRESULT_SUCCESS = 4
};

#define SASL_MECHANISM_MAXLEN	60U
#define SASL_DECBUF_LEN		4096U
#define SASL_MAXPACKET_B64	400U

struct sasl_mechanism;

struct sasl_session {
	rb_dlink_node node;
	struct Client *client;

	const struct sasl_mechanism *mech;
	void *mechdata;

	char *buf;
	char authcid[NICKLEN + 1];
	char authzid[NICKLEN + 1];

	bool continuing;
};

struct sasl_input_buf {
	const void *buf;
	const size_t len;
};

struct sasl_output_buf {
	void *buf;
	size_t len;
};

struct sasl_mechanism {
	char name[SASL_MECHANISM_MAXLEN];
	enum sasl_mechanism_result (*start_fn)(struct sasl_session *sess, struct sasl_output_buf *outbuf);
	enum sasl_mechanism_result (*step_fn)(struct sasl_session *sess, const struct sasl_input_buf *inbuf, struct sasl_output_buf *outbuf);
	void (*finish_fn)(struct sasl_session *sess);
	bool password_based;
};

struct sasl_hook_data {
	struct Client *client;
	const char *name;
	struct sasl_mechanism *mech;
};

#endif