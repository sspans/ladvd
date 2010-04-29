/*
 * $Id$
 *
 * Copyright (c) 2008, 2009
 *      Sten Spans <sten@blinkenlights.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _cli_h
#define _cli_h

struct mode {
    void (*init) ();
    void (*write) (struct master_msg *, const uint16_t);
    void (*dispatch) ();
};

void batch_write(struct master_msg *msg, const uint16_t);
void cli_header();
void cli_write(struct master_msg *msg, const uint16_t);
void debug_header();
void debug_write(struct master_msg *msg, const uint16_t);

#if HAVE_EVHTTP_H
void http_connect();
void http_request(struct master_msg *msg, const uint16_t);
void http_reply(struct evhttp_request *req, void *arg);
void http_dispatch();
#endif /* HAVE_EVHTTP_H */

static void usage() __noreturn;

#endif /* _cli_h */
