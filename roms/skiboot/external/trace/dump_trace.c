// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Dump the content of an OPAL trace
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <trace.h>
#include <err.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "../../ccan/endian/endian.h"
#include "../../ccan/short_types/short_types.h"
#include "../../ccan/heap/heap.h"
#include "trace.h"


struct trace_entry {
	int index;
	union trace t;
	struct list_node link;
};

static int follow;
static long poll_msecs;

static void *ezalloc(size_t size)
{
	void *p;

	p = calloc(size, 1);
	if (!p)
		err(1, "Allocating memory");
	return p;
}

#define TB_HZ 512000000ul

static void display_header(const struct trace_hdr *h)
{
	static u64 prev_ts;
	u64 ts = be64_to_cpu(h->timestamp);

	printf("[%5lu.%09lu,%d] (+%8lx) [%03x] : ",
		ts / TB_HZ, /* match the usual skiboot log header */
		ts % TB_HZ,
		h->type, /* hey why not */
		prev_ts ? (ts - prev_ts) % TB_HZ : 0, be16_to_cpu(h->cpu));
	prev_ts = ts;
}

static void dump_fsp_event(struct trace_fsp_event *t)
{
	printf("FSP_EVT [st=%d] ", be16_to_cpu(t->fsp_state));

	switch(be16_to_cpu(t->event)) {
	case TRACE_FSP_EVT_LINK_DOWN:
		printf("LINK DOWN");
		break;
	case TRACE_FSP_EVT_DISR_CHG:
		printf("DISR CHANGE (0x%08x)", be32_to_cpu(t->data[0]));
		break;
	case TRACE_FSP_EVT_SOFT_RR:
		printf("SOFT R&R (DISR=0x%08x)", be32_to_cpu(t->data[0]));
		break;
	case TRACE_FSP_EVT_RR_COMPL:
		printf("R&R COMPLETE");
		break;
	case TRACE_FSP_EVT_HDES_CHG:
		printf("HDES CHANGE (0x%08x)", be32_to_cpu(t->data[0]));
		break;
	case TRACE_FSP_EVT_POLL_IRQ:
		printf("%s HDIR=%08x CTL=%08x PSI_IRQ=%d",
		       t->data[0] ? "IRQ " : "POLL", be32_to_cpu(t->data[1]),
		       be32_to_cpu(t->data[2]), be32_to_cpu(t->data[3]));
		break;
	default:
		printf("Unknown %d (d: %08x %08x %08x %08x)",
		       be16_to_cpu(t->event), be32_to_cpu(t->data[0]),
		       be32_to_cpu(t->data[1]), be32_to_cpu(t->data[2]),
		       be32_to_cpu(t->data[3]));
	}
	printf("\n");
}

static void dump_opal_call(struct trace_opal *t)
{
	unsigned int i, n;

	printf("OPAL CALL %"PRIu64, be64_to_cpu(t->token));
	printf(" LR=0x%016"PRIx64" SP=0x%016"PRIx64,
	       be64_to_cpu(t->lr), be64_to_cpu(t->sp));
	n = (t->hdr.len_div_8 * 8 - offsetof(union trace, opal.r3_to_11))
		/ sizeof(u64);
	for (i = 0; i < n; i++)
		printf(" R%u=0x%016"PRIx64,
		       i+3, be64_to_cpu(t->r3_to_11[i]));
	printf("\n");
}

static void dump_fsp_msg(struct trace_fsp_msg *t)
{
	unsigned int i;

	printf("FSP_MSG: CMD %u SEQ %u MOD %u SUB %u DLEN %u %s [",
	       be32_to_cpu(t->word0) & 0xFFFF,
	       be32_to_cpu(t->word0) >> 16,
	       be32_to_cpu(t->word1) >> 8,
	       be32_to_cpu(t->word1) & 0xFF,
	       t->dlen,
	       t->dir == TRACE_FSP_MSG_IN ? "IN" :
	       (t->dir == TRACE_FSP_MSG_OUT ? "OUT" : "UNKNOWN"));

	for (i = 0; i < t->dlen; i++) 
		printf("%s%02x", i ? " " : "", t->data[i]);
	printf("]\n");
}

static void dump_uart(struct trace_uart *t)
{
	switch(t->ctx) {
	case TRACE_UART_CTX_IRQ:
		printf(": IRQ  IRQEN=%d IN_CNT=%d\n",
		       !t->irq_state, be16_to_cpu(t->in_count));
		break;
	case TRACE_UART_CTX_POLL:
		printf(": POLL IRQEN=%d IN_CNT=%d\n",
		       !t->irq_state, be16_to_cpu(t->in_count));
		break;
	case TRACE_UART_CTX_READ:
		printf(": READ IRQEN=%d IN_CNT=%d READ=%d\n",
		       !t->irq_state, be16_to_cpu(t->in_count), t->cnt);
		break;
	default:
		printf(": ???? IRQEN=%d IN_CNT=%d\n",
		       !t->irq_state, be16_to_cpu(t->in_count));
		break;
	}
}

static void dump_i2c(struct trace_i2c *t)
{
	uint16_t type = be16_to_cpu(t->type);

	printf("I2C: bus: %d dev: %02x len: %x ",
			be16_to_cpu(t->bus),
			be16_to_cpu(t->i2c_addr),
			be16_to_cpu(t->size)
			);

	switch (type & 0x3) {
	case 0:
		printf("read");
		break;
	case 1:
		printf("write");
		break;
	case 2:
		printf("smbus read from %x", be16_to_cpu(t->smbus_reg));
		break;
	case 3:
		printf("smbus write to %x", be16_to_cpu(t->smbus_reg));
		break;
	default:
		printf("u wot?");
	}

	printf(", rc = %hd\n", (int16_t) be16_to_cpu(t->rc));
}

static void load_traces(struct trace_reader *trs, int count)
{
	struct trace_entry *te;
	union trace t;
	int i;

	for (i = 0; i < count; i++) {
		while (trace_get(&t, &trs[i])) {
			te = ezalloc(sizeof(struct trace_entry));
			memcpy(&te->t, &t, sizeof(union trace));
			te->index = i;
			list_add_tail(&trs[i].traces, &te->link);
		}
	}
}

static void print_trace(union trace *t)
{
	display_header(&t->hdr);
	switch (t->hdr.type) {
	case TRACE_REPEAT:
		printf("REPEATS: %u times\n",
		       be16_to_cpu(t->repeat.num));
		break;
	case TRACE_OVERFLOW:
		printf("**OVERFLOW**: %"PRIu64" bytes missed\n",
		       be64_to_cpu(t->overflow.bytes_missed));
		break;
	case TRACE_OPAL:
		dump_opal_call(&t->opal);
		break;
	case TRACE_FSP_MSG:
		dump_fsp_msg(&t->fsp_msg);
		break;
	case TRACE_FSP_EVENT:
		dump_fsp_event(&t->fsp_evt);
		break;
	case TRACE_UART:
		dump_uart(&t->uart);
		break;
	case TRACE_I2C:
		dump_i2c(&t->i2c);
		break;
	default:
		printf("UNKNOWN(%u) CPU %u length %u\n",
		       t->hdr.type, be16_to_cpu(t->hdr.cpu),
		       t->hdr.len_div_8 * 8);
	}
}

/* Gives a min heap */
bool earlier_entry(const void *va, const void *vb)
{
	struct trace_entry *a, *b;

	a = (struct trace_entry *) va;
	b = (struct trace_entry *) vb;

	if (!a)
		return false;
	if (!b)
		return true;
	return be64_to_cpu(a->t.hdr.timestamp) < be64_to_cpu(b->t.hdr.timestamp);
}

static void display_traces(struct trace_reader *trs, int count)
{
	struct trace_entry *current, *next;
	struct heap *h;
	int i;

	h = heap_init(earlier_entry);
	if (!h)
		err(1, "Allocating memory");

	for (i = 0; i < count; i++) {
		current = list_pop(&trs[i].traces, struct trace_entry, link);
		/* no need to add empty ones */
		if (current)
			heap_push(h, current);
	}

	while (h->len) {
		current = heap_pop(h);
		if (!current)
			break;

		print_trace(&current->t);

		next = list_pop(&trs[current->index].traces, struct trace_entry,
				link);
		heap_push(h, next);
		free(current);
	}
	heap_free(h);
}


/* Can't poll for 0 msec, so use 0 to signify failure */
static long get_mseconds(char *s)
{
	char *end;
	long ms;

	errno = 0;
	ms = strtol(s, &end, 10);
	if (errno || *end || ms < 0)
		return 0;
	return ms;
}

static void usage(void)
{
	errx(1, "Usage: dump_trace [-f [-s msecs]] file...");
}

int main(int argc, char *argv[])
{
	struct trace_reader *trs;
	struct trace_info *ti;
	bool no_mmap = false;
	struct stat sb;
	int fd, opt, i;

	poll_msecs = 1000;
	while ((opt = getopt(argc, argv, "fs:")) != -1) {
		switch (opt) {
		case 'f':
			follow++;
			break;
		case 's':
			poll_msecs = get_mseconds(optarg);
			if (follow && poll_msecs)
				break;
			/* fallthru */
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	trs = ezalloc(sizeof(struct trace_reader) * argc);

	for (i =  0; i < argc; i++) {
		fd = open(argv[i], O_RDONLY);
		if (fd < 0)
			err(1, "Opening %s", argv[i]);

		if (fstat(fd, &sb) < 0)
			err(1, "Stating %s", argv[1]);

		ti = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (ti == MAP_FAILED) {
			no_mmap = true;

			ti = ezalloc(sb.st_size);
			if (!ti)
				err(1, "allocating memory for %s", argv[i]);

			if (read(fd, ti, sb.st_size) == -1)
				err(1, "reading from %s", argv[i]);
		}

		trs[i].tb = &ti->tb;
		list_head_init(&trs[i].traces);
	}

	if (no_mmap) {
		fprintf(stderr, "disabling follow mode: can't mmap() OPAL export files\n");
		follow = 0;
	}

	do {
		load_traces(trs, argc);
		display_traces(trs, argc);
		if (follow)
			usleep(poll_msecs * 1000);
	} while (follow);

	return 0;
}
