#include "rte_ring.h"
#include <assert.h>

typedef void (*msg_fn)(void *arg);

struct msg {
    msg_fn fn;
    void *arg;
};

static int cnt = 0;

void test_fn(void *arg)
{
    printf("Coperd,cnt=%d\n", cnt++);
}

void test_rte_ring(void)
{
#define RSZ (31)
    int i;
    struct rte_ring *r = rte_ring_create("test", RSZ + 1, 0);
    struct msg *tmsg;
    struct msg *p;

    assert(rte_ring_empty(r));

    for (i = 0; i < 7/*RSZ*/; i++) {
        tmsg = malloc(sizeof(struct msg));
        tmsg->fn = test_fn;
        tmsg->arg = NULL;
        assert(rte_ring_enqueue(r, tmsg) == 0);
    }

    //assert(rte_ring_full(r));

    while (!rte_ring_empty(r)) {
        assert(rte_ring_dequeue(r, (void *)&p) == 0);
        p->fn(p->arg);
        free(p);
    }

    assert(rte_ring_empty(r));

    rte_ring_free(r);
}

void test_femu_ring(void)
{
#define RSZ (31)
    int i;
    struct rte_ring *r = femu_ring_create(FEMU_RING_TYPE_MP_SC, RSZ + 1);
    struct msg *tmsg[2];
    struct msg *p;
    int ret;

    assert(rte_ring_empty(r));

    for (i = 0; i < 2/*RSZ*/; i++) {
        tmsg[0] = malloc(sizeof(struct msg));
        tmsg[0]->fn = test_fn;
        tmsg[0]->arg = NULL;
        tmsg[1] = malloc(sizeof(struct msg));
        tmsg[1]->fn = test_fn;
        tmsg[1]->arg = NULL;
        ret = femu_ring_enqueue(r, (void **)tmsg, 2);
        if (ret == 2) {
            printf("Coperd,%s,enqueue,ret=%d\n", __func__, ret);
        } else {
            printf("Coperd,failed to enqueue, ret=%d\n", ret);
        }
    }

    printf("Coperd,enqueued: %d\n", femu_ring_count(r));
    //assert(rte_ring_full(r));

    while (femu_ring_count(r)) {
        assert(femu_ring_dequeue(r, (void *)&p, 1) == 1);
        printf("Coperd,now: %d\n", femu_ring_count(r));
        p->fn(p->arg);
        //free(p);
    }

    //assert(rte_ring_empty(r));

    femu_ring_free(r);
}

/* Coperd: two threads working cooperatively on the ring buffer */
int main(int argc, char *argv[])
{
    //test_rte_ring();
    test_femu_ring();

    return 0;
}
