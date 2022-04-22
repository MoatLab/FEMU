/*
 * QMP interface for background jobs
 *
 * Copyright (c) 2011 IBM Corp.
 * Copyright (c) 2012, 2018 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/job.h"
#include "qapi/qapi-commands-job.h"
#include "qapi/error.h"
#include "trace/trace-root.h"

/* Get a job using its ID and acquire its AioContext */
static Job *find_job(const char *id, AioContext **aio_context, Error **errp)
{
    Job *job;

    *aio_context = NULL;

    job = job_get(id);
    if (!job) {
        error_setg(errp, "Job not found");
        return NULL;
    }

    *aio_context = job->aio_context;
    aio_context_acquire(*aio_context);

    return job;
}

void qmp_job_cancel(const char *id, Error **errp)
{
    AioContext *aio_context;
    Job *job = find_job(id, &aio_context, errp);

    if (!job) {
        return;
    }

    trace_qmp_job_cancel(job);
    job_user_cancel(job, true, errp);
    aio_context_release(aio_context);
}

void qmp_job_pause(const char *id, Error **errp)
{
    AioContext *aio_context;
    Job *job = find_job(id, &aio_context, errp);

    if (!job) {
        return;
    }

    trace_qmp_job_pause(job);
    job_user_pause(job, errp);
    aio_context_release(aio_context);
}

void qmp_job_resume(const char *id, Error **errp)
{
    AioContext *aio_context;
    Job *job = find_job(id, &aio_context, errp);

    if (!job) {
        return;
    }

    trace_qmp_job_resume(job);
    job_user_resume(job, errp);
    aio_context_release(aio_context);
}

void qmp_job_complete(const char *id, Error **errp)
{
    AioContext *aio_context;
    Job *job = find_job(id, &aio_context, errp);

    if (!job) {
        return;
    }

    trace_qmp_job_complete(job);
    job_complete(job, errp);
    aio_context_release(aio_context);
}

void qmp_job_finalize(const char *id, Error **errp)
{
    AioContext *aio_context;
    Job *job = find_job(id, &aio_context, errp);

    if (!job) {
        return;
    }

    trace_qmp_job_finalize(job);
    job_ref(job);
    job_finalize(job, errp);

    /*
     * Job's context might have changed via job_finalize (and job_txn_apply
     * automatically acquires the new one), so make sure we release the correct
     * one.
     */
    aio_context = job->aio_context;
    job_unref(job);
    aio_context_release(aio_context);
}

void qmp_job_dismiss(const char *id, Error **errp)
{
    AioContext *aio_context;
    Job *job = find_job(id, &aio_context, errp);

    if (!job) {
        return;
    }

    trace_qmp_job_dismiss(job);
    job_dismiss(&job, errp);
    aio_context_release(aio_context);
}

static JobInfo *job_query_single(Job *job, Error **errp)
{
    JobInfo *info;
    uint64_t progress_current;
    uint64_t progress_total;

    assert(!job_is_internal(job));
    progress_get_snapshot(&job->progress, &progress_current,
                          &progress_total);

    info = g_new(JobInfo, 1);
    *info = (JobInfo) {
        .id                 = g_strdup(job->id),
        .type               = job_type(job),
        .status             = job->status,
        .current_progress   = progress_current,
        .total_progress     = progress_total,
        .has_error          = !!job->err,
        .error              = job->err ? \
                              g_strdup(error_get_pretty(job->err)) : NULL,
    };

    return info;
}

JobInfoList *qmp_query_jobs(Error **errp)
{
    JobInfoList *head = NULL, **tail = &head;
    Job *job;

    for (job = job_next(NULL); job; job = job_next(job)) {
        JobInfo *value;
        AioContext *aio_context;

        if (job_is_internal(job)) {
            continue;
        }
        aio_context = job->aio_context;
        aio_context_acquire(aio_context);
        value = job_query_single(job, errp);
        aio_context_release(aio_context);
        if (!value) {
            qapi_free_JobInfoList(head);
            return NULL;
        }
        QAPI_LIST_APPEND(tail, value);
    }

    return head;
}
