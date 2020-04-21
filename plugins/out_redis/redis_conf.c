/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_kv.h>

#include "redis.h"
#include "redis_conf.h"

struct flb_out_redis *flb_redis_conf_create(struct flb_output_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    const char *tmp;
    struct flb_out_redis *ctx = NULL;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_out_redis));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    ctx->ins = ins;

    /* Set default network configuration if not set */
    flb_output_net_default("127.0.0.1", 6379, ins);

    tmp = flb_output_get_property("key", ins);
    if (tmp) {
        flb_sds_copy(ctx->key, tmp, strlen(tmp));
    } else {
        ctx->key = flb_sds_create("default_key");
    }


    printf("(1) host ptr: %p\n", ctx->host);
    printf("(1) key ptr: %p\n", ctx->key);

    /* Output format */
    ctx->out_format = FLB_PACK_JSON_FORMAT_NONE;
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        ret = flb_pack_to_json_format_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "unrecognized 'format' option '%s'. "
                          "Using 'msgpack'", tmp);
        }
        else {
            ctx->out_format = ret;
        }
    }

    /* Date format for JSON output */
    ctx->json_date_format = FLB_PACK_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "unrecognized 'json_date_format' option '%s'. "
                          "Using 'double'", tmp);
        }
        else {
            ctx->json_date_format = ret;
        }
    }

    /* Date key for JSON output */
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp) {
        ctx->json_date_key = flb_sds_create(tmp);
    }
    else {
        ctx->json_date_key = flb_sds_create("date");
    }

    ctx->host = ins->host.name;
    ctx->port = ins->host.port;

    printf("host: %s\n", ctx->host);
    printf("(1) key ptr: %p\n", ctx->key);

    ctx->redis_context = redisConnect(ins->host.name, ins->host.port);
    if (!ctx->redis_context) {
        flb_plg_error(ctx->ins, "could not create redis context got NULL pointer");
        flb_free(ctx);
        return NULL;
    }
    if (ctx->redis_context->err) {
        flb_plg_error(ctx->ins, "could not create redis context");
        flb_free(ctx);
        return NULL;
    }

    return ctx;
}

void flb_redis_conf_destroy(struct flb_out_redis *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->key) {
        flb_sds_destroy(ctx->key);
    }

    if (ctx->json_date_key) {
        flb_sds_destroy(ctx->json_date_key);
    }
    flb_free(ctx);
    ctx = NULL;
}
