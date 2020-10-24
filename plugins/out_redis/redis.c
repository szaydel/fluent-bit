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
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <msgpack.h>
#include <hiredis.h>

#include "redis.h"
#include "redis_conf.h"

// int do_redis(void) {
//     unsigned int j, isunix = 0;
//     redisContext *c;
//     redisReply *reply;
//     const char *hostname = "127.0.0.1";

//     int port = 6379;

//     struct timeval timeout = { 1, 500000 }; // 1.5 seconds
//     if (isunix) {
//         c = redisConnectUnixWithTimeout(hostname, timeout);
//     } else {
//         c = redisConnectWithTimeout(hostname, port, timeout);
//     }
//     if (c == NULL || c->err) {
//         if (c) {
//             printf("Connection error: %s\n", c->errstr);
//             redisFree(c);
//         } else {
//             printf("Connection error: can't allocate redis context\n");
//         }
//         exit(1);
//     }

//     /* PING server */
//     reply = redisCommand(c,"PING");
//     printf("PING: %s\n", reply->str);
//     freeReplyObject(reply);

//     /* Set a key */
//     reply = redisCommand(c,"SET %s %s", "foo", "hello world");
//     printf("SET: %s\n", reply->str);
//     freeReplyObject(reply);

//     /* Set a key using binary safe API */
//     reply = redisCommand(c,"SET %b %b", "bar", (size_t) 3, "hello", (size_t) 5);
//     printf("SET (binary API): %s\n", reply->str);
//     freeReplyObject(reply);

//     /* Try a GET and two INCR */
//     reply = redisCommand(c,"GET foo");
//     printf("GET foo: %s\n", reply->str);
//     freeReplyObject(reply);

//     reply = redisCommand(c,"INCR counter");
//     printf("INCR counter: %lld\n", reply->integer);
//     freeReplyObject(reply);
//     /* again ... */
//     reply = redisCommand(c,"INCR counter");
//     printf("INCR counter: %lld\n", reply->integer);
//     freeReplyObject(reply);

//     /* Create a list of numbers, from 0 to 9 */
//     reply = redisCommand(c,"DEL mylist");
//     freeReplyObject(reply);
//     for (j = 0; j < 10; j++) {
//         char buf[64];

//         snprintf(buf,64,"%u",j);
//         reply = redisCommand(c,"LPUSH mylist element-%s", buf);
//         freeReplyObject(reply);
//     }

//     /* Let's check what we have inside the list */
//     reply = redisCommand(c,"LRANGE mylist 0 -1");
//     if (reply->type == REDIS_REPLY_ARRAY) {
//         for (j = 0; j < reply->elements; j++) {
//             printf("%u) %s\n", j, reply->element[j]->str);
//         }
//     }
//     freeReplyObject(reply);

//     /* Disconnects and frees the context */
//     redisFree(c);

//     return 0;
// }

struct flb_redis_entry {
    flb_sds_t string;
    struct mk_list _head;
};

static int cb_redis_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    fprintf(stderr, "In cb_redis_init\n");
    int ret;
    const char *tmp;
    struct flb_out_redis *ctx = NULL;

    struct flb_redis_entry *item = malloc(sizeof(struct flb_redis_entry));

    // flb_sds_t s1, s2, s3;
    // s1 = flb_sds_create_size(100);
    // s2 = flb_sds_create_size(100);
    // s3 = flb_sds_create_size(100);

    // flb_sds_cat(s1, "alpha beta", 10);
    // flb_sds_cat(s2, "alpha beta", 10);
    // flb_sds_printf(&s1, "This is s1: %s\n");
    // flb_sds_printf(&s2, "This is s2: %s\n");
    // flb_sds_printf(&s3, "Hello s3: %s\n", "Hi");
    // fprintf(stderr, "%s\n", s3);
    // flb_sds_cmp(s1,)


    // struct mk_list *head;
    // struct mk_list *tmp_list;

    // item->string = flb_sds_create("test string");

    // flb_info("*item = %p | item->string = %p\n", item, item->string);

    // struct mk_list mylist;
    // mk_list_init(&mylist);
    // mk_list_add(&item->_head, &mylist);

    // struct flb_redis_entry *another_item;
    // mk_list_foreach_safe(head, tmp_list, &mylist) {
    //     another_item = mk_list_entry(head, struct flb_redis_entry, _head);
    //     flb_info("*another_item = %p | item->string = %p\n", another_item, another_item->string);
    //     flb_info("list item data value: %s", another_item->string);
    //     mk_list_del(another_item);
    // }

    printf("(1)\n");
    ctx = flb_redis_conf_create(ins, config);
    if (!ctx) {
        flb_plg_error(ctx->ins, "failed to create redis instance");
        return -1;
        }

    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }
printf("(1.1)\n");
    // ctx->out_format = FLB_PACK_JSON_FORMAT_NONE;
    // tmp = flb_output_get_property("format", ins);
    // if (tmp) {
    //     ret = flb_pack_to_json_format_type(tmp);
    //     if (ret == -1) {
    //         flb_plg_error(ctx->ins, "unrecognized 'format' option. "
    //                       "Using 'msgpack'");
    //     }
    //     else {
    //         ctx->out_format = ret;
    //     }
    // }

    /* Date format for JSON output */
    ctx->json_date_format = FLB_PACK_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "invalid json_date_format '%s'. "
                          "Using 'double' type", tmp);
        }
        else {
            ctx->json_date_format = ret;
        }
    }
printf("(2)\n");
    /* Export context */
    flb_output_set_context(ins, ctx);

    printf("connecting to: %s %d\n", ins->host.name, ins->host.port);

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
printf("(3)\n");
    return 0;
}

static void cb_redis_flush(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0, cnt = 0;
    struct flb_out_redis *ctx = out_context;
    flb_sds_t json;
    char *buf = NULL;
    (void) i_ins;
    (void) config;
    struct flb_time tmp;
    msgpack_object *p;

    if (ctx->out_format != FLB_PACK_JSON_FORMAT_NONE) {
        json = flb_pack_msgpack_to_json_format(data, bytes,
                                               ctx->out_format,
                                               ctx->json_date_format,
                                               ctx->json_date_key);
        write(STDOUT_FILENO, json, flb_sds_len(json));
        flb_sds_destroy(json);

        /*
         * If we are 'not' in json_lines mode, we need to add an extra
         * breakline.
         */
        if (ctx->out_format != FLB_PACK_JSON_FORMAT_LINES) {
            printf("\n");
        }
        fflush(stdout);
    }
    else {
        /* A tag might not contain a NULL byte */
        buf = flb_malloc(tag_len + 1);
        if (!buf) {
            flb_errno();
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        memcpy(buf, tag, tag_len);
        buf[tag_len] = '\0';
        msgpack_unpacked_init(&result);
        while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
            printf("[%zd] %s: [", cnt++, buf);
            flb_time_pop_from_msgpack(&tmp, &result, &p);
            printf("%"PRIu32".%09lu, ", (uint32_t)tmp.tm.tv_sec, tmp.tm.tv_nsec);
            msgpack_object_print(stdout, *p);
            printf("]\n");
        }
        msgpack_unpacked_destroy(&result);
        flb_free(buf);
    }
    fflush(stdout);

    // ctx->redis_context->
    // do_redis();
    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_redis_exit(void *data, struct flb_config *config)
{
    struct flb_out_redis *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "format", NULL,
     0, FLB_FALSE, 0,
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_format", NULL,
     0, FLB_FALSE, 0,
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_out_redis, json_date_key),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "host", FLB_REDIS_HOST,
     0, FLB_TRUE, offsetof(struct flb_out_redis, host),
     "Redis Host address"
    },
    {
     FLB_CONFIG_MAP_INT, "port", FLB_REDIS_PORT,
     0, FLB_TRUE, offsetof(struct flb_out_redis, port),
     "Redis TCP port"
    },
    {
        FLB_CONFIG_MAP_STR, "key", FLB_REDIS_KEY,
        0, FLB_TRUE, offsetof(struct flb_out_redis, key),
        "Redis key (must be a list type)"
    },

    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_redis_plugin = {
    .name         = "redis",
    .description  = "Sends messages to redis",
    .cb_init      = cb_redis_init,
    .cb_flush     = cb_redis_flush,
    .cb_exit      = cb_redis_exit,
    .flags        = 0,
    .config_map   = config_map,
};

