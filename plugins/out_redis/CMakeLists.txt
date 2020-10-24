add_subdirectory(hiredis EXCLUDE_FROM_ALL)

include_directories(hiredis/src/)

set(src
  redis.c
  redis_conf.c)

FLB_PLUGIN(out_redis "${src}" "")
target_link_libraries(flb-plugin-out_redis hiredis)
