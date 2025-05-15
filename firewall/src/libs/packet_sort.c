#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <msgpack.h>

#include "packet_sort.h"

void filter_packets(char* filename, char* filter, char* value, uint64_t* packet_num)
{
    FILE *file = fopen(filename, "rb");
    if (!file) 
    {
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    size_t filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *data = malloc(filesize);
    fread(data, 1, filesize, file);
    fclose(file);

    msgpack_unpacked upk;
    msgpack_unpacked_init(&upk);
    
    size_t offset = 0;

    while (offset < filesize) {
        if (msgpack_unpack_next(&upk, data, filesize, &offset)) {
            msgpack_object obj = upk.data;
            // printf("Packet %d:\n", (*packet_num));
            if (obj.type == MSGPACK_OBJECT_MAP) {
                for (uint32_t i = 0; i < obj.via.map.size; i++) {
                    msgpack_object_kv kv = obj.via.map.ptr[i];
                    msgpack_object key = kv.key;
                    msgpack_object val = kv.val;

                    if (key.type == MSGPACK_OBJECT_STR && val.type == MSGPACK_OBJECT_STR) {
                        if (
                            (
                                key.via.str.size == strlen(filter) && 
                                strncmp(key.via.str.ptr, filter, key.via.str.size) == 0
                            ) && 
                            (
                                val.via.str.size == strlen(value) && 
                                strncmp(val.via.str.ptr, value, val.via.str.size) == 0
                            )
                        )
                        {
                            (*packet_num)++;
                            // printf("  %.*s: %.*s\n",
                            //     key.via.str.size, key.via.str.ptr,
                            //     val.via.str.size, val.via.str.ptr);
                        }
                    }
                }
                // printf("\n");
            } else {
                printf("  Skipped non-map object\n\n");
            }
        } else {
            printf("Failed to unpack data at offset %zu\n", offset);
            break;
        }
    }

    msgpack_unpacked_destroy(&upk);
    free(data);
}
