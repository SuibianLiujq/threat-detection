/*******************************************************************************
 *  Copyright (c) 2011-2014 Nanjing Yunlilai.
 *  All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms with or without
 *  modification are permitted provided that: (1) source distributions
 *  retain this entire copyright notice and comment, and (2) distributions
 *  including binaries display the following acknowledgement: "This product
 *  includes software developed by Nanjing Yunlilai. and its
 *  contributors" in the documentation or other materials provided with the
 *  distribution and in all advertising materials mentioning features or use
 *  of this software. Neither the name of the company nor the names of its
 *  contributors may be used to endorse or promote products derived from this
 *  software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *******************************************************************************/
#include "../lpm.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

//argv[1] configfile
//argv[2] ipfile
#define IPBUFFER 256
int main (int argc, char *argv[]) {
    int res;
    uint32_t  ip_addr;

    char *config = argv[1];
    char *ipfile = argv[2];
    char ip[IPBUFFER];
    FILE *fp;

    //init_master(&bitmap_master);
    //BitMapIndex * pmaster = init_master();
    read_rules(config);

    fp = fopen(ipfile, "rb");

    while (fgets(ip, IPBUFFER, fp)) {
        ip[strlen(ip) - 1] = 0;
        //printf("ip %s\n", ip);
        ip_addr = inet_addr(ip);
        ip_addr = ntohl(ip_addr);
        print_search_res(ip);
    }

    close(ipfile);
    return 0;

}
