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
#ifndef __BIT_MAP__
#define __BIT_MAP__
#include <stdint.h>

#define BitmapSize          (256)
#define BucketSize          (8*sizeof(uint64_t))
#define BucketMask          (BucketSize-1)
#define BitmapBucketNum     (BitmapSize/BucketSize)
#define MAXRULES            (1<<13 - 1)

#define NO_ERROR            1
#define E_INVALID_PARM      (-1)
#define E_INSUFFICIENT_MEM  (-2)
#define E_CONFLICT          (-3) //rule already has been insert
#define E_INVALID_RULE      (-5)

#define NO_MATCH (0)

typedef struct _prefix_ele_ {
    union {
      uint64_t   dummy;
      struct {
        uint64_t   aggregation: 1;
        uint64_t   status:  2;
        uint64_t   ruleID: 13;  //! Maximal 8K
        uint64_t   next:   48;
      };
    };
} PrefixEle, *PrefixElePtr;

typedef struct _bit_map_index_ {
    PrefixEle   prefix_index[BitmapSize];
    int8_t      always_match;
    int8_t      aggregation;
    int         id;
} BitMapIndex;

typedef struct _bitmapleaf_ {
   uint64_t     bitmap[BitmapBucketNum];
} BitMapLeaf;

#define BitMapIndex_I_64(ptr, i)            ((ptr)->prefix_index[i].dummy)
#define BitMapIndex_I_aggregation(ptr, i)   ((ptr)->prefix_index[i].aggregation)
#define BitMapIndex_I_status(ptr, i)        ((ptr)->prefix_index[i].status)
#define BitMapIndex_I_ruleID(ptr, i)        ((ptr)->prefix_index[i].ruleID)
#define BitMapIndex_I_next(ptr, i)          ((ptr)->prefix_index[i].next)
#define BitMapLeaf_I_bucket(ptr, i)         ((ptr)->bitmap[i])
#define BitMapBucket(I)                     ((I)>> 6)
#define BitMapBucketPos(I)                  ((I) & BucketMask)
#define BitMapLeaf_B(ptr, i)                ((ptr)->bitmap[i])
#define BitMapLeaf_Addr(ptr, i)             (((ptr)->bitmap)+i)

enum RuleType {NO_RULE=0, HAS_RULE, HAS_INDEX};


void begin_insert_rules();
void end_insert_rules();
int insert_rule(const char *pIP, int id, int agregation);
int search_prefix_tree(uint32_t ip, int *pAgregation);

void lpm_init_rule();
int lpm_insert_rule(const char *pIP);
int lpm_search_rule(uint32_t ip);

#endif //__BIT_MAP__
