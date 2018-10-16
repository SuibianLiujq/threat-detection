/***************************************************************************
 * Author:  Xinan Tang
 * Copyright:   ClearCouds Inc.
 *              2013, 2014
 * Algorithm:   Implement the longest prefix match for 32bit IP address
 *              (1) only support class A/B/C
 *                   192.168.1.*
 *                   192.168.*
 *
 *              (2) doesn't support arbitratry prefix length like
 *                   192.168.1.1/26
 *
 *              (3) Maximal 4 memory accesses to detect a match
 *
 *              (4) From the root to an internal node,
 *                  from the highest 8bits to the lowest,
 *                    each time use 8-bit of ip address as an index to search and
 *                    at last (leaf) use bitmap to save space
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "lpm.h"

//! Root master index
BitMapIndex bitmap_masters[2] = {{0}, {0}};
BitMapIndex* current_bitmap = &bitmap_masters[0];
int candidate_bitmap_index = 0;

BitMapIndex pcap_master;

void destroy_bitmap_index(BitMapIndex* bitmap_index, int level) // level = 0 for root
{
    int i;
    for(i=0; i<BitmapSize; i++)
    {
        if(BitMapIndex_I_next(bitmap_index, i))
        {
            destroy_bitmap_index((BitMapIndex *)(unsigned long)BitMapIndex_I_next(bitmap_index, i), level + 1);
            BitMapIndex_I_next(bitmap_index, i) = 0;
        }
    }

    if(level == 0)
        memset(bitmap_index, 0, sizeof(*bitmap_index));
    else
        free(bitmap_index);
}


static int skip_line(char *line)
{
    int i, len;
    //! Skipe space chars
    while (line[0] =='\t' || line[0]==' ') {
       len = strlen(line);
       for (i=0; i<len-1; i++) {
           line[i] = line[i+1];
       }
    }
    if (line[0] == '#')
        return 1;
    if (line[0] == '\r' || line[0] == '\n')
        return 1;
    return 0;
}

//! Assume sscanf return the number of successfuly parsed arguments
static int read_one_rule(const char *ip_input, uint32_t *ip32)
{
   int      res;
   uint32_t d[4], ip;
   int      type;

   type = 0;
   res  = sscanf(ip_input,"%d.%d.%d.%d", &d[0], &d[1], &d[2], &d[3]);
   switch (res) {
       case 1:
          //! printf("res=%d, %d\n", res, d[0]);
          ip   = d[0] << 24;
          type = 1;
          break;
       case 2:
          //! printf("res=%d, %d.%d\n", res, d[0],d[1]);
          ip = d[0]<<24 | d[1] << 16;
          type = 2;
          break;
       case 3:
          //! printf("res=%d, %d.%d.%d\n", res, d[0],d[1],d[2]);
          ip = d[0]<<24 | d[1] << 16 | d[2] << 8;
          type = 3;
          break;
       case 4:
          //! printf("res=%d, %d.%d.%d.%d\n", res, d[0],d[1],d[2],d[3]);
          ip = d[0] << 24 | d[1] << 16 | d[2] << 8 | d[3];
          type = 4;
          break;
       default:
          //! printf("res=%d\n");
          if (res == '*') {
             type = 5;
          }
     }

   *ip32 = ip;
   return type;
}


void read_rules(const char *file_name)
{
   FILE *fp;
   char *line;
   int  res, err;
   int  rule_id, line_num;
   uint32_t ip;
   enum RuleType type;
   char ip_addr[BitmapSize];

    fp = fopen(file_name, "rb");
    if (fp==NULL) {
       printf("File %s doesn't exist\n", file_name);
       exit(1);
    }

    begin_insert_rules();
    rule_id=0; line_num=0; err =0;
    do {
      line = fgets(ip_addr, BitmapSize, fp);
      line_num++;
      if (line) {
        res = skip_line(ip_addr);
        if (res) {
            continue;
        }
        //!
        type = read_one_rule(ip_addr, &ip);
        if (type != 0) {
          res = insert_rule(ip_addr, rule_id, (rule_id % 2));
          if (res == E_CONFLICT) {
              printf("Insert rule %d at line %d failed ip_addr %s\n", rule_id, line_num, ip_addr);
              err++;
          }
          else
              rule_id++;
        } else {
          err++;
          printf("Parsing error at line %d for rule %d\n", line_num, rule_id+1);
        }
      }
    } while (line !=NULL);

    if (err) {
       printf("Total %d errors\n", err);
       //exit(1);
    }
    else {
       printf("Parsing IP filtering rules success, rules=%d\n", rule_id);
    }
    end_insert_rules();
}

void begin_insert_rules()
{
    candidate_bitmap_index = 1 - candidate_bitmap_index;
    BitMapIndex* bitmap = &bitmap_masters[candidate_bitmap_index];
    destroy_bitmap_index(bitmap, 0);
}

void end_insert_rules()
{
    current_bitmap = &bitmap_masters[candidate_bitmap_index];
}

/*****************************Index Scheme ************************
 * 1. A leaf node stores bitmap without rule ID to save space
 * 2. root and internal nodes stores index with pointer to
 *    the next level structure
 * 3. 192.168.1.1 has four levels:
 *
 *    three level of index master (4), level (3), level (2)
 *    and level (1) in which bitmap has the bit 1 is set
 *
 ******************************************************************/


//! Only set status and rule ID, the address are treated differently
static int insert_longest_prefx(BitMapIndex *master, int rule_id, int ip_prefix, enum RuleType type, int agregation)
{

    if (BitMapIndex_I_status(master, ip_prefix) == HAS_RULE) {
           return E_CONFLICT;
    }
    else {
            BitMapIndex_I_status(master, ip_prefix) = type;
            if (type == HAS_RULE) {
                BitMapIndex_I_ruleID(master, ip_prefix) = rule_id;
                BitMapIndex_I_aggregation(master, ip_prefix) = agregation;
            }
    }

    return NO_ERROR;
}

static int longest_prefx_expansion_index(BitMapIndex *master, int rule_id, int agregation)
{
    int i, res;

    res = 1;
    for (i=0; i<BitmapSize;i++) {
       res = insert_longest_prefx(master, rule_id, i, HAS_RULE, agregation) ;
       if (res ==0)
           break;
    }
    return res;
}

static inline int bitmap_I(BitMapLeaf *master, int i)
{
    //! divided by 64
    int bucket = BitMapBucket(i);
    int pos    = BitMapBucketPos(i); //! lower 64bits

    uint64_t k   = BitMapLeaf_B(master, bucket);
    int      bit = k>>pos & 0x1;
    return bit;
}

static inline void set_bitmap_I(BitMapLeaf *master, int i)
{
    //! divided by 64
    int bucket = BitMapBucket(i);
    //! lower 64bits
    int pos    = BitMapBucketPos(i);

    uint64_t *k_ptr = BitMapLeaf_Addr(master, bucket);
    uint64_t k   =  *k_ptr;
    uint64_t bit = (0x1<<pos) | k;
    //! Set the bit
    *k_ptr = bit;

    return ;
}

static void bitmap_print(BitMapLeaf *leaf)
{
    uint64_t k;
    int i, j;

    for (i=0; i<BitmapBucketNum; i++) {
      printf("Bucket %d: ", i);
      k   = BitMapLeaf_B(leaf,i);
      printf("%lx\n", k);
    }
    return ;
}

static int insert_and_expansion(int level, BitMapIndex *master,
                         int rule_id, uint32_t ip, int agregation)
{
    int      res;
    uint64_t ip_prefix;
    uint64_t ip_master_prefix;

    res = 1;

    if (level==1) {
        //!  Insert rule like 192.*.*.*
        ip_prefix = ip>>24;
        res = insert_longest_prefx(master, rule_id, ip_prefix, HAS_RULE, agregation);
        return res;
    } else {
       //! abstract the high-level index
        ip_master_prefix = ip >> 24;
        if (BitMapIndex_I_status(master, ip_master_prefix) == NO_RULE) {

            BitMapIndex *new_master = (BitMapIndex * ) malloc(sizeof(BitMapIndex));
            if (new_master==NULL) {
                return E_INSUFFICIENT_MEM;
            }

            memset(new_master, 0, sizeof(BitMapIndex));
            res = insert_longest_prefx(master, rule_id, ip_master_prefix, HAS_INDEX, agregation) ;
            if (res == E_INSUFFICIENT_MEM) {
               return E_INSUFFICIENT_MEM;
            }

            BitMapIndex_I_next(master, ip_master_prefix) = (uint64_t) new_master;
               //! the highest 8 bits are used as index of the master
            ip_prefix = ip<<8;
            res = insert_and_expansion(level-1, new_master, rule_id, ip_prefix, agregation);
            return res;
        }

        if (BitMapIndex_I_status(master, ip_master_prefix) == HAS_INDEX) {
               BitMapIndex *new_master = (BitMapIndex *) (unsigned long) BitMapIndex_I_next(master, ip_master_prefix);
               ip_prefix = ip<<8;
               res = insert_and_expansion(level-1, new_master, rule_id, ip_prefix, agregation);
               return res;
        }

        if (BitMapIndex_I_status(master, ip_master_prefix) == HAS_RULE) {
               return E_CONFLICT;
        }
    }

    return NO_ERROR;
}




static int _insert_rule(BitMapIndex *master, int type, int rule_id, uint32_t ip, int agregation)
{
   int res;
   switch (type) {
     case 1:
           res = insert_and_expansion(1, master, rule_id, ip, agregation);
           break;
     case 2:
           res = insert_and_expansion(2, master, rule_id, ip, agregation);
           break;
     case 3:
           res = insert_and_expansion(3, master, rule_id, ip, agregation);
           break;
     case 4:
           res = insert_and_expansion(4, master, rule_id, ip, agregation);
           break;
     case 5:
           res = longest_prefx_expansion_index(master, rule_id, agregation);
           break;
     default:
           res = E_INVALID_RULE;
   }
   return res;
}

int insert_rule(const char *pIP, int id, int agregation) {
    int ip, type;
    int ret;

    if (id < 0 || id > MAXRULES) {
        return E_INVALID_PARM;
    }

    if (NULL == pIP) {
        return E_INVALID_PARM;
    }

    if (pIP[0] == ' ') {
        return E_INVALID_PARM;
    }

    if (pIP[0] == '*') {
        bitmap_masters[candidate_bitmap_index].always_match = 1;
        bitmap_masters[candidate_bitmap_index].aggregation = (int8_t)agregation;
        bitmap_masters[candidate_bitmap_index].id = id;
        return NO_ERROR;
    }

    type = read_one_rule(pIP, &ip);
    ret = _insert_rule(&bitmap_masters[candidate_bitmap_index], type, id, ip, agregation);

    return ret;
}

static void print_tabs(int level) {
    switch (level) {
        case 4:
            break;
        case 3:
            printf("\t");
            break;
        case 2:
            printf("\t\t");
            break;
        case 1:
            printf("\t\t\t");
            break;
    }
}

static int _search_prefix_tree(BitMapIndex *master, int level, uint32_t ip_addr, int *pAgregation)
{
    int status;
    int ip, res;
    BitMapIndex *new_master;


     ip = ip_addr>>24;
     if (level == 1) {
        BitMapLeaf *leaf = (BitMapLeaf *) master;
        if (BitMapIndex_I_status(master, ip)) {
            res = BitMapIndex_I_ruleID(master, ip);
            *pAgregation = BitMapIndex_I_aggregation(master, ip);
        }
        else
            res = NO_MATCH;
     }
     else {
        status  = BitMapIndex_I_status(master,  ip);
        if (status == HAS_INDEX) {
            new_master = (BitMapIndex *)(unsigned long)BitMapIndex_I_next(master,ip);
            res = _search_prefix_tree(new_master, level-1, ip_addr<<8, pAgregation);
        }
        else if (status == HAS_RULE) {
            res = BitMapIndex_I_ruleID(master, ip);
            *pAgregation = BitMapIndex_I_aggregation(master, ip);
        }
        else {
            res = NO_MATCH;
        }
     }
     return res;
}

int search_prefix_tree(uint32_t ip, int *pAgregation) {

    if (current_bitmap->always_match) {
        *pAgregation = current_bitmap->aggregation;
        return current_bitmap->id;
    }
    return _search_prefix_tree(current_bitmap, 4, ip, pAgregation);
}


void lpm_init_rule()
{
    BitMapIndex* bitmap = &pcap_master;
    destroy_bitmap_index(bitmap, 0);
}

int lpm_insert_rule(const char *pIP) {
    int ip, type;
    int ret;
    int agregation = 0;
    int id = 1;

    if (NULL == pIP) {
        return E_INVALID_PARM;
    }

    if (pIP[0] == ' ') {
        return E_INVALID_PARM;
    }

    if (pIP[0] == '*') {
        pcap_master.always_match = 1;
        pcap_master.id = id;
        return NO_ERROR;
    }

    type = read_one_rule(pIP, &ip);
    ret = _insert_rule(&pcap_master, type, id, ip, agregation);

    return ret;
}

int lpm_search_rule(uint32_t ip) {
    int pAgregation;
    BitMapIndex* bitmap = &pcap_master;

    if (bitmap->always_match) {
        return bitmap->id;
    }
    return _search_prefix_tree(bitmap, 4, ip, &pAgregation);
}


static int print_prefix_tree(BitMapIndex *master, int level)
{
    int status;
    int rule_id;
    int i;

    int total_rules = 0;
     if (level == 1) {
        BitMapLeaf *leaf = (BitMapLeaf *) master;
        for (i=0; i<BitmapBucketNum; i++) {
           if (bitmap_I(leaf, i)) {
               print_tabs(level);
               printf("Position %d has a rule\n", i);
               total_rules++;
           }
        }
     } else {
       for (i=0; i< BitmapSize; i++) {
         status  = BitMapIndex_I_status(master,  i);
         rule_id = BitMapIndex_I_ruleID(master, i);
         if (status == HAS_RULE) {
             print_tabs(level);
             printf("Position %d has rule %d\n", i, rule_id);
             total_rules++;
         }
       }
       //! recursively search for the other rules
       for (i=0; i< BitmapSize; i++) {
         status  = BitMapIndex_I_status(master,  i);
         if (status == HAS_INDEX) {
             print_tabs(level);
             printf("prefix %d has rules:\n", i);
             total_rules += print_prefix_tree((BitMapIndex *)(unsigned long)BitMapIndex_I_next(master,i), level-1);
         }
       }
    }
    return total_rules;
}


void print_search_res(uint32_t ip)
{
    int res;
    int agregation;
    res = search_prefix_tree(ip, &agregation);
    printf("%d.%d.%d.%d ", ip>>24, ip>>16&0xFF, ip>>8&0xFF, ip&0xFF);
    if (res != NO_MATCH)
        printf("matcheed %d %d\n", res, agregation);
    else
        printf("unmatched\n");
}

#if 0

#define arraysize(array)    (sizeof(array)/sizeof(array[0]))

void test(const char** rules, int rule_count)
{
    static int count = 0;
    int i;
    uint32_t  ip_addr;

    printf("==================================================\n");
    begin_insert_rules();
    for(i=0; i<rule_count; i++)
    {
        printf("insert rule: %s,  id: %d\n", rules[i], count);
        insert_rule(rules[i], count++, 1);
    }
    end_insert_rules();

    printf("candidate_bitmap_index: %d,   bitmap[index]: %x    current_bitmap: %x\n",
        candidate_bitmap_index, &bitmap_masters[candidate_bitmap_index], current_bitmap);

    printf("bitmap rules: %d\n", print_prefix_tree(current_bitmap, 4));

    ip_addr = 10<<24 | 1 <<16;
    print_search_res(ip_addr);

    ip_addr = 192<<24 | 168 <<16 | 1<<8;
    print_search_res(ip_addr);

    ip_addr = 8<<24 | 8 <<16 | 8<<8 | 8;
    print_search_res(ip_addr);

    ip_addr = 172<<24 | 8 <<16 | 8<<8 | 8;
    print_search_res(ip_addr);

    printf("\n\n");
}

int main()
{
    const char* group1[] = {"*.*.*.*"};
    const char* group2[] = {"10.*.*.*"};
    const char* group3[] = {"192.168.1.*","192.168.10.*"};
    const char* group4[] = {"8.8.8.8","4.4.4.4"};

    test(group1, arraysize(group1));
    test(group2, arraysize(group2));
    test(group3, arraysize(group3));
    test(group4, arraysize(group4));
}

#endif
