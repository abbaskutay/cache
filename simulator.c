#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <stdbool.h>

struct cache_options {
  int s  ,b;
  int S,E,B;
};

struct cache_stat {
  int hit, miss, evict;
};

struct statistics {
  struct cache_stat L1I, L1D, L2;
};

struct cache_line {
  int tag;
  time_t time;
  char v;
  char *data;
};

struct cache_set {
  struct cache_line *lines;
  int fifo_id;  //counter for FIFO policy
};

struct options {
  struct cache_options L1, L2;
  char *filename;
};

static struct options opts;
static struct statistics stats;

static void instr_load(const bool is_load, const char *label, struct cache_set *L1I, struct cache_set *L1D, struct cache_set *L2, const char *hex_addr, const int size);
static void instr_store(struct cache_set *L1D, struct cache_set *L2, char *hex_addr, const int size, char *data);

static int parse_options(const int argc, char *argv[]){

  if(argc != (14 + 1)){
    fprintf(stderr, "Usage: -L1s <L1s> -L1E <L1E> -L1b <L1b> -L2s <L2s> -L2E <L2E> -L2b <L2b> -t <tracefile>\n");
    return -1;
  }

  opts.L1.s = atoi(argv[2]);
  opts.L1.E = atoi(argv[4]);
  opts.L1.b = atoi(argv[6]);
  opts.L2.s = atoi(argv[8]);
  opts.L2.E = atoi(argv[10]);
  opts.L2.b = atoi(argv[12]);
  opts.filename = argv[14];

  opts.L1.S = 1 << opts.L1.s;
  opts.L2.S = 1 << opts.L2.s;
  opts.L1.B = 1 << opts.L1.b;
  opts.L2.B = 1 << opts.L2.b;

  return 0;
}

static struct cache_set * allocate_cache(const int S, const int E, const int B){
  int i, j;

  struct cache_set * cache = (struct cache_set*) calloc(S, sizeof(struct cache_set));
  if(cache == NULL){
    perror("malloc");
    return NULL;
  }

  for(i = 0; i < S; i++){
    cache[i].lines = calloc(E, sizeof(struct cache_line));
    if(cache[i].lines == NULL){
      perror("malloc");
      return NULL;
    }

    for(j=0; j < E; j++){
      cache[i].lines[j].data = calloc(B, sizeof(char));
      if(cache[i].lines[j].data == NULL){
        perror("malloc");
        return NULL;
      }

      // invalidate the line
      cache[i].lines[j].v = 0;
    }
  }
  return cache;
}

static void deallocate_cache(struct cache_set * cache, const int S, const int E){
  int i,j;
  for(i = 0; i < S; i++){
    for(j = 0; j < E; j++){
      free(cache[i].lines[j].data);
    }
    free(cache[i].lines);
  }
  free(cache);
}

static void print_stats(struct cache_stat * st, const char * label){
  printf("%s-hits: %d %s-misses: %d %s-evictions: %d\n",
    label, st->hit,
    label, st->miss,
    label, st->evict);
}

static int trace(struct cache_set *L1I, struct cache_set *L1D, struct cache_set *L2){
  char buf[250];

  FILE *fp = fopen(opts.filename, "r");
  if(fp == NULL){
    perror("fopen");
    return -1;
  }

  while(fgets(buf, sizeof(buf), fp) != NULL) {

    int size;
    char *op, *address, *data, *ptr;

    op = strtok(buf, " ,\n");
    address   = strtok(NULL, " ,\n");
    ptr       = strtok(NULL, " ,\n");
    data = strtok(NULL, " ,\n");

    size = atoi(ptr);

    if(op[0] == 'I'){

      printf("\nI %s, %d", address, size);
      instr_load(true, "L1I", L1I, L1D, L2, address, size);

    }else if(op[0] == 'L'){

      printf("\nL %s, %d", address, size);
      instr_load(false, "L1D", L1I, L1D, L2, address, size);

    }else if(op[0] == 'S'){

      printf("\nS %s, %d, %s", address, size, data);
      instr_store(L1D, L2, address, size, data);

    }else if(op[0] == 'M'){

      printf("\nM %s, %d, %s", address, size, data);

      //modify is load and store
      instr_load(false, "L1D", L1I, L1D, L2, address, size);
      instr_store(L1D, L2, address, size, data);

    }else{
      printf("Error: Invalid operation %s\n", op);
      break;
    }
  }
  fclose(fp);
  return 0;
}

static int cache_find_tag(struct cache_set * cache, const int nlines, const int setNum, const int tag){
  int i;
  for(i = 0; i < nlines; i++){
    if( (cache[setNum].lines[i].v   == 1) &&
        (cache[setNum].lines[i].tag == tag) ){
      return i;
    }
  }
  return -1;
}

static int cache_find_invalid(struct cache_set * cache, const int seti, const int n){
  int i;
  for(i = 0; i < n; i++){
    if(cache[seti].lines[i].v == 0){
      return i;
    }
  }
  return -1;
}

static int ram_write(const int addr, const int size, const char *data){
  int i;
  char hex[3];

  FILE *fp = fopen("RAM.txt", "r+");
  if(fp == NULL){
    perror("fopen");
    return -1;
  }

  fseek(fp, addr, SEEK_SET);

  for(i=0; i < size; i++){
    snprintf(hex, 3, "%X ", data[i]);
    fwrite(hex, 3, 1, fp);
  }
  fclose(fp);

  return 0;
}

static char * ram_read(const int addr){
  int i;
  char hex[2+1+1];  //2 hex letters + 1 space + 1 for end of string
  const int offset = addr & (0xFFFFFFFF ^ (opts.L2.B - 1));

  FILE *fp = fopen("RAM.txt", "r");
  if(fp == NULL){
    perror("fopen");
    return NULL;
  }

  char *data = malloc(opts.L2.B);
  if(data == NULL){
    perror("malloc");
    fclose(fp);
    return NULL;
  }

  hex[3] = '\0';
  fseek(fp, offset, SEEK_SET);
  for(i=0; i < opts.L2.B; i++){
    fread(hex, 3, 1, fp);
    data[i] = (char) strtol(hex, NULL, 16);
  }
  fclose(fp);

  return data;
}

static int cache_evict_fifo(struct cache_set * cache, const int seti, const int n){
  int i, f = 0;
  time_t first_t = cache[seti].lines[f].time;


  // find the first inserted cache line
  for(i = 1; i < n; i++){
    if(first_t > cache[seti].lines[i].time){
      first_t = cache[seti].lines[i].time;
      f = i;
      //break;
    }
  }

  stats.L2.evict++;

  return f;
}

static int ram_to_cache(const int addr, struct cache_set *L2, const int seti, const int tag){

  // load data from ram
  char * data = ram_read(addr);
  if(data == NULL){
    return -1;
  }

  // find where to place the data
  int li = cache_find_invalid(L2, seti, opts.L2.E);
  if(li == -1){
    li = cache_evict_fifo(L2, seti, opts.L2.E);
  }

  // copy data to cache
  L2[seti].lines[li].v = 1;
  L2[seti].lines[li].tag = tag;
  L2[seti].lines[li].time = L2[seti].fifo_id++;
  memcpy(L2[seti].lines[li].data, data, (size_t) opts.L2.B);

  free(data);

  return li;
}

static int cache_copy(struct cache_set *source, struct cache_set *dest, int sli, const int sseti, const int dseti, const int dtag, int destE, int destB){

  int eviction = 0;
  int li = cache_find_invalid(dest, dseti, destE);

  //If freeSlot is false, it means all the lines are valid so we have an eviction.
  if(li == -1){
    eviction = 1;
    li = cache_evict_fifo(dest, dseti, destE);
  }

  //Now, we have determined which line to store our instruction.
  dest[dseti].lines[li].v = 1;
  dest[dseti].lines[li].tag = dtag;
  dest[dseti].lines[li].time = dest[dseti].fifo_id++;
  memcpy(dest[dseti].lines[li].data, source[sseti].lines[sli].data, (size_t) destB);

  return eviction;
}

static void instr_load(const bool is_load, const char *label, struct cache_set *L1I, struct cache_set *L1D, struct cache_set *L2, const char *hex_addr, const int size){

    // determine cache source
    struct cache_set * source = (is_load) ? L1I : L1D;

    // convert hex to address
    const int addr = (int) strtol(hex_addr, NULL, 16);

    // block number
    const int bn1 = addr & (opts.L1.B - 1);
    const int bn2 = addr & (opts.L2.B - 1);

    //set number
    const int seti1 = (addr >> opts.L1.b) & (opts.L1.S - 1);
    const int seti2 = (addr >> opts.L1.b) & (opts.L2.S - 1);

    // tag size
    const int ts1 = 32 - (opts.L1.s + opts.L1.b);
    const int ts2 = 32 - (opts.L2.s + opts.L2.b);

    // tag
    const int tag1 = (addr >> (opts.L1.s + opts.L1.b)) & ((1 << ts1) - 1);
    const int tag2 = (addr >> (opts.L2.s + opts.L2.b)) & ((1 << ts2) - 1);

    //Checking if the data can fit into cache block.
    if( ((bn1 + size) > opts.L1.B) ||
        ((bn2 + size) > opts.L2.B)   ){
      printf("Error: Data can't fit\n");
      exit(0);
    }
    printf("\n   ");

    //Then, we need to check if the instruction is in caches.
    int li1 = cache_find_tag(source, opts.L1.E, seti1, tag1);
    int li2 = cache_find_tag(L2,     opts.L2.E, seti2, tag2);

    if(li1 != -1){

        printf("%s hit", label);
        (is_load == true) ? stats.L1I.hit++ : stats.L1D.hit++;

        // is instruction in L2 ?
        if(li2 != -1){

          printf(", L2 hit\n");
          stats.L2.hit++;

        }else{

          printf(", L2 miss\n");
          stats.L2.miss++;
          stats.L2.evict += cache_copy(source, L2, li1, seti1, seti2, tag2, opts.L2.E, opts.L2.B);
        }

    }else{

        printf("%s miss", label);
        (is_load == true) ? stats.L1I.miss++ : stats.L1D.miss++;

        int eviction_counter = 0;

        //is instruction in L2 ?
        if(li2 != -1) {

            printf(", L2 hit\n");
            stats.L2.hit++;

            eviction_counter = cache_copy(L2, source, li2, seti2, seti1, tag1, opts.L1.E, opts.L1.B);
        }else{

          printf(", L2 miss\n");
          stats.L2.miss++;

          li2 = ram_to_cache(addr, L2, seti2, tag2);
          eviction_counter = cache_copy(L2, source, li2, seti2, seti1, tag1, opts.L1.E, opts.L1.B);
        }

        if(is_load){
          stats.L1I.evict += eviction_counter;
        }else{
          stats.L1D.evict += eviction_counter;
        }
    }

    printf("   Place in L2 set %d, %s\n", seti2, label);
}

static void instr_store(struct cache_set *L1D, struct cache_set *L2, char *hex_addr, const int size, char *data){
    int i;
    char bin_data[size], hex[2+1];

    // convert hex address to decimal
    const int addr = (int) strtol(hex_addr, NULL, 16);

    //convert hex data to binary
    hex[2] = '\0';
    for(i = 0; i < size; i++){
      strncpy(hex, &data[i*2], 2);
      bin_data[i] = (char) strtol(hex, NULL, 16);
    }

    // block number
    const int bn1 = addr & (opts.L1.B - 1);
    const int bn2 = addr & (opts.L2.B - 1);

    //set number
    const int seti1 = (addr >> opts.L1.b) & (opts.L1.S - 1);
    const int seti2 = (addr >> opts.L1.b) & (opts.L2.S - 1);

    // tag size
    const int ts1 = 32 - (opts.L1.s + opts.L1.b);
    const int ts2 = 32 - (opts.L2.s + opts.L2.b);

    // tag
    const int tag1 = (addr >> (opts.L1.s + opts.L1.b)) & ((1 << ts1) - 1);
    const int tag2 = (addr >> (opts.L2.s + opts.L2.b)) & ((1 << ts2) - 1);

    //Checking if the data can fit into cache block.
    if( ((bn1 + size) > opts.L1.B) ||
        ((bn2 + size) > opts.L2.B)   ){
      printf("Error: Data can't fit\n");
      exit(0);
    }
    printf("\n   ");

    // location index
    int li1 = cache_find_tag(L1D, opts.L1.E, seti1, tag1);
    int li2  = cache_find_tag(L2, opts.L2.E, seti2, tag2);

    // data in L1D ?
    if(li1 != -1) {

        printf("L1D hit");
        stats.L1D.hit++;

        // store data in L1D
        memcpy(L1D[seti1].lines[li1].data, bin_data, (size_t) size);

        //data it in L2 ?
        if(li2 != -1) {

            printf(", L2 hit\n");
            stats.L2.hit++;

            // store data in L2
            memcpy(L2[seti2].lines[li2].data, bin_data, (size_t) size);
        }else{
          //data is in L1D, but not in L2 cache
          printf(", L2 miss\n");
          stats.L2.miss++;
          stats.L2.evict += cache_copy(L1D, L2, li1, seti1, seti2, tag2, opts.L2.E, opts.L2.B);
        }
    }else{

        printf("L1D miss");
        stats.L1D.miss++;

        //data it in L2 ?
        if(li2 != -1) {

            printf(", L2 hit\n");
            stats.L2.hit++;
            stats.L1D.evict += cache_copy(L2, L1D, li2, seti2, seti1, tag1, opts.L1.E, opts.L1.B);

        }else{

          printf(", L2 miss\n");
          stats.L2.miss++;

          li2 = ram_to_cache(addr, L2, seti2, tag2);
          stats.L1D.evict = cache_copy(L2, L1D, li2, seti2, seti1, tag1, opts.L1.E, opts.L1.B);
        }

        //find where it is and update it
        li1 = cache_find_tag(L1D, opts.L1.E, seti1, tag1);
        memcpy(L1D[seti1].lines[li1].data, bin_data, (size_t) size);

        //update L2 too
        cache_copy(L1D, L2, li1, seti1, seti2, tag2, opts.L2.E, opts.L2.B);
    }

    // sync with ram
    ram_write(addr, size, bin_data);

    printf("   Store in L1D, L2, RAM\n");
}

int main(int argc, char *argv[]){

  struct cache_set *L1I, *L1D, *L2;

  bzero(&opts, sizeof(struct options));
  bzero(&stats, sizeof(struct statistics));

  if(parse_options(argc, argv) < 0){
    return EXIT_FAILURE;
  }

  L1I = allocate_cache(opts.L1.S, opts.L1.E, opts.L1.B);
  L1D = allocate_cache(opts.L1.S, opts.L1.E, opts.L1.B);
  L2  = allocate_cache(opts.L2.S, opts.L2.E, opts.L2.B);

  if((L1I == NULL) || (L1D == NULL) || (L2 == NULL)){
    return EXIT_FAILURE;
  }

  trace(L1I, L1D, L2);

  print_stats(&stats.L1I, "L1I");
  print_stats(&stats.L1D, "L1D");
  print_stats(&stats.L2,  "L2");


  deallocate_cache(L1I, opts.L1.S, opts.L1.E);
  deallocate_cache(L1D, opts.L1.S, opts.L1.E);
  deallocate_cache(L2,  opts.L2.S, opts.L2.E);

  return 0;
}
