#include "pefile.h"
#include "stdlib.h"

add_t 
pefile_baseofcode (pefile_t* pe){
  if (pe->arch == 32)
    return pe->opthdr.ImageBase;
  else if (pe->arch == 64)
    return pe->opthdr64.ImageBase;
  return 0;
}

add_t 
pefile_entrypoint (pefile_t* pe){
  if (pe->arch == 32)
    return pe->opthdr.AddressOfEntryPoint + pefile_baseofcode (pe);
  else if (pe->arch == 64)
    return pe->opthdr64.AddressOfEntryPoint + pefile_baseofcode (pe);
  return 0;
}

add_t 
pefile_exporttable (pefile_t* pe){
  add_t ret = pefile_baseofcode (pe);
  if (pe->arch == 32)
    return ret + pe->opthdr.DataDirectory[0].VirtualAddress;
  else if (pe->arch == 64)
    return ret + pe->opthdr64.DataDirectory[0].VirtualAddress;
  return 0;
}

void* 
pefile_alloc (){
  pefile_t* pe = malloc (sizeof (pefile_t));
  pe->entrypoint = 0;
  pe->baseofcode = 0;
  pe->arch = 0;
  pe->sections_hdr = (IMAGE_SECTION_HEADER*) malloc (0);
  pe->sections_nb = 0;
  pe->sections = (uint8_t**) malloc (pe->sections_nb * sizeof (uint8_t*));
  //pe->cache.buffer = (uint8_t*) malloc (PEFILE_CACHE_SIZE * sizeof (uint8_t));;
  pe->cache.high = 0;
  pe->cache.low = 0;
  pe->cache.lock = 0;
  return pe;
}

void 
pefile_cache_lock (pefile_t* pe){
  pe->cache.lock = 1;
}

void 
pefile_cache_unlock (pefile_t* pe){
  pe->cache.lock = 0;
}


void 
pefile_free (pefile_t* pe){
  size_t i;
  for (i = 0; i < pe->sections_nb; ++i)
    free (pe->sections[i]);
  free (pe->sections);
  free (pe->sections_hdr);
  //free (pe->cache.buffer);
  free (pe);
}

/* Offset to header address */
#define HDR_OFFSET 60

enum pefile_error_t
pefile_extract (pefile_t* pe, FILE* fp){
  /* parse file header */
  if (fseek (fp, HDR_OFFSET, SEEK_SET) != 0)
    return PEFILE_FILE_HDR_ERROR;
  uint32_t hdr_add;
  if (fread(&hdr_add, sizeof(uint32_t), 1, fp) != 1)
    return PEFILE_FILE_HDR_ERROR;
  if (fseek (fp, hdr_add, SEEK_SET) != 0)
    return PEFILE_FILE_HDR_ERROR;
  if (fread(pe->magic, 
	    sizeof(uint8_t), 
	    PEFILE_MAGIC_LENGTH, fp) != PEFILE_MAGIC_LENGTH)
    return PEFILE_FILE_HDR_ERROR;
  if (fread(&pe->hdr, sizeof(IMAGE_FILE_HEADER), 1, fp) != 1)
    return PEFILE_FILE_HDR_ERROR;

  /* parse optional header */
  if (pe->hdr.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER) )
    pe->arch = 32;
  else if (pe->hdr.SizeOfOptionalHeader 
	   == sizeof(IMAGE_OPTIONAL_HEADER64) )
    pe->arch = 64;
  else
    return PEFILE_OPT_HDR_ERROR;
  if (fread(&pe->opthdr, pe->hdr.SizeOfOptionalHeader, 1, fp) != 1 )
    return PEFILE_OPT_HDR_ERROR;

  /* get the entrypoint and the base of code and the export table*/
  pe->entrypoint = pefile_entrypoint (pe);
  pe->baseofcode = pefile_baseofcode (pe);
  pe->exporttable = pefile_exporttable (pe);

  /* parse section table (+1 virtual)*/
  pe->sections_nb = pe->hdr.NumberOfSections + 1;
  pe->sections_hdr = (IMAGE_SECTION_HEADER*) 
    realloc (pe->sections_hdr, pe->sections_nb * sizeof(IMAGE_SECTION_HEADER));
  if (pe->sections_hdr == NULL)
    return PEFILE_TOO_BIG_ERROR;
  /* pe->sections_nb - 1 real sections */
  int read = fread(pe->sections_hdr, sizeof(IMAGE_SECTION_HEADER), pe->sections_nb - 1, fp);
  if (read != pe->sections_nb - 1){
    int i;
    for (i = 0; i < pe->sections_nb; ++i) 
      pe->sections[i] = (uint8_t*)malloc (0);
    return PEFILE_SEC_TABLE_ERROR;
  }
  /* 1 virtual to represent the mapping of the header */
  uint64_t hdr_size = 0;
  size_t i;
  for (i = 0; i < pe->sections_nb - 1; ++i) {
    if (hdr_size == 0 || hdr_size > pe->sections_hdr[i].PointerToRawData)
      hdr_size = pe->sections_hdr[i].PointerToRawData;
  }  
  pe->sections_hdr[pe->sections_nb - 1].PointerToRawData = 0;
  pe->sections_hdr[pe->sections_nb - 1].VirtualAddress = 0;
  pe->sections_hdr[pe->sections_nb - 1].SizeOfRawData = hdr_size;

  /* build the memory image */
  enum pefile_error_t ret = PEFILE_ALL_OK;
  pe->sections = (uint8_t**) realloc (pe->sections, pe->sections_nb * sizeof(uint8_t*));
  for (i = 0; i < pe->sections_nb; ++i) {
    DWORD size = pe->sections_hdr[i].SizeOfRawData;
    pe->sections[i] = (uint8_t*)malloc (size * sizeof (uint8_t));
    if (pe->sections[i] == NULL)
      return PEFILE_TOO_BIG_ERROR;
    if (fseek (fp, pe->sections_hdr[i].PointerToRawData, SEEK_SET) != 0){
      ret = PEFILE_BROKEN_FILE_ERROR;
      memset (pe->sections[i], 0, size);
    }
    read = fread (pe->sections[i], sizeof(uint8_t), size, fp);
    if (read != size){
      ret = PEFILE_BROKEN_FILE_ERROR;
      memset (pe->sections[i] + read, 0, size - read);
    }
  }
  return ret;
}

enum pefile_error_t
pefile_extract_raw (pefile_t* pe, FILE* fp, int sz){
  unsigned long offset = ftell (fp);
  if (sz == 0){
    fseek(fp, 0, SEEK_END);
    sz = ftell (fp);
    sz -= offset;
  }
  fseek(fp, offset, SEEK_SET);

  pe->arch = 32;
  pe->entrypoint = 0;
  pe->baseofcode = 0x80000000;
  pe->exporttable = 0;

  pe->sections_nb = 1;
  pe->sections_hdr = (IMAGE_SECTION_HEADER*) 
    realloc (pe->sections_hdr, pe->sections_nb * sizeof(IMAGE_SECTION_HEADER));
  pe->sections_hdr[0].PointerToRawData = 0;
  pe->sections_hdr[0].VirtualAddress = 0;
  pe->sections_hdr[0].SizeOfRawData = sz;

  /* build the memory image */
  enum pefile_error_t ret = PEFILE_ALL_OK;
  pe->sections = (uint8_t**) realloc (pe->sections, pe->sections_nb * sizeof(uint8_t*));
  int i;
  for (i = 0; i < pe->sections_nb; ++i) {
    DWORD size = pe->sections_hdr[i].SizeOfRawData;
    pe->sections[i] = (uint8_t*)malloc (size * sizeof (uint8_t));
    if (pe->sections[i] == NULL)
      return PEFILE_TOO_BIG_ERROR;
    int read = fread (pe->sections[i], sizeof(uint8_t), size, fp);
    if (read != size){
      ret = PEFILE_BROKEN_FILE_ERROR;
      memset (pe->sections[i] + read, 0, size - read);
    }
  }
  return ret;

  /* pe->sections = (uint8_t**)  */
  /*   realloc (pe->sections, pe->sections_nb * sizeof(uint8_t*)); */
  /* pe->sections[0] = NULL; */
  /* pe->fp = fp; */
  /* return PEFILE_ALL_OK; */
}

uint8_t*
pefile_seek_cache (pefile_t* pe, add_t add){
  add -= pe->baseofcode;
  size_t i;
  for (i = 0; i < pe->sections_nb; ++i) {
    if (add >= pe->sections_hdr[i].VirtualAddress &&
	add < pe->sections_hdr[i].VirtualAddress + pe->sections_hdr[i].SizeOfRawData)
      break;
  }
  if (i >= pe->sections_nb)
    return NULL;
  if (pe->sections[i] != NULL)
    return NULL;
  int offset = (add - pe->sections_hdr[i].VirtualAddress);
  pe->cache.low = pe->sections_hdr[i].VirtualAddress + offset;
  fseek (pe->fp, pe->sections_hdr[i].PointerToRawData + offset, SEEK_SET);
  int read = fread (pe->cache.buffer, sizeof(uint8_t), PEFILE_CACHE_SIZE, pe->fp);
  pe->cache.high = pe->cache.low + read;
  add_t high = pe->sections_hdr[i].VirtualAddress + pe->sections_hdr[i].SizeOfRawData;
  if (pe->cache.high > high)
    pe->cache.high = high;
  if (read != PEFILE_CACHE_SIZE)
    memset (pe->cache.buffer + read, 0, PEFILE_CACHE_SIZE - read);
  return pe->cache.buffer + (add - pe->cache.low);
}

uint8_t*
pefile_virtual_goto (pefile_t* pe, add_t add){
  add -= pe->baseofcode;
  if (add >= pe->cache.low && add < pe->cache.high)
    return pe->cache.buffer + (add - pe->cache.low);
  size_t i;
  for (i = 0; i < pe->sections_nb; ++i) {
    if (add >= pe->sections_hdr[i].VirtualAddress &&
	add < pe->sections_hdr[i].VirtualAddress + pe->sections_hdr[i].SizeOfRawData)
      break;
  }
  if (i >= pe->sections_nb)
    return NULL;
  if (pe->sections[i] != NULL)
    return pe->sections[i] + add - pe->sections_hdr[i].VirtualAddress;
  else if (add >= pe->cache.low && add < pe->cache.high)
    return pe->cache.buffer + (add - pe->cache.low);
  else if (pe->cache.lock == 0){
    int offset = (add - pe->sections_hdr[i].VirtualAddress);
    if (offset > PEFILE_CACHE_SIZE / 2)
      offset -= PEFILE_CACHE_SIZE / 2;
    else
      offset = 0;
    pe->cache.low = pe->sections_hdr[i].VirtualAddress + offset;
    fseek (pe->fp, pe->sections_hdr[i].PointerToRawData + offset, SEEK_SET);
    int read = fread (pe->cache.buffer, sizeof(uint8_t), PEFILE_CACHE_SIZE, pe->fp);
    pe->cache.high = pe->cache.low + read;
    add_t high = pe->sections_hdr[i].VirtualAddress + pe->sections_hdr[i].SizeOfRawData;
    if (pe->cache.high > high)
      pe->cache.high = high;
    if (read != PEFILE_CACHE_SIZE)
      memset (pe->cache.buffer + read, 0, PEFILE_CACHE_SIZE - read);
    if (add >= pe->cache.low && add < pe->cache.high)
      return pe->cache.buffer + (add - pe->cache.low);
    return NULL;
  }
  return NULL;
}

