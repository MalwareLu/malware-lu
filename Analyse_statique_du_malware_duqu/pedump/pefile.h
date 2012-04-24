#ifndef MK_PEFILE_H
#define MK_PEFILE_H

/*!
  @file pefile.h
  @brief Library to parse portable executable binaries.
  @par Example:
  @example example-pefile_virtual_goto.c 
  @example example-pefile_extract.c
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "pestruct.h"

typedef uint64_t add_t;

/*!
 Error codes on PE file extraction.
*/
enum pefile_error_t {
  /*!
    No error, all went smoothly.
  */
  PEFILE_ALL_OK,
  /*!
    Error during the extraction of the file header.
  */
  PEFILE_FILE_HDR_ERROR,
  /*!
    Error during the extraction of the optional header.
  */
  PEFILE_OPT_HDR_ERROR,
  /*!
    Error during the extraction of the section table header.
  */
  PEFILE_SEC_TABLE_ERROR,
  /*!
    The file is broken.
  */
  PEFILE_BROKEN_FILE_ERROR,
  /*!
    Unable to malloc.
  */
  PEFILE_TOO_BIG_ERROR,
};


enum arch_t {
  BIT16 = 16,
  BIT32 = 32,
  BIT64 = 64,
};

/*!
  Size of the magic word 
*/
#define PEFILE_MAGIC_LENGTH 4

/*!
 Structure to handle a cache.
*/
typedef struct cache_t{
  uint8_t* buffer;
  add_t high;
  add_t low;
  uint8_t lock;
}cache_t;
/*!
  default size of cache.
*/
#define PEFILE_CACHE_SIZE 0x1000

/*!
 Structure to represent a PE file.
*/
typedef struct pefile_t{
  /*!
    Magic word 
  */
  char magic[PEFILE_MAGIC_LENGTH];
  /*!
    Current virtual.
  */
  add_t current;
  /*!
    Absolute virtual address to the entrypoint.
  */
  add_t entrypoint;
  /*!
    Virtual address to the base of the code.
  */
  add_t baseofcode;
  /*!
    Absolute virtual address to the export table.
  */
  add_t exporttable;
  /*!
    The architecture (16, 32, or 64)
  */
  enum arch_t arch;
  /*!
    The file header structure.
  */
  IMAGE_FILE_HEADER hdr;
  union {
    /*!
      The optional header (for 16/32bit PE files).
    */
    IMAGE_OPTIONAL_HEADER opthdr;
    /*!
      The optional header (for 64bit PE files).
    */
    IMAGE_OPTIONAL_HEADER64 opthdr64;
  };      
  /*!
    Table of the section headers.
  */
  IMAGE_SECTION_HEADER* sections_hdr;
  /*!
    Number of allocated sections.
  */
  size_t sections_nb;
  /*!
    Dump of the sections mapped in memory.
  */
  uint8_t** sections;
  /*!
    Cache for big files.
  */
  cache_t cache;
  /*!
    File pointer.
  */
  FILE* fp;  
} pefile_t;

/*!
  Allocate a pefile_t structure.
  @return pefile A pointer to the newly allocated pefile structure.
*/
void* 
pefile_alloc ();

/*!
  Free a pefile_t structure.
  @param pefile A pointer to the pefile_t structure to free
  @see pefile_extract ()
*/
void 
pefile_free (pefile_t* pefile);

void 
pefile_cache_lock (pefile_t* pe);

void 
pefile_cache_unlock (pefile_t* pe);

/*!
  Extract pe header and sections from file.
  This method allocate memory that should be freed with pefile_free()
  @param pefile pointer to the pefile_t structure to fill
  @param fp file pointer to the source PE file
  @return error code 
  @see pefile_free()
*/
enum pefile_error_t 
pefile_extract (pefile_t* pefile, FILE* fp);

enum pefile_error_t
pefile_extract_raw (pefile_t* pe, FILE* fp, int sz);

uint8_t*
pefile_seek_cache (pefile_t* pe, add_t add);

/*!
  Get a pointer on the memory image corresponding to a virtual address.
  @param pefile the pefile_t structure.
  @param add the virtual address to access.
  @return pointer on pefile->buffer corresponding to error the given virtual address.
*/
uint8_t* 
pefile_virtual_goto (pefile_t* pefile, add_t add);

#endif

