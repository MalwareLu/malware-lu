#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef WINDOWS
	#include <windows.h>
#else
	#include "winnt.h"
#endif

// Stage2 fixed data, update if stage change
#define BIN_OFFSET 0x171
#define KEY2 0x3e9
#define CHUNK2 0x78
#define JUNK2 0x1

#define min(a, b) (((a) < (b)) ? (a) : (b))

uint8_t *readfile(uint8_t *filename, uint32_t *size)
{
	uint8_t *src = NULL;
	uint32_t r = 0;

	FILE *fp = fopen(filename, "rb");
	if (fp == NULL){
		perror("fopen");
		return NULL;
	}

	fseek(fp, 0, SEEK_END);
	*size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	src = malloc(*size * sizeof(uint8_t));
	if (src == NULL){
		perror("malloc");
		fclose(fp);
		return NULL;
	}

	r = fread(src, sizeof(uint8_t), *size, fp);
	if (r != *size){
		if (r < 0){
			perror("fread");
		}else{
			fprintf(stderr, "Read failed size don't match.\n");
		}
		return NULL;

	}
	fclose(fp);
	return src;
}

uint8_t writefile(uint8_t *filename, uint8_t *src, uint32_t size)
{
	uint32_t r = 0;

	FILE *fp = fopen(filename, "wb");
	if (fp == NULL){
		perror("fopen");
		return EXIT_FAILURE;
	}

	r = fwrite(src, sizeof(uint8_t), size, fp);
	if (r != size){
		if (r < 0){
			perror("fwrite");
		}else{
			fprintf(stderr, "Write failed size don't match.\n");
		}
		return EXIT_FAILURE;

	}
	fclose(fp);
	return EXIT_SUCCESS;
}

uint32_t extractbasedoffset(uint8_t *src, uint32_t size)
{
	uint32_t i;
	uint32_t offset = 0;

	// The first is good normally
	for (i=0; i < size; ++i){
                if (src[i] != 0xc7 || src[i+1] != 0x05)
			continue;

		if (src[i+10] == 0x5d || src[i+11] == 0xc3){
			offset = *(uint32_t*)(src+i+6);
			//printf(" [*] offset: 0x%08x\n", offset);
			break;
		}
		if(src[i+12] == 0x5d || src[i+13] == 0xc3){
			offset = *(uint32_t*)(src+i+6);
			//printf(" [*] offset2: 0x%08x\n", offset);
			break;
		}
	}
	if (offset !=0) return offset;

	// Nothing round two
	// cause dc37799a0693ec6ddaa00149771420e4
	for (i=0; i < size; ++i){
                if (src[i] != 0xc7 || src[i+1] != 0x05)
			continue;

		if (src[i+10] == 0x8b || src[i+11] == 0x0d){
			offset = *(uint32_t*)(src+i+6);
			//printf(" [*] offset: 0x%08x\n", offset);
			break;
		}
	}
	

	return offset;
}

uint32_t extractoffset(uint8_t *src, uint32_t size)
{
	// PE section text
	uint32_t offset = 0, i;
	uint32_t based_offset, base_adr;

	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS32 nt_headers;
	PIMAGE_SECTION_HEADER sect_header;	

	dos_header = (PIMAGE_DOS_HEADER)src;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE){
		fprintf(stderr, "Not a valid MZ.\n");
		return 0;
	}

	nt_headers = (PIMAGE_NT_HEADERS32)( src + dos_header->e_lfanew );
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE ){
		fprintf(stderr, "Not a valid PE.\n");
		return 0;
	}
	
	base_adr = nt_headers->OptionalHeader.ImageBase;
	printf(" [*] base adr: 0x%08x\n", base_adr);

	based_offset = extractbasedoffset(src, size);
	if ( based_offset == 0){
		return 0;
	}
	printf(" [*] based offset: 0x%08x\n", based_offset);

	for (i=0; i < nt_headers->FileHeader.NumberOfSections; ++i){
		sect_header = (PIMAGE_SECTION_HEADER)(src + 
			dos_header->e_lfanew +
			sizeof(IMAGE_NT_HEADERS32) +
			(i * sizeof(IMAGE_SECTION_HEADER)));
		
		if ( base_adr + sect_header->VirtualAddress <= based_offset && 
				based_offset <= (base_adr + 
					sect_header->VirtualAddress + 
					sect_header->SizeOfRawData)){
			offset = sect_header->PointerToRawData + 
				based_offset - base_adr - 
				sect_header->VirtualAddress - sizeof(uint32_t);
		}
		/*if( strcmp(".text",  sect_header->Name) == 0 ){
			offset = sect_header->PointerToRawData;
		}*/
	}

	return offset;
}

uint32_t extractkey(uint8_t *src, uint32_t size)
{
	// Regex style
	uint32_t key = 0;
	uint32_t i;
	
	// The first is good normally
	for (i=0; i < size; ++i){
		/* Sequence start with 0x8b 0x55 and finish with 0x89 */
		//if (src[i] != 0x8b || src[i+1] != 0x55 || src[i+2] != 0xf0)
		//	continue;

		/* add ebx, XXXX */
		if (src[i+3] == 0x81 && src[i+4] == 0xc2 && src[i+9] == 0x89){
			key = *(uint32_t*)(src+i+5);
			break;
		}
		
		/* add ebx, XX */
		if (src[i+3] == 0x83 && src[i+4] == 0xc2 && src[i+6] == 0x89){
			key = src[i+5];
			break;
		}
	}

	return key;
}

uint8_t extractindex(uint8_t *src, uint32_t size, 
		uint32_t *chunk, uint32_t *junk)
{
	// maxi regex style
	uint32_t i;
	*chunk = 0; *junk = 0;

	// The first is good normally
	for (i=0; i < size; ++i){
		if (src[i] != 0xc7)
			continue;
		if (src[i+1] == 0x85){
			/* mov[ebp+var_XXX], XXXX ; Chunk
			 * mov[ebp+var_XXX], XXXX ; Junk
			 * mov[ebp+var_XXX], 0000  
			 * mov[ebp+var_XXX], 0000 */
			if (src[i+(1*10)] != 0xc7 || src[i+(1*10)+1] != 0x85)
				continue;
			if (src[i+(2*10)] != 0xc7 || src[i+(2*10)+1] != 0x85)
				continue;
			if (memcmp("\x00\x00\x00\x00", src+i+(2*10)+6, 4) != 0)
				continue;
			if (src[i+(3*10)] != 0xc7 || src[i+(3*10)+1] != 0x85)
				continue;
			if (memcmp("\x00\x00\x00\x00", src+i+(3*10)+6, 4) != 0)
				continue;
			*chunk = *(uint32_t*)(src+i+(0*10)+6);
			*junk = *(uint32_t*)(src+i+(1*10)+6);

			// inconsistency go next
			if (*chunk <= *junk) continue;

			return EXIT_SUCCESS;
		}
		if (src[i+1] == 0x45){
			/* mov[ebp+var_X], XXXX ; Chunk
			 * mov[ebp+var_X], XXXX ; Junk
			 * mov[ebp+var_X], 0000  
			 * mov[ebp+var_X], 0000 */
			if (src[i+(1*7)] != 0xc7 || src[i+(1*7)+1] != 0x45)
				continue;
			if (src[i+(2*7)] != 0xc7 || src[i+(2*7)+1] != 0x45)
				continue;
			if (memcmp("\x00\x00\x00\x00", src+i+(2*7)+3, 4) != 0)
				continue;
			if (src[i+(3*7)] != 0xc7 || src[i+(3*7)+1] != 0x45)
				continue;
			if (memcmp("\x00\x00\x00\x00", src+i+(3*7)+3, 4) != 0)
				continue;
			*chunk = *(uint32_t*)(src+i+(0*7)+3);
			*junk = *(uint32_t*)(src+i+(1*7)+3);
			
			// inconsistency go next
			if (*chunk <= *junk) continue;

			return EXIT_SUCCESS;
		}
	}

	return EXIT_FAILURE;
}

void decode(uint8_t *dst, uint8_t *src, uint32_t size, 
		uint32_t key, uint32_t chunk, uint32_t junk)
{
	uint32_t i, s, rest;
	uint32_t x = 0, y =0;

	/* Part1, clean the src by removing junk */
	rest = size;
	while( x < size ){
		s = min(chunk, rest);
		memcpy(dst+x, src+y, s);
		x += chunk;
		y += chunk + junk;
		rest -= s;
	}

	/* Part2 */
	for (i=0; i < size; i+=4){
		*(uint32_t*)(dst+i) += i;
		*(uint32_t*)(dst+i) ^= (i + key);
	}
}

int main(int argc, char *argv[])
{
	uint8_t *src = NULL, *payload = NULL, *binary = NULL;
	uint32_t src_size = 0, payload_size = 0, binary_size = 0;
	uint32_t key = 0, offset = 0, chunk = 0, junk = 0;

	if (argc < 2) {
		fprintf(stderr, "%s <packedfile> [<unpackedfile>]\n", argv[0]);
		return EXIT_FAILURE;
	}
	printf (" [*] Unpack file %s\n", argv[1]);
	// Read file
	src = readfile(argv[1], &src_size);
	if (src == NULL) return EXIT_FAILURE;

	// Extract offset
	offset = extractoffset(src, src_size);
	if (offset == 0){
		fprintf(stderr, " [x] Failed to extract payload offset!\n");
		free(src);
		return EXIT_FAILURE;
	}
	printf(" [*] Extracted payload offset: 0x%08x\n", offset);

	// Extract key
	key = extractkey(src, src_size);
	if (key == 0){
		fprintf(stderr, " [x] Failed to extract key!\n");
		free(src);
		return EXIT_FAILURE;
	}
	printf(" [*] Extracted key: 0x%08x\n", key);

	// Extract index
	if (extractindex(src, src_size, &chunk, &junk) != EXIT_SUCCESS){
		fprintf(stderr, " [x] Failed to extract chunk and junk!\n");
		free(src);
		return EXIT_FAILURE;
	}
	printf(" [*] Extracted chunk: 0x%x junk: 0x%x\n", chunk, junk);
	
	// Extract payload size
	payload_size = *(uint32_t *)(src + offset);
	printf(" [*] Payload size: %d\n", payload_size);

	// Diry secure check
	if (payload_size >= src_size){
                fprintf(stderr, " [x] Failed, something goes "\
				"wrong payload size too heavy!\n");
		free(src);
		return EXIT_FAILURE;
	}

	// Alloc payload memory
	payload = malloc(payload_size * sizeof(uint8_t));
	if (payload == NULL){
		perror("malloc");
		free(src);
		return EXIT_FAILURE;
	}

	// Extract and decode payload
	printf(" [*] Extract payload...\n");
	decode(payload, src + offset + sizeof(uint32_t), payload_size,
		key, chunk, junk);
	
	/* Get bin file in the payload */
	binary_size = *(uint32_t *)(payload + BIN_OFFSET);
	printf(" [*] Binary size: %d\n", binary_size);
	
	// Alloc binary memory
	binary = malloc(binary_size * sizeof(uint8_t));
	if (binary == NULL){
		perror("malloc");
		free(src); free(binary);
		return EXIT_FAILURE;
	}

	// Extract and decode binary
	printf(" [*] Extract binary...\n");
	decode(binary, payload + BIN_OFFSET + sizeof(uint32_t), binary_size,
		KEY2, CHUNK2, JUNK2);

	// Fast check MZ
	if ( *(uint16_t*)binary != IMAGE_DOS_SIGNATURE){
		fprintf(stderr, " [x] Check MZ failed!\n");
		free(src); free(payload); free(binary);
		return EXIT_FAILURE;
	}
	
	if (argc == 3){
		writefile(argv[2], binary, binary_size);
		printf(" [*] File unpack: %s\n", argv[2]);
	}

	printf(" [*] Finish!\n");

	free(src); free(payload); free(binary);
	return EXIT_SUCCESS;
}
