#include <pefile.h>
#include <getopt.h>
#include <stdint.h>

/*! Verbose levels */
enum verbose_t{
  VERBOSE_LOW,
  VERBOSE_NORMAL,
  VERBOSE_HIGH,
};

/*! Structure to represent the arguments */
typedef struct _args_t {
  /*! Verbose level */
  enum verbose_t verbose;
  /*! Verbose level */
  char* input;
  char* output;
} args_t;

/*! Print the usage on standar output */
void
print_usage (){ 
  printf ("\n");
  printf ("Usage: pedump [option] pefile\n");
  printf ("\t pefile \t Name of the portable executable to dump\n");
  printf ("\n");
  printf ("Description: \n");
  printf ("\t Parse a portable executable file [pefile] and dump its memory mapping.\n");
  printf ("\n");
  printf ("Option: \n");
  printf ("\t --ouput filename \t Redirect output to filename. \n");
  printf ("\t --verbose        \t More verbose. \n");
  printf ("\t --quiet          \t Be quiet. \n");
  printf ("\t --help           \t Give this help list. \n");
  printf ("\n");
}

/*! Parse command line arguments.
  @param argc number of arguments.
  @argv table of arguments.
*/
args_t
parse_args (int argc, char **argv){
  args_t args = {
    .verbose = VERBOSE_NORMAL,
    .input = NULL,
    .output = NULL,
  };

  /* Description of options */
  static struct option long_options[] ={
    {"verbose",  no_argument, 0, 'v'},
    {"quiet",  no_argument, 0, 'q'},
    {"help",  no_argument, 0, 'h'},
    {"output",  required_argument, 0, 'o'},
  };

  /* Parsing options */
  int c = 0, index = 0;
  while ( (c = getopt_long (argc, argv, "r:s:",long_options, &index)) != -1 ){
    switch ( c ){
    case 'v':
      args.verbose=VERBOSE_HIGH;
      break;
    case 'q':
      args.verbose=VERBOSE_LOW;
      break;
    case 'h':
      print_usage ();
      exit (0);
      break;
    case 'o':
      args.output = optarg;
      break;
    default:
      printf("unrecognized option -%c %s", c, optarg);
      print_usage ();   
      exit (1);
    }
  }     

  /* Parsing remaining args */
  if (optind > argc){
    print_usage ();  
    exit (1);
  }
  else 
    args.input = argv[optind];
  return args;
}

int 
main (int argc, char** argv){
  args_t args = parse_args (argc, argv);
  FILE* fp = fopen (args.input, "rb");
  if (fp == NULL){
    printf ("error: cannot open %s", args.input);
    exit (0);
  }
  pefile_t* pefile = pefile_alloc ();
  int error = pefile_extract (pefile, fp);
  fclose (fp);
  switch (error){
  case PEFILE_ALL_OK:
    if (args.verbose >= VERBOSE_HIGH)
      fprintf (stderr, "Extraction done with no errors\n");
    break;
  case PEFILE_FILE_HDR_ERROR:
    fprintf (stderr, "Error during the extration of the file header\n");
    break;
  case PEFILE_OPT_HDR_ERROR:
    fprintf (stderr, "Error during the extration of the optional header\n");
    break;
  case PEFILE_SEC_TABLE_ERROR:
    fprintf (stderr, "Error during the extration of the section headers\n");
    break;
  case PEFILE_BROKEN_FILE_ERROR:
    if (args.verbose >= VERBOSE_NORMAL)
      fprintf (stderr, "The file is broken\n");
    break;
  case PEFILE_TOO_BIG_ERROR:
    fprintf (stderr, "Unable to malloc\n");
    break;
  }
  FILE* output = stdout;
  if (args.output != NULL)
    output = fopen (args.output, "wb");
  size_t i; 
  add_t max = 0;
  for (i = 0; i < pefile->sections_nb; ++i){
    add_t current = pefile->baseofcode+pefile->sections_hdr[i].VirtualAddress + pefile->sections_hdr[i].SizeOfRawData;
    if (max < current)
      max = current;
  }
  add_t add;
  for (add = pefile->baseofcode; add < max; ++add){
	char *c = pefile_virtual_goto(pefile, add);
	if ( c != NULL )
	  putc(*c, output);
	else
	  putc(0,output);
  }
  if (args.output != NULL)
    fclose (output);
  pefile_free (pefile);
  return 0;
}
