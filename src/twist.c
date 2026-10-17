/* twist.c - Main source file for Twist

   Copyright (C) 2026 Chris

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "config.h"
#include "twist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Print program version */
void
Twist_print_version(void)
{
  printf("Twist version %s\n", PACKAGE_VERSION);
  printf("Copyright (C) 2026 Chris\n");
  printf("License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>\n");
  printf("This is free software: you are free to change and redistribute it.\n");
  printf("There is NO WARRANTY, to the extent permitted by law.\n");
}

/* Print usage information */
void
Twist_print_help(void)
{
  printf("Usage: %s [OPTION]... [FILE]...\n", PACKAGE_NAME);
  printf("\n");
  printf("A sample GNU program.\n");
  printf("\n");
  printf("Options:\n");
  printf("  -h, --help         Show this help message and exit\n");
  printf("  -v, --version      Show version information and exit\n");
  printf("\n");
  printf("Report bugs to: %s\n", PACKAGE_BUGREPORT);
  printf("Home page: %s\n", PACKAGE_URL);
}

/* Process a file */
int
Twist_process_file(const char *filename)
{
  FILE *fp;
  int c;
  size_t count = 0;

  if (strcmp(filename, "-") == 0)
    fp = stdin;
  else
    {
      fp = fopen(filename, "r");
      if (!fp)
        {
          perror(filename);
          return TWIST_EXIT_FAILURE;
        }
    }

  while ((c = getc(fp)) != EOF)
    {
      putchar(c);
      count++;
    }

  if (fp != stdin)
    fclose(fp);

  fprintf(stderr, "Processed %zu bytes from %s\n", count, filename);
  return TWIST_EXIT_SUCCESS;
}

/* Main function */
int
main(int argc, char *argv[])
{
  int i;
  int exit_status = TWIST_EXIT_SUCCESS;

  /* Parse command line options */
  for (i = 1; i < argc; i++)
    {
      if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
          Twist_print_help();
          return TWIST_EXIT_SUCCESS;
        }
      else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0)
        {
          Twist_print_version();
          return TWIST_EXIT_SUCCESS;
        }
      else if (argv[i][0] == '-')
        {
          fprintf(stderr, "%s: unknown option '%s'\n", PACKAGE_NAME, argv[i]);
          fprintf(stderr, "Try '%s --help' for more information.\n", PACKAGE_NAME);
          return TWIST_EXIT_FAILURE;
        }
      else
        {
          if (Twist_process_file(argv[i]) != TWIST_EXIT_SUCCESS)
            exit_status = TWIST_EXIT_FAILURE;
        }
    }

  /* If no files specified, process stdin */
  if (argc == 1)
    {
      if (Twist_process_file("-") != TWIST_EXIT_SUCCESS)
        exit_status = TWIST_EXIT_FAILURE;
    }

  return exit_status;
}
