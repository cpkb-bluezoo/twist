/* test-twist.c - Test suite for Twist

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

/* Test counter */
static int tests_passed = 0;
static int tests_failed = 0;

/* Test result */
static void
TEST_RESULT(int success, const char *test_name)
{
  if (success)
    {
      printf("PASS: %s\n", test_name);
      tests_passed++;
    }
  else
    {
      printf("FAIL: %s\n", test_name);
      tests_failed++;
    }
}

/* Test version string */
static void
TEST_VERSION(void)
{
  /* This is a simple test that version is defined */
  TEST_RESULT(PACKAGE_VERSION != NULL && strlen(PACKAGE_VERSION) > 0,
              "Package version is defined");
}

/* Test help function */
static void
TEST_HELP(void)
{
  /* This test just verifies the function can be called */
  Twist_print_help();
  TEST_RESULT(1, "Help function runs without error");
}

/* Test version function */
static void
TEST_VERSION_PRINT(void)
{
  /* This test just verifies the function can be called */
  Twist_print_version();
  TEST_RESULT(1, "Version function runs without error");
}

/* Main test function */
int
main(void)
{
  printf("Running Twist test suite...\n\n");

  TEST_VERSION();
  TEST_HELP();
  TEST_VERSION_PRINT();

  printf("\n");
  printf("Test results:\n");
  printf("  Passed: %d\n", tests_passed);
  printf("  Failed: %d\n", tests_failed);
  printf("\n");

  if (tests_failed > 0)
    {
      printf("Some tests FAILED.\n");
      return EXIT_FAILURE;
    }
  else
    {
      printf("All tests PASSED.\n");
      return EXIT_SUCCESS;
    }
}
