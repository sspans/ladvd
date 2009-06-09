
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <check.h>

#include "../src/config.h"
#include "../src/compat/compat.h"

#ifndef HAVE_SETPROCTITLE
START_TEST(test_setproctitle) {
    int argc = 1;
    char **argv; 
    extern char *__progname;
    char *ptitle = NULL;
    const char *str = "123456788ABCDEF";

    extern int check_fail_calloc;

    argv = calloc(argc + 1, sizeof(*argv));

    argv[0] = malloc(BUFSIZ);
    memset(argv[0], 0, BUFSIZ);
    memset(argv[0], 'a', 1);
    argv[1] = NULL;

    compat_init_setproctitle(0, argv);
    check_fail_calloc = 1;
    compat_init_setproctitle(argc, argv);
    check_fail_calloc = 0;
    compat_init_setproctitle(argc, argv);
    setproctitle(str);

    memset(argv[0], 'a', BUFSIZ - 1);
    compat_init_setproctitle(argc, argv);
    setproctitle(str);

    asprintf(&ptitle, "%s: %s", __progname, str);
    fail_unless (strcmp(argv[0], ptitle) == 0,
	"title should be '%s' not '%s'", ptitle, argv[0]);
}
END_TEST
#endif /* HAVE_SETPROCTITLE */

#ifndef HAVE_STRLCAT
START_TEST(test_strlcat) {
    char dst[BUFSIZ];
    const char *src = "0123456789ABCDEF";
    size_t len = 0;

    memset(&dst, 0, BUFSIZ);
    len = strlcat(dst, src, 0);
    fail_unless (strlen(dst) == 0, "length should be 0");
    len = strlcat(dst, src, 1);
    fail_unless (strlen(dst) == 0, "length should be 0");
    len = strlcat(dst, src, 10);
    fail_unless (strlen(dst) == 9, "length should be equal to 9");

    memset(&dst, 0, BUFSIZ);
    len = strlcat(dst, src, BUFSIZ);
    fail_unless (strlen(dst) == strlen(src),
	"length should be equal to src");
    len = strlcat(dst, src, BUFSIZ);
    fail_unless (strlen(dst) == strlen(src) * 2,
	"length should be equal to src * 2");

    memset(&dst, 'a', BUFSIZ - 8);
    len = strlcat(dst, src, BUFSIZ);
    fail_unless (strlen(dst) == BUFSIZ - 1, "length should be BUFSIZ - 1");

    memset(&dst, 'a', BUFSIZ - 1);
    len = strlcat(dst, src, BUFSIZ);
    fail_unless (strlen(dst) == BUFSIZ - 1, "length should be BUFSIZ - 1");
}
END_TEST
#endif  /* HAVE_STRLCAT */

#ifndef HAVE_STRLCPY
START_TEST(test_strlcpy) {
    char dst[BUFSIZ];
    const char *src = "0123456789ABCDEF";
    size_t len = 0;

    memset(&dst, 0, BUFSIZ);
    len = strlcpy(dst, src, 0);
    fail_unless (strlen(dst) == 0, "length should be 0");
    len = strlcpy(dst, src, 1);
    fail_unless (strlen(dst) == 0, "length should be 0");
    len = strlcpy(dst, src, 10);
    fail_unless (strlen(dst) == 9, "length should be equal to 9");

    memset(&dst, 0, BUFSIZ);
    len = strlcpy(dst, src, BUFSIZ);
    fail_unless (strlen(dst) == strlen(src), "length should be equal to src");

    memset(&dst, 'a', BUFSIZ);
    len = strlcpy(dst, src, BUFSIZ);
    fail_unless (strlen(dst) == strlen(src), "length should be equal to src");
}
END_TEST
#endif /* HAVE_STRLCPY */

Suite * compat_suite (void) {
    Suite *s = suite_create("libcompat");

    // compat test case
    TCase *tc_compat = tcase_create("libcompat");
#ifndef HAVE_SETPROCTITLE
    tcase_add_test(tc_compat, test_setproctitle);
#endif /* HAVE_SETPROCTITLE */
#ifndef HAVE_STRLCAT
    tcase_add_test(tc_compat, test_strlcat);
#endif  /* HAVE_STRLCAT */
#ifndef HAVE_STRLCPY
    tcase_add_test(tc_compat, test_strlcpy);
#endif /* HAVE_STRLCPY */
    suite_add_tcase(s, tc_compat);

    return s;
}

int main (void) {
    int number_failed;
    Suite *s = compat_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

