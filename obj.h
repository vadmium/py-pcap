#ifndef __EXCEPT_H__
#define __EXCEPT_H__

#include <stdlib.h>

/* obj.h: objecty and exceptiony stuff
 *
 * Some macros to make C a bit more like C++, but without bringing in
 * all of C++'s crapola.
 */

/* Here's an example:
 *
 * int
 * foo()
 * {
 *   struct bar *b = NULL;
 *   FILE       *f = NULL;
 *
 *   attempt {
 *     b = new(struct bar);
 *     if (! b) fail;
 *
 *     f = fopen("foo", "r");
 *     if (! f) fail;
 *
 *     (void)fgets(b->baz, 10, f);
 *   }
 *
 *   if (f) {
 *     (void)fclose(f);
 *   }
 *
 *   recover {
 *     if (b) {
 *       free(b);
 *     }
 *     return -1;
 *   }
 *
 *   return 0;
 * }
 */

/** Exception-type things
 *
 * These allow you to have pseudo-exceptions.  It looks kludgy and it
 * is, but it's only that way so you can have nice pretty code.
 */
static int __obj_passed = 0;
#define attempt for (__obj_passed = 0; !__obj_passed; __obj_passed = 1)
#define fail break
#define succeed continue
#define recover if (__obj_passed ? (__obj_passed = 0) : 1)

#define new(type) (type *)calloc(1, sizeof(type))

#endif
