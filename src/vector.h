/* vector.h - macro implementation of generic vector data structure */

#ifndef VECTOR_H
#define VECTOR_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* [Internal] Actual storage type of a generic vector. This macro is 
 * implementation-specific and should not be used directly in client code.
 */
#define VECTOR_STRUCT(Ty)   \
    struct {                \
        size_t elemsize;    \
        Ty *p;              \
        size_t count;       \
        size_t capacity;    \
    }

/* [Internal] Vector that stores an array of void elements. This macro is
 * used by certain macros just to get the size of the actual storage.
 */
typedef VECTOR_STRUCT(void) VECTOR_VOID_STRUCT;

/* Declares a vector containing elements of type Ty. */
#define VECTOR(Ty) VECTOR_STRUCT(Ty) *

/* Creates a vector, v, of type Ty. */
#define VECTOR_CREATE(v, Ty) \
    do { \
        (v) = calloc(1, sizeof(VECTOR_VOID_STRUCT)); \
        (v)->elemsize = sizeof(Ty); \
    } while (0)

/* Destroys a vector, v. */
#define VECTOR_DESTROY(v) \
    do { \
        if (v) { \
            free((v)->p); \
            free(v); \
        } \
    } while (0)

/* Returns a pointer to the first element in the vector. */
#define VECTOR_DATA(v) ((v)->p)

/* Returns a reference to the i-th element in the vector. */
#define VECTOR_AT(v, i) ((v)->p[i])

/* Returns a boolean value indicating whether the vector is empty. */
#define VECTOR_EMPTY(v) ((v)->count == 0)

/* Returns the number of elements in a vector. */
#define VECTOR_SIZE(v) ((v)->count)

/* Reserves at least _cap_ elements in the vector, and returns a pointer
 * to the (possibly reallocated) underlying buffer.
 */
#define VECTOR_RESERVE(v,cap) \
    ( \
        ((cap) <= (v)->capacity) ? \
            ((v)->p) : \
            ((v)->p = realloc((v)->p, (v)->elemsize * ((v)->capacity = cap))) \
    )

/* Push an element to the end of the array. Returns an lvalue that refers to
 * the pushed element.
 */
#define VECTOR_PUSH(v,elem) \
    ( \
        ( ((v)->count < (v)->capacity)? (v)->p : \
              VECTOR_RESERVE(v, (10 > (v)->capacity * 2 ? 10 : (v)->capacity * 2)) \
        ) [++(v)->count - 1] = (elem) \
    )

/* Pop an element from the end of the vector. Returns an lvalue to the element
 * originally stored at the end of the vector.
 */
#define VECTOR_POP(v) ((v)->p[--(v)->count])

/* Sort the elements in a vector using the C qsort() library function. */
#define VECTOR_QSORT(v, comparer) \
    qsort((v)->p, (v)->count, (v)->elemsize, (comparer))

#if 0
#define QUEUE(Ty) VECTOR(Ty)
#define QUEUE_CREATE(q,Ty) VECTOR_CREATE(q,Ty)
#define QUEUE_DESTROY(q) VECTOR_DESTROY(q)
#define QUEUE_EMPTY(q) VECTOR_EMPTY(q)
#define QUEUE_PUSH(q,elem) VECTOR_PUSH(q,elem)
#define QUEUE_POP(q) VECTOR_POP(q)
#endif

#ifdef __cplusplus
}
#endif

#endif /* VECTOR_H */
