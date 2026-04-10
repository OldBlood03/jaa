#ifndef DARRAY
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#define DARRAY
#define INIT_CAPACITY 32
typedef struct darray_header{
    int size;
    int capacity;
}darray_header;

#define darray(type) type*
#define darray_size(arr) (assert(arr != NULL && "cannot take length of a NULL pointer"), ((darray_header *)(arr) - 1)->size);
#define darray_push_back(arr, elem) do{\
    if(arr == NULL)\
    {\
        arr = malloc(INIT_CAPACITY * sizeof(*arr) + sizeof(darray_header));\
        *(darray_header *)arr = (darray_header){.size = 0, .capacity = INIT_CAPACITY * sizeof(*arr)};\
        arr = (void *)((darray_header *)arr + 1);\
    }\
    darray_header *hp = (void *)((darray_header *)arr - 1);\
    if (hp->size >= hp->capacity)\
    {\
        hp->capacity *= 2;\
        arr = (void *)((darray_header *)realloc(hp, sizeof(*arr) * hp->capacity + sizeof(darray_header)) + 1);\
        assert(arr);\
    }\
    arr[hp->size] = (elem);\
    hp->size++;\
}\
while(0)

#define darray_pop(arr) (\
    assert((((darray_header *)arr - 1)->size > 0) && "no more elements to pop"),\
    ((darray_header *)arr - 1)->size--,\
    arr[((darray_header *)arr - 1)->size]\
)

#define darray_remove(arr, i) do{\
    int size = ((darray_header *)arr - 1)->size;\
    assert(size > i && "trying to remove out of bounds element");\
    assert(i >= 0 && "lowest element is 0");\
    for (int curr = i, next = i+1; next < size; curr++, next++)\
        arr[curr] = arr[next];\
    ((darray_header *)arr - 1)->size--;\
}\
while(0)

//int main(void)
//{
//    darray(int) arr = NULL;
//    darray_push_back(arr, 1);
//    darray_push_back(arr, 2);
//    darray_push_back(arr, 3);
//    darray_push_back(arr, 2);
//    darray_remove(arr, -1);
//    int size = darray_size(arr);
//    for (int i = 0; i < size; i++)
//    {
//        printf("%d\n", arr[i]);
//    }
//}

#endif //DARRAY
