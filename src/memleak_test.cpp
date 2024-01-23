// g++ memleak_test.cpp -o memleak_test -g
// ./memleak_test &
// sudo ./memleak pid
// touch /tmp/memleak_print
// touch /tmp/memleak_quit

// 人为制造内存泄漏的代码
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if 0
static void * alloc_v3(int alloc_size)
{
    void * ptr = malloc(alloc_size);
    
    return ptr;
}
#endif

#if 0
static void * alloc_v3(int alloc_size)
{
    void * memptr = NULL;
    posix_memalign(&memptr, 128, 1024);
    return memptr;
}
#endif

#if 1
static void * alloc_v3(int alloc_size)
{
    void * ptr = new char[alloc_size];
    
    return ptr;
}
#endif

static void * alloc_v2(int alloc_size)
{
    void * ptr = alloc_v3(alloc_size);

    return ptr;
}

static void * alloc_v1(int alloc_size)
{
    void * ptr = alloc_v2(alloc_size);

    return ptr;
}

int main(int argc, char * argv[])
{
    const int alloc_size = 4;
    void * ptr = NULL;
    int i = 0;

    for (i = 0; ; i++)
    {
        ptr = alloc_v1(alloc_size);

        sleep(2);

        if (0 == i % 2)
        {
            // free(ptr);
            delete [] (char *)ptr;
        }
    }

    return 0;
}
