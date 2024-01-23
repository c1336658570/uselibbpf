// gcc memleak_test.c -g -o memleak_test
// ./memleak_test &

// sudo ./memleakv1 pid
// touch /tmp/memleakv1_print
// touch /tmp/memleakv1_quit

// sudo ./memleakv2 pid
// touch /tmp/memleakv2_print
// touch /tmp/memleakv2_quit

// 人为制造内存泄漏的代码
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void * alloc_v3(int alloc_size)
{
    void * ptr = malloc(alloc_size);
    
    return ptr;
}

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
            free(ptr);
        }
    }

    return 0;
}