
#include <x86intrin.h>  

int
main(void)
{
    unsigned int j;
    __attribute__ ((aligned(16))) int temp[4] =
        {0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF};

    __m128 const_sign_bit_0 = _mm_load_ps((float *) temp);


/*
    for (j = 0; j < size/4; j++, src+=4)
    {
        src4 = _mm_load_ps(src);    // load the 4 src values
        src4 = _mm_and_ps(src4, const_sign_bit_0);      // clear bit 31
        _mm_store_ps(src, src4);    // store the 4 values back
}
*/
}

