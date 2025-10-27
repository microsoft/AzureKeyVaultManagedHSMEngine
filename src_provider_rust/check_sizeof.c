#include <stdio.h>
#include <openssl/core.h>

int main() {
    printf("sizeof(OSSL_DISPATCH) = %zu\n", sizeof(OSSL_DISPATCH));
    printf("sizeof(int) = %zu\n", sizeof(int));
    printf("sizeof(void (*)(void)) = %zu\n", sizeof(void (*)(void)));
    
    OSSL_DISPATCH test = {1, NULL};
    printf("offsetof function field = %zu\n", (size_t)&test.function - (size_t)&test);
    
    return 0;
}
