#include "dynamic1.h"
#include "lib2_dynamic.h"
#include <stdio.h>
#include <dlfcn.h>
    
typedef void (*_FUNC)();
_FUNC g_dynamic1_func;
void open_dl() {
    void *_handle = dlopen("./libdynamic1.so", RTLD_LAZY|RTLD_LOCAL|RTLD_DEEPBIND);
    if (NULL == _handle) {
        printf("get_external_encrypt_handle failed, open lib\n");
        return;
    }
    dlerror();

    g_dynamic1_func = (_FUNC)(dlsym(_handle, "dynamic1_func"));
    if (NULL != dlerror()) {
        printf("Impl failed, get encrypt func\n");
        dlclose(_handle);
        _handle = NULL;
        return;
    }
}


int main(int argc, const char* argv[]) {
   open_dl();
    printf("hello\n");
   g_dynamic1_func();
//    dynamic1_func();

    lib2_func();

    printf("hello\n");

    return 1;
}

