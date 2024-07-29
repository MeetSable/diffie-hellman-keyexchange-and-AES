#include "dhk.h"

int main(int argc, char* argv[])
{
    generate_and_write_dh_params(argv[1]);
    return 0;
}