#include <linux/calclock.h>

KTDEC(__handle_mm_fault);
void print_all() {
	ktprint(0, __handle_mm_fault);
}
