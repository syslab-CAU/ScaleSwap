obj-m	+= swap.o
swap-y	:= swap_profiling_module.o print_clock.o calclock.o calclock2.o mm/memory.o \
			 mm/page_alloc.o mm/page_isolation.o mm/mempolicy.o mm/vmscan.o \
			 mm/page_io.o block/blk-core.o block/blk-mq.o block/blk-wbt.o \
			 mm/swap_state.o mm/filemap.o mm/swapfile.o mm/swap_slots.o mm/shmem.o \
			 mm/rmap.o mm/kswapd_worker.o mm/memcontrol.o mm/page_counter.o init_lruvec.o # arch/mm/tlb.o 

# lock_folio_counter.o

# obj-$(CONFIG_MEMCG) += 

ccflags-y += -g
ccflags-y += -I/home/syslab/workspace_cmh/swap_test/pxt4-6.6.8-vanilla/linux-6.6.8/include
# kernel/sched/fair.o 


KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	sudo $(MAKE) -C $(KDIR) M=$(PWD) modules_install
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(RM) Modules.markers modules.order
