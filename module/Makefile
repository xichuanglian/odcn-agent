ifndef MODULE_DIR
MODULE_DIR = $(PWD)
endif

ifndef PROJECT_INCLUDE
PROJECT_INCLUDE = $(PWD)/../include
endif

obj-m += agent_module.o
agent_module-y += module.o
ccflags-y := -I$(PROJECT_INCLUDE)
KVERSION = $(shell uname -r)

modules: module.c
	make -C /lib/modules/$(KVERSION)/build M=$(MODULE_DIR) modules

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(MODULE_DIR) clean
