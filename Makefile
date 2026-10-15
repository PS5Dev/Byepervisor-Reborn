#   Copyright (C) 2023 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := byepervisor_reborn.elf
CENSUS_1270_ELF := census_1270.elf

PAYLOAD_DIR := break_hv_payload
PAYLOAD_HDR := $(PAYLOAD_DIR)/break_hv.h

CFLAGS := -Wall -Werror -Wno-unused-function -g -I./include -DENABLE_FW_1270
HOST_CC ?= cc

all: $(ELF)

STRIKE_HDR_1270 := $(PAYLOAD_DIR)/vmcb_strike_1270.h

$(ELF): byepervisor_1270.c textmap_1270.c khook_1270.c \
        $(STRIKE_HDR_1270) include/byepervisor_1270.h \
        include/khook_1270_alias.h include/textmap_1270.h \
        include/offsets/12_70_candidate.h

$(STRIKE_HDR_1270): $(PAYLOAD_DIR)/vmcb_strike_1270.c \
                     $(PAYLOAD_DIR)/entry_1270.S \
                     $(PAYLOAD_DIR)/link_strike_1270.ld \
                     $(PAYLOAD_DIR)/build_vmcb_strike_1270.sh
	sh $(PAYLOAD_DIR)/build_vmcb_strike_1270.sh

$(PAYLOAD_HDR): $(PAYLOAD_DIR)/break_hv.c $(PAYLOAD_DIR)/entry.S $(PAYLOAD_DIR)/link.ld
	sh $(PAYLOAD_DIR)/build.sh

$(ELF): $(PAYLOAD_HDR) main.c kdlsym.c khook.c paging.c util.c
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

$(CENSUS_1270_ELF): census_1270.c kdlsym.c util.c \
                   include/khook.h include/offsets/12_70_candidate.h
	$(CC) $(CFLAGS) -o $@ census_1270.c kdlsym.c util.c

clean:
	rm -f $(ELF) $(CENSUS_1270_ELF) $(STRIKE_HDR_1270) \
	    $(PAYLOAD_DIR)/vmcb_strike_1270.bin \
	    $(PAYLOAD_DIR)/vmcb_strike_1270.elf \
	    $(PAYLOAD_DIR)/vmcb_strike_1270.o $(PAYLOAD_DIR)/entry_1270.o
	rm -f $(PAYLOAD_DIR)/break_hv.h $(PAYLOAD_DIR)/break_hv.bin $(PAYLOAD_DIR)/break_hv.elf $(PAYLOAD_DIR)/*.o

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

check-hook-1270:
	@out=$$(mktemp /tmp/khook_1270.XXXXXX); \
	 trap 'rm -f "$$out"' EXIT; \
	 $(HOST_CC) -std=c11 -Wall -Wextra -Werror -Wno-unused-function \
	 -Iinclude tests/khook_1270_host.c -o "$$out" && "$$out"

debug: $(ELF)
	gdb-multiarch \
	-ex "set architecture i386:x86-64" \
	-ex "target extended-remote $(PS5_HOST):2159" \
	-ex "file $(ELF)" \
	-ex "remote put $(ELF) /data/$(ELF)" \
	-ex "set remote exec-file /data/$(ELF)" \
	-ex "start"
