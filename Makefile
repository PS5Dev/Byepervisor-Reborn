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
KTEXT_1160 ?= ps5-11.60-ktext.bin

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := byepervisor_reborn.elf
ISSUE9_ELF := byepervisor_issue9_diag.elf
ISSUE9_DR0_ELF := byepervisor_issue9_dr0_diag.elf
ISSUE9_RESUME_ELF := byepervisor_issue9_resume_diag.elf
ISSUE9_ABORT_ELF := byepervisor_issue9_resume_abort.elf

PAYLOAD_DIR := break_hv_payload
PAYLOAD_HDR := $(PAYLOAD_DIR)/break_hv.h

CFLAGS := -Wall -Werror -Wno-unused-function -g -O0 -I./include

all: $(ELF)

$(PAYLOAD_HDR): $(PAYLOAD_DIR)/break_hv.c $(PAYLOAD_DIR)/entry.S $(PAYLOAD_DIR)/link.ld
	sh $(PAYLOAD_DIR)/build.sh

$(ELF): $(PAYLOAD_HDR) main.c kdlsym.c khook.c paging.c util.c issue9_diag.c
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

issue9-diag: $(ISSUE9_ELF)

issue9-dr0-diag: $(ISSUE9_DR0_ELF)

audit-issue9-dr0: $(ISSUE9_DR0_ELF)
	python3 scripts/audit_issue9_dr0.py $(ISSUE9_DR0_ELF) \
		--objdump "$${OBJDUMP:-llvm-objdump}" \
		--ktext "$(KTEXT_1160)"

issue9-resume-diag: $(ISSUE9_RESUME_ELF)

issue9-resume-abort: $(ISSUE9_ABORT_ELF)

audit-issue9-resume: $(ISSUE9_RESUME_ELF)
	python3 scripts/audit_issue9_resume.py $(ISSUE9_RESUME_ELF) \
		--objdump "$${OBJDUMP:-llvm-objdump}" \
		--ktext "$(KTEXT_1160)"

audit-issue9: $(ISSUE9_ELF)
	python3 scripts/audit_issue9_diag.py $(ISSUE9_ELF) --objdump "$${OBJDUMP:-llvm-objdump}"

$(ISSUE9_ELF): $(PAYLOAD_HDR) main.c kdlsym.c khook.c paging.c util.c issue9_diag.c
	$(CC) $(CFLAGS) -DISSUE9_DIAG=1 -o $@ $(filter %.c,$^)

$(ISSUE9_DR0_ELF): $(PAYLOAD_HDR) main.c kdlsym.c khook.c paging.c util.c issue9_diag.c
	$(CC) $(CFLAGS) -DISSUE9_DR0_DIAG=1 -o $@ $(filter %.c,$^)

$(ISSUE9_RESUME_ELF): $(PAYLOAD_HDR) main.c kdlsym.c khook.c paging.c util.c issue9_diag.c
	$(CC) $(CFLAGS) -DISSUE9_RESUME_DIAG=1 -o $@ $(filter %.c,$^)

$(ISSUE9_ABORT_ELF): $(PAYLOAD_HDR) main.c kdlsym.c khook.c paging.c util.c issue9_diag.c
	$(CC) $(CFLAGS) -DISSUE9_RESUME_ABORT=1 -o $@ $(filter %.c,$^)

clean:
	rm -f $(ELF)
	rm -f $(ISSUE9_ELF)
	rm -f $(ISSUE9_DR0_ELF)
	rm -f $(ISSUE9_RESUME_ELF)
	rm -f $(ISSUE9_ABORT_ELF)
	rm -f $(PAYLOAD_DIR)/break_hv.h $(PAYLOAD_DIR)/break_hv.bin $(PAYLOAD_DIR)/break_hv.elf $(PAYLOAD_DIR)/*.o

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

debug: $(ELF)
	gdb-multiarch \
	-ex "set architecture i386:x86-64" \
	-ex "target extended-remote $(PS5_HOST):2159" \
	-ex "file $(ELF)" \
	-ex "remote put $(ELF) /data/$(ELF)" \
	-ex "set remote exec-file /data/$(ELF)" \
	-ex "start"

audit-11.60: $(ELF)
	python3 scripts/audit_11_60.py --objdump "$${OBJDUMP:-llvm-objdump}"
