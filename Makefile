AS      := aarch64-linux-gnu-as
LD      := aarch64-linux-gnu-ld
OBJCOPY := aarch64-linux-gnu-objcopy
NM      := aarch64-linux-gnu-nm

PAYLOAD_BIN := build/payload.bin
PAYLOAD_MAP := build/payload.map

.PHONY: all payload image stage0 verify verify-image verify-sim verify-emu verify-flow verify-overlay clean

all: payload image

payload: $(PAYLOAD_BIN)

$(PAYLOAD_BIN): payload/payload.S payload/linker.ld
	@mkdir -p build
	$(AS) -o build/payload.o payload/payload.S
	$(LD) -T payload/linker.ld -o build/payload.elf build/payload.o --no-warn-rwx-segments
	$(OBJCOPY) -O binary build/payload.elf $(PAYLOAD_BIN)
	$(NM) -n build/payload.elf > $(PAYLOAD_MAP)
	@echo "payload: $$(stat -c %s $(PAYLOAD_BIN)) bytes"

image: payload
	python3 scripts/patch_lk.py

stage0:
	@mkdir -p build
	$(AS) -o build/stage0.o payload/stage0.S
	$(LD) -Ttext=0 -o build/stage0.elf build/stage0.o --no-warn-rwx-segments
	$(OBJCOPY) -O binary build/stage0.elf build/stage0.bin
	python3 scripts/make_rawboot_payload.py build/stage0.bin /dev/null dist/stage0.img --pad 0x100000 --load 0x40080000

verify: verify-image verify-sim verify-emu verify-flow verify-overlay

verify-image:
	python3 scripts/verify_output.py

verify-sim:
	python3 scripts/lk_sim.py

verify-emu:
	python3 scripts/emulate_payload.py

verify-flow:
	python3 scripts/lk_flow_sim.py

verify-overlay:
	python3 scripts/emulate_overlay.py

clean:
	rm -rf build
