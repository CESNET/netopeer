MODULES = combo.yang hanic-probe.yang meterpoint.yang

.PHONY: all tree yin clean

all: $(MODULES) tree yin

tree: $(MODULES)
	@[ -d tree ] || mkdir tree;
	@for MODULE in $(MODULES); do \
		pyang -f tree -o ./tree/`echo $$MODULE | sed 's/\.yang/\.tree/'` $$MODULE; \
	done;

yin: $(MODULES)
	@[ -d yin ] || mkdir yin;
	@for MODULE in $(MODULES); do \
		pyang -f yin -o ./yin/`echo $$MODULE | sed 's/\.yang/\.yin/'` $$MODULE; \
	done;

clean:
	rm -rf tree yin
