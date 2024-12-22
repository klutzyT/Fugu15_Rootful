tipa: all
	cp Fugu15/Fugu15.ipa Fugu15.tipa

all %:
	$(MAKE) -C bootstrapFS $@
	$(MAKE) -C jbinjector $@
	$(MAKE) -C FuFuGuGu $@
	$(MAKE) -C stashd $@
	$(MAKE) -C MachOMerger $@
	$(MAKE) -C libdyldhook $@
	./trustcache_macos_x86_64 create Fugu15/Fugu15_test.tc TrustCache
	$(MAKE) -C Fugu15 Fugu15.ipa
