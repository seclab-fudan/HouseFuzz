.PHONY: all
all:
	@echo 'building docker image house_fuzzing_dude...'
	@sleep 1
	docker build --network=host -t house_fuzzing_dude .
	@echo 'run image house_fuzzing_dude to build the supporting binaries...'
	@sleep 1
	@docker run -v `pwd`/artifacts/fuzz_bins:/AFLplusplus_out -it house_fuzzing_dude bash -c 'cp -a /AFLplusplus_release/* /AFLplusplus_out/; mkdir -p /AFLplusplus_out/qemu; cp /AFLplusplus/afl-qemu-trace* /AFLplusplus_out/qemu/; chown -R '$(shell id -u):$(shell id -g)' /AFLplusplus_out'
