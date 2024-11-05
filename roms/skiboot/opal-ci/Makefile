
OP_BUILD_GIT?=git@github.com:open-power/op-build.git
BUILDROOT_GIT?=https://github.com/open-power/buildroot
DL_CACHE?=~/op-build/dl
SCRATCH?=/scratch/stewart/op-build/

all: op-build-images

op-build-images: build-op-build-v1.0 build-op-build-v1.1 build-op-build-v1.2 build-op-build-v1.2.1

op-build:
	git clone ${OP_BUILD_GIT} op-build
	(cd op-build && git submodule init)
	(cd op-build && git config submodule.buildroot.url ${BUILDROOT_GIT})
	(cd op-build && git submodule update --reference ${OP_BUILD_GIT})

op-build-v1.0: op-build
	git clone -s op-build op-build-v1.0
	(cd op-build && git submodule init)
	(cd op-build-v1.0 && git config submodule.buildroot.url ${BUILDROOT_GIT})
	(cd op-build-v1.0 && git checkout v1.0)
	(cd op-build-v1.0 && git submodule update --recursive)
	(cd op-build-v1.0 && cp -rl ${DL_CACHE}/* dl/)
	rm -rf ${SCRATCH}/op-build-v1.0 && mkdir ${SCRATCH}/op-build-v1.0
	(rm -rf op-build-v1.0/output && ln -s ${SCRATCH}/op-build-v1.0 op-build-v1.0/output)

op-build-v1.1: op-build
	git clone -s op-build op-build-v1.1
	(cd op-build && git submodule init)
	(cd op-build-v1.1 && git config submodule.buildroot.url ${BUILDROOT_GIT})
	(cd op-build-v1.1 && git checkout v1.1)
	(cd op-build-v1.1 && git submodule update --recursive)
	(cd op-build-v1.1 && cp -rl ${DL_CACHE}/* dl/)
	rm -rf ${SCRATCH}/op-build-v1.1 && mkdir ${SCRATCH}/op-build-v1.1
	(rm -rf op-build-v1.1/output && ln -s ${SCRATCH}/op-build-v1.1 op-build-v1.1/output)

op-build-v1.2: op-build
	git clone -s op-build op-build-v1.2
	(cd op-build && git submodule init)
	(cd op-build-v1.2 && git config submodule.buildroot.url ${BUILDROOT_GIT})
	(cd op-build-v1.2 && git checkout v1.2)
	(cd op-build-v1.2 && git submodule update --recursive)
	(cd op-build-v1.2 && cp -rl ${DL_CACHE}/* dl/)
	rm -rf ${SCRATCH}/op-build-v1.2 && mkdir ${SCRATCH}/op-build-v1.2
	(rm -rf op-build-v1.2/output && ln -s ${SCRATCH}/op-build-v1.2 op-build-v1.2/output)

op-build-v1.2.1: op-build
	git clone -s op-build op-build-v1.2.1
	(cd op-build && git submodule init)
	(cd op-build-v1.2.1 && git config submodule.buildroot.url ${BUILDROOT_GIT})
	(cd op-build-v1.2.1 && git checkout v1.2.1)
	(cd op-build-v1.2.1 && git submodule update --recursive)
	(cd op-build-v1.2.1 && cp -rl ${DL_CACHE}/* dl/)
	rm -rf ${SCRATCH}/op-build-v1.2.1 && mkdir ${SCRATCH}/op-build-v1.2.1
	(rm -rf op-build-v1.2.1/output && ln -s ${SCRATCH}/op-build-v1.2.1 op-build-v1.2.1/output)

build-op-build-v1.0: op-build-v1.0
	cd op-build-v1.0 && ../run-op-build-mambo.sh

build-op-build-v1.1: op-build-v1.1
	cd op-build-v1.1 && ../run-op-build-mambo.sh

build-op-build-v1.2: op-build-v1.2
	cd op-build-v1.2 && ../run-op-build-mambo.sh

build-op-build-v1.2.1: op-build-v1.2.1
	cd op-build-v1.2.1 && ../run-op-build-mambo.sh

images/op-build-v1.0: images-dir
	cp -r op-build-v1.0/output/images images/op-build-v1.0

images/op-build-v1.1: images-dir
	cp -r op-build-v1.1/output/images images/op-build-v1.1

images/op-build-v1.2: images-dir
	cp -r op-build-v1.2/output/images images/op-build-v1.2

images/op-build-v1.2.1: images-dir
	cp -r op-build-v1.2.1/output/images images/op-build-v1.2.1

images-dir:
	mkdir images;

.PHONY: images

images: images/op-build-v1.0 images/op-build-v1.1 images/op-build-v1.2 images/op-build-v1.2.1
