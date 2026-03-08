NVRAM_FUZZ_VERSION = 0.1
NVRAM_FUZZ_SITE = $(TOPDIR)/../../src/nvram-fuzz
NVRAM_FUZZ_SITE_METHOD = local

define NVRAM_FUZZ_BUILD_CMDS
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) -fPIC -Wall -shared -o $(@D)/libnvram-fuzz.so $(@D)/nvram.c $(@D)/redqueen.c $(@D)/orig_strfunc.c $(@D)/libnvram_fuzz.h
endef

define NVRAM_FUZZ_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 755 $(@D)/libnvram-fuzz.so $(TARGET_DIR)/usr/lib/libnvram-fuzz.so
endef

$(eval $(generic-package))