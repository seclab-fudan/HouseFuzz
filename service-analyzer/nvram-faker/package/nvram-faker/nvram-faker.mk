NVRAM_FAKER_VERSION = 0.1
NVRAM_FAKER_SITE = $(TOPDIR)/../../src/nvram-faker
NVRAM_FAKER_SITE_METHOD = local
NVRAM_FAKER_SOURCE = "nvram-faker.c"

define NVRAM_FAKER_BUILD_CMDS
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) -shared -fPIC -ldl -o $(@D)/libnvram-faker.so $(@D)/nvram-faker.c
endef

define NVRAM_FAKER_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 755 $(@D)/libnvram-faker.so $(TARGET_DIR)/usr/lib/libnvram-faker.so
endef

$(eval $(generic-package))