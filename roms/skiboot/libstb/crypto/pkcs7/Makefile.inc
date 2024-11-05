
PKCS7_DIR = libstb/crypto/pkcs7

SUBDIRS += $(PKCS7_DIR)

PKCS7_SRCS = pkcs7.c
PKCS7_OBJS = $(PKCS7_SRCS:%.c=%.o)
PKCS7 = $(PKCS7_DIR)/built-in.a

CFLAGS_$(PKCS7_DIR)/ = -I$(SRC)/$(LIBSTB_DIR)/crypto -DMBEDTLS_CONFIG_FILE='<mbedtls-config.h>'

$(PKCS7): $(PKCS7_OBJS:%=$(PKCS7_DIR)/%)
