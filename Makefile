# Reproducible PKI generation for the Secure IoT Smart Lock project.

SHELL := /bin/bash

OUT_DIR := out
ROOT_KEY := $(OUT_DIR)/rootCA.key
ROOT_CERT := $(OUT_DIR)/rootCA.crt
ROOT_EXT := $(OUT_DIR)/root_ext.cnf

SERVER_KEY := $(OUT_DIR)/server.key
SERVER_CSR := $(OUT_DIR)/server.csr
SERVER_CERT := $(OUT_DIR)/server.crt
SERVER_EXT := $(OUT_DIR)/server_ext.cnf

CLIENT_EXT := $(OUT_DIR)/client_ext.cnf

ADMIN_KEY := $(OUT_DIR)/admin.key
ADMIN_CSR := $(OUT_DIR)/admin.csr
ADMIN_CERT := $(OUT_DIR)/admin.crt

RESIDENT_KEY := $(OUT_DIR)/resident.key
RESIDENT_CSR := $(OUT_DIR)/resident.csr
RESIDENT_CERT := $(OUT_DIR)/resident.crt

MAINT_KEY := $(OUT_DIR)/maintenance.key
MAINT_CSR := $(OUT_DIR)/maintenance.csr
MAINT_CERT := $(OUT_DIR)/maintenance.crt

OPENSSL := openssl
ROOT_DAYS := 3650
LEAF_DAYS := 825

.PHONY: all pki clean show extfiles

all: pki

pki: extfiles $(ROOT_CERT) $(SERVER_CERT) $(ADMIN_CERT) $(RESIDENT_CERT) $(MAINT_CERT)
	@echo "PKI generation complete."

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

extfiles: $(ROOT_EXT) $(SERVER_EXT) $(CLIENT_EXT)

$(ROOT_EXT): | $(OUT_DIR)
	printf '%s\n' \
	'[req]' \
	'distinguished_name = req_distinguished_name' \
	'x509_extensions = v3_ca' \
	'prompt = no' \
	'' \
	'[req_distinguished_name]' \
	'CN = SmartLock Root CA' \
	'' \
	'[v3_ca]' \
	'basicConstraints = critical, CA:TRUE' \
	'keyUsage = critical, keyCertSign, cRLSign' \
	'subjectKeyIdentifier = hash' \
	'authorityKeyIdentifier = keyid:always,issuer' > $(ROOT_EXT)

$(SERVER_EXT): | $(OUT_DIR)
	printf '%s\n' \
	'basicConstraints = CA:FALSE' \
	'keyUsage = critical, digitalSignature, keyEncipherment' \
	'extendedKeyUsage = serverAuth' \
	'subjectAltName = @alt_names' \
	'' \
	'[alt_names]' \
	'DNS.1 = localhost' \
	'IP.1 = 127.0.0.1' > $(SERVER_EXT)

$(CLIENT_EXT): | $(OUT_DIR)
	printf '%s\n' \
	'basicConstraints = CA:FALSE' \
	'keyUsage = critical, digitalSignature, keyEncipherment' \
	'extendedKeyUsage = clientAuth' > $(CLIENT_EXT)

$(ROOT_KEY): | $(OUT_DIR)
	$(OPENSSL) genrsa -out $(ROOT_KEY) 4096

$(ROOT_CERT): $(ROOT_KEY) $(ROOT_EXT)
	$(OPENSSL) req -x509 -new \
		-key $(ROOT_KEY) \
		-config $(ROOT_EXT) \
		-extensions v3_ca \
		-days $(ROOT_DAYS) \
		-out $(ROOT_CERT)

$(SERVER_KEY): | $(OUT_DIR)
	$(OPENSSL) genrsa -out $(SERVER_KEY) 2048

$(SERVER_CSR): $(SERVER_KEY)
	$(OPENSSL) req -new \
		-key $(SERVER_KEY) \
		-subj "/CN=localhost" \
		-out $(SERVER_CSR)

$(SERVER_CERT): $(SERVER_CSR) $(ROOT_CERT) $(ROOT_KEY) $(SERVER_EXT)
	$(OPENSSL) x509 -req \
		-in $(SERVER_CSR) \
		-CA $(ROOT_CERT) \
		-CAkey $(ROOT_KEY) \
		-CAcreateserial \
		-out $(SERVER_CERT) \
		-days $(LEAF_DAYS) \
		-sha256 \
		-extfile $(SERVER_EXT)

$(ADMIN_KEY): | $(OUT_DIR)
	$(OPENSSL) genrsa -out $(ADMIN_KEY) 2048

$(ADMIN_CSR): $(ADMIN_KEY)
	$(OPENSSL) req -new \
		-key $(ADMIN_KEY) \
		-subj "/CN=admin" \
		-out $(ADMIN_CSR)

$(ADMIN_CERT): $(ADMIN_CSR) $(ROOT_CERT) $(ROOT_KEY) $(CLIENT_EXT)
	$(OPENSSL) x509 -req \
		-in $(ADMIN_CSR) \
		-CA $(ROOT_CERT) \
		-CAkey $(ROOT_KEY) \
		-CAcreateserial \
		-out $(ADMIN_CERT) \
		-days $(LEAF_DAYS) \
		-sha256 \
		-extfile $(CLIENT_EXT)

$(RESIDENT_KEY): | $(OUT_DIR)
	$(OPENSSL) genrsa -out $(RESIDENT_KEY) 2048

$(RESIDENT_CSR): $(RESIDENT_KEY)
	$(OPENSSL) req -new \
		-key $(RESIDENT_KEY) \
		-subj "/CN=resident" \
		-out $(RESIDENT_CSR)

$(RESIDENT_CERT): $(RESIDENT_CSR) $(ROOT_CERT) $(ROOT_KEY) $(CLIENT_EXT)
	$(OPENSSL) x509 -req \
		-in $(RESIDENT_CSR) \
		-CA $(ROOT_CERT) \
		-CAkey $(ROOT_KEY) \
		-CAcreateserial \
		-out $(RESIDENT_CERT) \
		-days $(LEAF_DAYS) \
		-sha256 \
		-extfile $(CLIENT_EXT)

$(MAINT_KEY): | $(OUT_DIR)
	$(OPENSSL) genrsa -out $(MAINT_KEY) 2048

$(MAINT_CSR): $(MAINT_KEY)
	$(OPENSSL) req -new \
		-key $(MAINT_KEY) \
		-subj "/CN=maintenance" \
		-out $(MAINT_CSR)

$(MAINT_CERT): $(MAINT_CSR) $(ROOT_CERT) $(ROOT_KEY) $(CLIENT_EXT)
	$(OPENSSL) x509 -req \
		-in $(MAINT_CSR) \
		-CA $(ROOT_CERT) \
		-CAkey $(ROOT_KEY) \
		-CAcreateserial \
		-out $(MAINT_CERT) \
		-days $(LEAF_DAYS) \
		-sha256 \
		-extfile $(CLIENT_EXT)

show:
	@echo "Generated files:"
	@ls -1 $(OUT_DIR)

clean:
	rm -f $(OUT_DIR)/*.key \
	      $(OUT_DIR)/*.csr \
	      $(OUT_DIR)/*.crt \
	      $(OUT_DIR)/*.srl \
	      $(OUT_DIR)/*_ext.cnf
	@echo "PKI artifacts removed."
