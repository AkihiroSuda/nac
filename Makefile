# Files are installed under $(DESTDIR)/$(PREFIX)
PREFIX ?= /usr/local
DEST := $(shell echo "$(DESTDIR)/$(PREFIX)" | sed 's:///*:/:g; s://*$$::')

all: _output/lib/libnac.dylib _output/bin/nac

GO ?= go
GO_LDFLAGS ?= -s -w
GO_BUILD ?= $(GO) build -trimpath -ldflags="$(GO_LDFLAGS)"

# Because deprecated functions have to be hooked
CFLAGS += -Wno-deprecated-declarations

%.o: %.c *.h
	$(CC) $(CFLAGS) -c $< -o $@

_output/lib/libnac.dylib: $(patsubst %.c, %.o, $(wildcard libnac/*.c))
	mkdir -p _output/lib
	$(CC) $(CFLAGS) -o $@ $(LDFLAGS) -ldl -dynamiclib $^

_output/bin/nac: $(shell find . -type f -name '*.go')
	$(GO_BUILD) -o $@ ./cmd/nac

.PHONY: clean
clean:
	$(RM) -r _output libnac/*.o

.PHONY: install
install: uninstall
	install _output/bin/nac "$(DEST)/bin/nac"
	install _output/lib/libnac.dylib "$(DEST)/lib/libnac.dylib"

.PHONY: uninstall
uninstall:
	$(RM) "$(DEST)/bin/nac" "$(DEST)/lib/libnac.dylib"
