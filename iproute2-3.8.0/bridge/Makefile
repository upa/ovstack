BROBJ = bridge.o fdb.o monitor.o link.o mdb.o

include ../Config

all: bridge

bridge: $(BROBJ) $(LIBNETLINK) 

install: all
	install -m 0755 bridge $(DESTDIR)$(SBINDIR)

clean:
	rm -f $(BROBJ) bridge

