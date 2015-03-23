EVDNS_PATH		= /usr/local
LDNS_PATH		= /usr/local
LIBEV_PATH		= /usr/local

CPPFLAGS		= -I$(EVLDNS_PATH)/include -I$(LDNS_PATH)/include -I$(LIBEV_PATH)/include -I.
CXXFLAGS		= -g -O3

LIBS_EVLDNS		= -Wl,-rpath,$(EVLDNS_PATH)/lib -L$(EVLDNS_PATH)/lib -levldns
LIBS_LDNS		= -Wl,-rpath,$(LDNS_PATH)/lib -L$(LDNS_PATH)/lib -lldns
LIBS_LIBEV		= -Wl,-rpath,$(LIBEV_PATH)/lib -L$(LIBEV_PATH)/lib -levent

OBJS_APNIC		= apnic.o apnetwork.o
LIBS_APNIC		= $(LIBS_EVLDNS) $(LIBS_LDNS) $(LIBS_LIBEV)

all:			apnic

apnic:			$(OBJS_APNIC)
	$(CXX) -o $(@) $(LDFLAGS) $(OBJS_APNIC) $(LIBS_APNIC)

clean:
	$(RM) -f *.o apnic
