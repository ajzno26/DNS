pkg = dns
source = $(pkg)/DNSMessage.java $(pkg)/DNSServer.java
jc = javac

classfiles = $(source:.java=.class)

all: $(classfiles)

%.class: %.java
	$(jc) $<

clean:
	rm -f $(pkg)/*.class
