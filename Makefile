JFLAGS = -g -Xlint -cp .:./src:./lib/jpcap-0.7/lib/jpcap.jar -d ./
JC = javac 

.SUFFIXES: .java .class

.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
	src/Rule.java \
	src/Flags.java \
	src/Stream.java \
	src/Session.java \
	src/snids.java 

default: classes JAR

JAR: 
	jar cmf MANIFEST.MF snids.jar ./*.class

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class

