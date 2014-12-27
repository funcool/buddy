all: core sign hashers auth index

core:
	asciidoctor -o core.html buddy-core.adoc

sign:
	asciidoctor -o sign.html buddy-sign.adoc

hashers:
	asciidoctor -o hashers.html buddy-hashers.adoc

auth:
	asciidoctor -o auth.html buddy-auth.adoc

index:
	asciidoctor -o index.html buddy.adoc

clean:
	rm -f index.html core.html hashers.html sign.html auth.html
