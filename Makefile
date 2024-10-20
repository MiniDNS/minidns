GRADLE ?= ./gradlew

.PHONY: all
all: check codecov eclipse javadocAll inttest

.PHONY: codecov
codecov:
	$(GRADLE) minidns-hla:testCodeCoverageReport
	echo "Code coverage report available at $(PWD)/minidns-hla/build/reports/jacoco/testCodeCoverageReport/html/index.html"

.PHONY: check
check:
	$(GRADLE) $@

.PHONY: eclipse
eclipse:
	$(GRADLE) $@

.PHONY: inttest
inttest:
	$(GRADLE) $@

.PHONY: javadocAll
javadocAll:
	$(GRADLE) $@
	echo "javadoc available at $(PWD)/build/javadoc/index.html"
