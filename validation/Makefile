PYTHON := python3

.PHONY: all baseline framework framework-inlined clean verifier-logs metrics

all: baseline framework framework-inlined

baseline:
	$(MAKE) -C baseline

framework:
	$(MAKE) -C framework

framework-inlined:
	$(MAKE) -C framework_inlined

clean:
	$(MAKE) -C baseline clean
	$(MAKE) -C framework clean
	$(MAKE) -C framework_inlined clean

verifier-logs: baseline framework
	cd softeng_perf && $(PYTHON) generate_verifier_logs.py --baseline ../baseline --framework ../framework

metrics:
	cd softeng_perf && $(PYTHON) compare_metrics.py \
		--baseline ../baseline \
		--framework ../framework \
		--framework-api-prefix bnt \
		--line-counter cloc \
		--baseline-verifier-log ../baseline \
		--framework-verifier-log ../framework \
		--json results/metrics.json \
		--csv results/metrics.csv \
		--markdown results/metrics.md \
		--split-output-dir results/split
