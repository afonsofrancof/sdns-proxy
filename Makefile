.PHONY: all clean

all:
	python3 scripts/post_processing/merge_files.py
	python3 scripts/post_processing/merge_cpu.py
	python3 scripts/post_processing/merge_mem.py
	python3 scripts/post_processing/merge_pcap.py

clean:
	rm -f ./dns_results.csv ./dns_results_cpu.csv ./dns_results_mem.csv ./dns_results_pcap.csv
