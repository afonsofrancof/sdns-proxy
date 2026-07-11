PY        := python3
PP        := scripts/post_processing

# Input trees produced by run.sh
GEN_IN    := results
DNS_IN    := results-dnssec

# Output layout
OUT       := out
GEN_OUT   := $(OUT)/general
DNS_OUT   := $(OUT)/dnssec

# netns veth IP for pcap direction detection (must match setup-netns.sh NS_IP).
LOCAL_IP  := 192.168.100.2

.PHONY: all general dnssec clean clean-general clean-dnssec

all: get_files general dnssec

get_files:
	rsync -a --progress afonso@afonso-pi:~/sdns-proxy/results/ $(GEN_IN)
	rsync -a --progress afonso@afonso-pi:~/sdns-proxy/results/ $(DNS_IN)

# ----- general workload: results/ -> out/general/ -----
general:
	mkdir -p $(GEN_OUT)
	$(PY) $(PP)/merge_files.py $(GEN_IN) -o $(GEN_OUT)/dns_results.csv
	$(PY) $(PP)/merge_cpu.py   $(GEN_IN) -o $(GEN_OUT)/dns_results_cpu.csv
	$(PY) $(PP)/merge_mem.py   $(GEN_IN) -o $(GEN_OUT)/dns_results_mem.csv
	$(PY) $(PP)/merge_pcap.py  $(GEN_IN) -o $(GEN_OUT)/dns_results_pcap.csv --local-ip $(LOCAL_IP)

# ----- DNSSEC workload: results-dnssec/ -> out/dnssec/ -----
dnssec:
	mkdir -p $(DNS_OUT)
	$(PY) $(PP)/merge_files.py $(DNS_IN) -o $(DNS_OUT)/dns_results.csv
	$(PY) $(PP)/merge_cpu.py   $(DNS_IN) -o $(DNS_OUT)/dns_results_cpu.csv
	$(PY) $(PP)/merge_mem.py   $(DNS_IN) -o $(DNS_OUT)/dns_results_mem.csv
	$(PY) $(PP)/merge_pcap.py  $(DNS_IN) -o $(DNS_OUT)/dns_results_pcap.csv --local-ip $(LOCAL_IP)

clean: clean-general clean-dnssec

clean-general:
	rm -f $(GEN_OUT)/dns_results.csv $(GEN_OUT)/dns_results_cpu.csv \
	      $(GEN_OUT)/dns_results_mem.csv $(GEN_OUT)/dns_results_pcap.csv

clean-dnssec:
	rm -f $(DNS_OUT)/dns_results.csv $(DNS_OUT)/dns_results_cpu.csv \
	      $(DNS_OUT)/dns_results_mem.csv $(DNS_OUT)/dns_results_pcap.csv
