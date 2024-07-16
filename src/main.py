import dpkt

import flows

class Main:
    def __init__(self):
        self.input_filename = "./s.pcap"
        self.output_filename = "./result.csv"

        self.flows = flows.Flows()
        self._run_file()
        self.flows.filter_packets();
        self.flows.write_csv(self.output_filename)


    def _run_file(self):
        with open(self.input_filename, 'rb') as pcap_file:
            pcap_file_handle = dpkt.pcap.Reader(pcap_file)
            try:
                self.flows.add_packet(pcap_file_handle)
            except (KeyboardInterrupt, SystemExit):
                print('SIGINT (Ctrl-c) detected.')

if __name__ == "__main__":
    main_obj = Main()