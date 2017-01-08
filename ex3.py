from scapy.all import *
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np

# my_colors = 'rgbkymc'
# my_colors = {'r': (1.0, 0.0, 0.0), 'w': (1.0, 1.0, 1.0), 'k': (0.0, 0.0, 0.0), 'm': (0.75, 0, 0.75), 'c': (0.0, 0.75, 0.75), 'g': (0.0, 0.5, 0.0), 'y': (0.75, 0.75, 0), 'b': (0.0, 0.0, 1.0)}
my_colors = np.array(['r', 'g', 'b','0.75','y','m','c'])

class parser:
    def __init__(self, path):
        self.pcap_file = rdpcap(path)

    # def export(self, type, format_file):
    #
    #     try:
    #
    #         filename = type + '.' + format
    #         plt.savefig(filename, format=format_file)
    #
    #         print(format_file + " created!")
    #
    #     except SyntaxError:
    #
    #         print("due to some error, the PDF wasn't created")

    def display_by_MAC_addresses(self):

        mac_adresses = {}  # new dictionary
        for pkt in self.pcap_file:
            mac_adresses.update({pkt[Dot11].addr1: 0})
        for pkt in self.pcap_file:
            mac_adresses[pkt[Dot11].addr1] += 1

        # MA_list = list(mac_adresses)

        MA = []
        for ma in mac_adresses:
            MA.append(mac_adresses[ma])

        plt.close()
        plt.bar(range(len(mac_adresses)), sorted(MA), align='center', color=my_colors)

        plt.xticks(range(len(mac_adresses)), sorted(mac_adresses.keys()))

        plt.rcParams.update({'font.size': 10})

        plt.xlabel('MAC Address')
        plt.ylabel('Count')

        # Set tick colors:
        ax = plt.gca()
        ax.tick_params(axis='x', colors='blue')
        ax.tick_params(axis='y', colors='red')
        ax.set_xticklabels(ax.xaxis.get_majorticklabels(), rotation=45)

        plt.legend()
        plt.show()

    def display_by_access_points(self):

        networks = {}

        for pkt in self.pcap_file:
            if pkt.haslayer(Dot11Elt):
                networks.update({str((pkt[Dot11Elt].info).decode("utf-8", "ignore")): 0})

        for pkt in self.pcap_file:
            if pkt.haslayer(Dot11Elt):
                networks[str((pkt[Dot11Elt].info).decode("utf-8", "ignore"))] += 1

        networks_list = []
        for network in networks:
            networks_list.append(networks[network])

        # my_colors = 'rgbkymc'
        plt.close()
        plt.bar(range(len(networks)), sorted(networks_list), align='center', color=my_colors)

        plt.xticks(range(len(networks)), sorted(networks.keys()))

        plt.rcParams.update({'font.size': 10})

        plt.xlabel('Network')
        plt.ylabel('Count')

        # Set tick colors:
        ax = plt.gca()
        ax.tick_params(axis='x', colors='blue')
        ax.tick_params(axis='y', colors='red')
        ax.set_xticklabels(ax.xaxis.get_majorticklabels(), rotation=30)

        plt.legend()
        plt.show()

    def display_protocol(self):

        count = 0

        for pkt in self.pcap_file:
            print(pkt.payload.payload.name)

        protocol_map = {}
        for pkt in self.pcap_file:
            protocol_map.update({pkt.payload.payload.name: 0})

        for pkt in self.pcap_file:
            protocol_map[pkt.payload.payload.name] += 1

        print(protocol_map)

    def display_graph(self):

        plt.close()
        G = nx.Graph()

        edges_list = []

        for pkt in self.pcap_file:
            if hasattr(pkt.payload, 'src') and hasattr(pkt.payload, 'dst'):
                edges_list.append((pkt.payload.src, pkt.payload.dst))


                # print(pkt.payload.src + " | " + pkt.payload.dst)
        plt.rcParams.update({'font.size': 10})
        G.add_edges_from(edges_list)
        nx.draw(G, with_labels=True, node_color=my_colors)
        plt.show()


        # End of class ex3



    def stam(self):

        aps = set()

        for packet in self.pcap_file:


            if packet.haslayer(Dot11Beacon):

                newCombination = str(packet.info) + " " + str(packet.addr2)
                if newCombination not in aps:
                    aps.add(newCombination)
                    print (str(len(aps)) + ": " + str(packet.addr2) + " --> AccessPoint name: " + str((packet.info).decode("utf-8")))
    # def stam2(self):
    #
    #     for pkt in self.pcap_file:
    #
    #         if pkt.haslayer(Dot11):
    #             print ("Deauth packet sniffed: %s" % (pkt.)


    def stam2(self):

        # getsrcdst = lambda x: (x.info.decode("utf-8", "ignore"),x.addr1, x.addr2, x.addr3)
        getsrcdst = lambda x: (x.info.decode("utf-8", "ignore"), x.addr3)

        for pkt in self.pcap_file:
            try:
                c = getsrcdst(pkt)
                print (c)
            except AttributeError:
                pass


    # def stam3(self):
    #
    #     for pkt in self.pcap_file:
    #         if pkt.haslayer(Dot11Elt):
    #             channel = int(ord(pkt[Dot11Elt:3].info))
    #             print (channel)
    #


def open_file(file_name = '/home/matan/PycharmProjects/second_project/pcg/dasda/file1.cap'):
    # filename = input('Enter file name: ')


    # return ex3('/home/matan/PycharmProjects/second_project/pcg/dasda/' + str(filename) + '.cap')
    return parser(file_name)


def main():
    ex3_object = open_file()

    # ex3_object.display_by_MAC_addresses()
    # ex3_object.display_by_networks()
    # ex3_object.display_graph()
    # ex3_object.stam()
    ex3_object.stam2()
    # ex3_object.stam3()

if __name__ == '__main__':
    main()
