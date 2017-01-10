"""
ex3.py
~~~~~~

"""
from _curses import start_color

from networkx.algorithms.flow import networksimplex
from scapy.all import *
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from operator import itemgetter




# my_colors = 'rgbkymc'
MY_COLORS = np.array(['r', 'g', 'b', '0.75', 'y', 'm', 'c'])
BW_STANDARD_WIFI = 15E7

class parser:
    def __init__(self, path):
        self.pcap_file = rdpcap(path)

    def display_by_receiver(self):

        mac_adresses = {}  # new dictionary
        for pkt in self.pcap_file:
            mac_adresses.update({pkt[Dot11].addr1: 0})
        for pkt in self.pcap_file:
            mac_adresses[pkt[Dot11].addr1] += 1

        MA = []
        for ma in mac_adresses:
            MA.append(mac_adresses[ma])

        plt.clf()
        plt.suptitle('Number of packets by receivers', fontsize=14, fontweight='bold')
        plt.bar(range(len(mac_adresses)), sorted(MA), align='center', color=MY_COLORS)

        plt.xticks(range(len(mac_adresses)), sorted(mac_adresses.keys()))

        plt.rcParams.update({'font.size': 10})

        plt.xlabel('Receiver mac address')
        plt.ylabel('Count')

        # Set tick colors:
        ax = plt.gca()
        ax.tick_params(axis='x', colors='blue')
        ax.tick_params(axis='y', colors='red')
        ax.set_xticklabels(ax.xaxis.get_majorticklabels(), rotation=45)

        plt.legend()
        plt.show()

    def display_by_sender(self):



        mac_adresses = {}  # new dictionary
        for pkt in self.pcap_file:
            mac_adresses.update({pkt[Dot11].addr2: 0})
        for pkt in self.pcap_file:
            mac_adresses[pkt[Dot11].addr2] += 1

        MA = []
        for ma in mac_adresses:
            MA.append(mac_adresses[ma])

        plt.clf()
        plt.suptitle('Number of packets by senders', fontsize=14, fontweight='bold')
        plt.bar(range(len(mac_adresses)), sorted(MA), align='center', color=MY_COLORS)

        plt.xticks(range(len(mac_adresses)), sorted(mac_adresses.keys()))

        plt.rcParams.update({'font.size': 10})

        plt.xlabel('Sender mac address')
        plt.ylabel('Count')

        # Set tick colors:
        ax = plt.gca()
        ax.tick_params(axis='x', colors='blue')
        ax.tick_params(axis='y', colors='red')
        ax.set_xticklabels(ax.xaxis.get_majorticklabels(), rotation=45)

        plt.legend()
        plt.show()


    def display_by_SSIDs(self):

        networks = {}

        for pkt in self.pcap_file:
            if pkt.haslayer(Dot11Elt):

                temp = str((pkt[Dot11Elt].info).decode("utf-8", "ignore"))
                if temp is "":
                    temp = pkt[Dot11].addr1

                networks.update({temp: 0})

        for pkt in self.pcap_file:
            if pkt.haslayer(Dot11Elt):

                temp = str((pkt[Dot11Elt].info).decode("utf-8", "ignore"))

                if temp is "":
                    temp = pkt[Dot11].addr1

            networks[temp] += 1

        networks_list = sorted(networks.items(), key=itemgetter(1))

        plt.clf()
        plt.suptitle('Number of packets by SSIDs', fontsize=14, fontweight='bold')
        plt.bar(range(len(networks_list)), [int(i[1]) for i in networks_list], align='center', color=MY_COLORS)

        plt.xticks(range(len(networks_list)), [i[0] for i in networks_list])

        plt.rcParams.update({'font.size': 10})

        plt.xlabel('SSID name')
        plt.ylabel('Count')

        # Set tick colors:
        ax = plt.gca()
        ax.tick_params(axis='x', colors='blue')
        ax.tick_params(axis='y', colors='red')
        ax.set_xticklabels(ax.xaxis.get_majorticklabels(), rotation=30)

        plt.legend()
        plt.show()

    def display_frames(self):

        frame_map = {}
        for pkt in self.pcap_file:
            frame_map.update({pkt.payload.payload.name: 0})

        for pkt in self.pcap_file:
            frame_map[pkt.payload.payload.name] += 1

        print(frame_map)
        frame_list = frame_map.items()

        pies = [pie for (pie, percent) in sorted((frame_list), key=itemgetter(1))]
        percents = [percent for (pie, percent) in sorted((frame_list), key=itemgetter(1))]

        # Make a pie graph.
        colors = ['gold', 'lightgreen', 'r', 'orange', 'c', 'plum']
        plt.figure(num=1, figsize=(12, 8))
        plt.axes(aspect=1)
        plt.suptitle('Frames map', fontsize=14, fontweight='bold')
        plt.rcParams.update({'font.size': 10})
        # plt.pie(percents, labels=pies, autopct='%1.f%%', colors=colors, pctdistance=0.7, labeldistance=1.2)
        plt.pie(percents, labels=pies, autopct='%1.f%%', startangle=270, colors=colors, pctdistance=0.7,
                labeldistance=1.2)

        plt.show()

    def display_graph(self):

        plt.clf()
        G = nx.Graph()

        count = 0
        edges_list = []

        for pkt in self.pcap_file:
            if hasattr(pkt.payload, 'src') and hasattr(pkt.payload, 'dst'):
                count += 1
                edges_list.append((pkt.payload.src, pkt.payload.dst))

        plt.suptitle('peer2peer communication', fontsize=14, fontweight='bold')
        plt.title("Number of users: " + str(count))
        plt.rcParams.update({'font.size': 10})
        G.add_edges_from(edges_list)
        nx.draw(G, with_labels=True, node_color=MY_COLORS)
        plt.show()


        # End of class ex3

    def stam(self):

        aps = set()

        for packet in self.pcap_file:

            if packet.haslayer(Dot11Beacon):

                newCombination = str(packet.info) + " " + str(packet.addr2)
                if newCombination not in aps:
                    aps.add(newCombination)
                    print(str(len(aps)) + ": " + str(packet.addr2) + " --> AccessPoint name: " + str(
                        (packet.info).decode("utf-8")))

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
                print(c)
            except AttributeError:
                pass

    def stam3(self):

        aps = {}

        for p in self.pcap_file:
            # if ((p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)) and not p[Dot11].addr3):
            if ((p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp))):
                ssid = p[Dot11Elt].info.decode("utf-8", "ignore")
                bssid = p[Dot11].addr3
                channel = int(ord(p[Dot11Elt:3].info))
                capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                            {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

                # Check for encrypted networks
                if re.search("privacy", capability):
                    enc = 'Encrypted'
                else:
                    enc = 'Not encrypted'

                # Save discovered AP
                aps[p[Dot11].addr3] = enc

                # Display discovered AP
                if bssid is not "":
                    print("%02d\t%s\t%s\t%s" % (int(channel), enc, bssid, ssid))


    def display_channel_efficiency(self):

        size = 0

        start_time = self.pcap_file[0].time
        end_time = self.pcap_file[len(self.pcap_file)-1].time

        duration = end_time - start_time

        # print(end_time - start_time)

        for i in range(len(self.pcap_file)-1):
            size += len(self.pcap_file[i])
        bps = round((size*8)/duration)
        ans =(((size*8)/duration)/BW_STANDARD_WIFI)*100
        ans = float("%.2f" % ans)
        labels = ['Used','Unused']
        sizes = [ans,100.0-ans]
        colors= ['g', 'firebrick']

        # Make a pie graph
        plt.figure(num=1, figsize=(8, 6))
        plt.axes(aspect=1)
        plt.suptitle('Channel efficiency', fontsize=14, fontweight='bold')
        plt.rcParams.update({'font.size': 17})
        # plt.pie(percents, labels=pies, autopct='%1.f%%', colors=colors, pctdistance=0.7, labeldistance=1.2)
        plt.pie(sizes, labels=labels, autopct='%.2f%%', startangle=-30, colors=colors, pctdistance=0.7,
                labeldistance=1.2)

        plt.show()

        # return "Channel efficiency: " + str(ans) + "%"\


    def destroy_fig(self):
        if plt:
            plt.close()

def open_file(file_name='/home/matan/PycharmProjects/second_project/pcg/dasda/file1.cap'):
# def open_file(file_name='/home/matan/Downloads/test.pcap'):
#     filename = input('Enter file name: ')


    return parser(file_name)


def main():
    ex3_object = open_file()

    # ex3_object.display_by_MAC_addresses()
    # ex3_object.display_by_access_points()
    # ex3_object.display_graph()
    # ex3_object.display_frames()
    ex3_object.stam()
    # ex3_object.stam2()
    # ex3_object.stam3()
    # print ("-start-")
    # ex3_object.display_channel_efficiency()
    # ex3_object.display_by_sender()
    # ex3_object.display_by_receiver()


if __name__ == '__main__':
    main()
