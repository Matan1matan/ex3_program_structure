"""
ex3_gui.py
~~~~~~

"""
import tkinter
from tkinter import *
from tkinter import ttk
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import showerror
import ex3


class ex3_gui(ttk.Frame):
    """The adders gui and functions."""

    def __init__(self, parent, *args, **kwargs):
        ttk.Frame.__init__(self, parent, *args, **kwargs)
        self.root = parent
        self.fname = "aa"
        self.is_used = False
        self.parser_object = None
        self.init_gui()

    def on_quit(self):
        """Exits program."""
        quit()

    def load_file(self, event=None):

        self.display_by_AP_button.configure(state='disable')
        self.display_the_graph_button.configure(state='disable')
        self.display_by_Mac_addresses_button.configure(state='disable')
        self.answer_label['text'] = ""
        self.fname = askopenfilename(filetypes=(("PCAP files", "*.cap"),))
        if self.fname:
            try:
                self.is_used = True
                self.parser_object = ex3.open_file(self.fname)
                self.answer_label['text'] = "File loaded successfully!"
                self.display_by_AP_button.configure(state='enable')
                self.display_the_graph_button.configure(state='enable')
                self.display_by_Mac_addresses_button.configure(state='enable')
                print("File loaded successfully!")
                # self.button.destroy()

            except:  # <- naked except is a bad idea
                showerror("Open Source File", "Failed to read file\n'%s'" % self.fname)


        elif self.is_used:
            self.display_by_AP_button.configure(state='enable')
            self.display_the_graph_button.configure(state='enable')
            self.display_by_Mac_addresses_button.configure(state='enable')

            # return

    def init_gui(self):
        """Builds GUI."""

        self.root.title('PCAP Parser')
        self.root.option_add('*tearOff', 'FALSE')
        self.grid(column=0, row=0, sticky='nsew')

        # Menu
        # self.menubar = tkinter.Menu(self.root)
        # self.menu_file = tkinter.Menu(self.menubar)
        # self.menu_file.add_command(label='Exit', command=self.on_quit)
        # self.menubar.add_cascade(menu=self.menu_file, label='File')
        # self.root.config(menu=self.menubar)

        self.button = ttk.Button(self, compound=tkinter.TOP, text="Browse", command=self.load_file)
        self.button.grid(column=1, row=3, columnspan=12, sticky=W + E + N + S)

        # self.num1_entry = ttk.Entry(self, width=5)
        # self.num1_entry.grid(column=1, row=2)
        #
        # self.num2_entry = ttk.Entry(self, width=5)
        # self.num2_entry.grid(column=3, row=2)

        self.display_by_AP_button = ttk.Button(self, text='Display by AccessPoints',
                                               command=self.display_by_AP_func)
        self.display_by_AP_button.grid(column=0, row=5, columnspan=12, sticky=W + N + S)

        self.display_by_AP_button.configure(state='disable')

        self.display_by_Mac_addresses_button = ttk.Button(self, text='Display by Mac addresses',
                                                          command=self.display_by_mac_addresses)
        self.display_by_Mac_addresses_button.grid(column=0, row=7, columnspan=12, sticky=W + N + S)

        self.display_by_Mac_addresses_button.configure(state='disable')

        self.display_the_graph_button = ttk.Button(self, text='Display Graph',
                                                   command=self.display_graph)
        self.display_the_graph_button.grid(column=0, row=9, columnspan=12, sticky=W + N + S)

        self.display_the_graph_button.configure(state='disable')

        self.answer_frame = ttk.LabelFrame(self, text='Status',
                                           height=100)
        self.answer_frame.grid(column=0, row=12, columnspan=12, sticky='nesw')

        self.answer_label = ttk.Label(self.answer_frame, text='')
        self.answer_label.grid(column=0, row=0)

        # Labels that remain constant throughout execution.
        ttk.Label(self, text='PCAP Parser').grid(column=0, row=0,
                                                 columnspan=12)

        ttk.Separator(self, orient='horizontal').grid(column=0,
                                                      row=1, columnspan=12, sticky='ew')
        self.root.bind("<Control-o>", self.load_file)

        for child in self.winfo_children():
            child.grid_configure(padx=10, pady=10)

    def display_by_AP_func(self):
        self.parser_object.display_by_access_points()

    def display_by_mac_addresses(self):
        self.parser_object.display_by_MAC_addresses()

    def display_graph(self):
        self.parser_object.display_graph()


    def flash_open(self, aa):
        print("Hey!")


        # print(self.fname)

        # self.pcap_file = rdpcap(self.fname)



        # print(self.pcap_file[0].show())
        # def printFilename(self):
        #
        #     self.filename_frame['text'] = self.button
        #     print(self.fname)
        #     # return


if __name__ == '__main__':
    root = tkinter.Tk()
    ex3_gui(root)
    root.mainloop()
