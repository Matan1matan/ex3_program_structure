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
        self.is_used = False
        self.parser_object = None
        self.init_gui()

    def load_file(self, event=None):

        for i in range(len(self.button_list)-1):
            self.button_list[i+1].configure(state='disable')

        self.answer_label['text'] = ""
        self.fname = askopenfilename(filetypes=(("PCAP files", ("*.pcap", "*.cap")),),initialdir=('./WiFi_Data_test'))
        if self.fname:
            try:
                self.is_used = True
                self.parser_object = ex3.open_file(self.fname)
                self.answer_label['text'] = "File loaded successfully!"

                for i in range(len(self.button_list) - 1):
                    self.button_list[i + 1].configure(state='enable')


            except:  # <- naked except is a bad idea
                showerror("Open Source File", "Failed to read file\n'%s'" % self.fname)


        elif self.is_used:

            for i in range(len(self.button_list) - 1):
                self.button_list[i + 1].configure(state='enable')


    def init_gui(self):
        """Builds GUI."""

        self.root.title('PCAP Parser')
        self.root.option_add('*tearOff', 'FALSE')
        self.grid(column=0, row=0, sticky='nsew')
        self.button_list = []

        columnspan = 12

        self.b_browse = ttk.Button(self, compound=tkinter.TOP, text="Browse", command=self.load_file)
        self.button_list.append(self.b_browse)
        self.b_browse.grid(column=1, row=3, columnspan=columnspan, sticky=W + E + N + S)

        self.button_list.append(ttk.Button(self, text='Display by SSIDs',
                                          command=self.display_by_SSIDs))
        self.button_list.append(ttk.Button(self, text='Display by sender',
                                                     command=self.display_by_sender))
        self.button_list.append(ttk.Button(self, text='Display by receiver',
                                           command=self.display_by_receiver))
        self.button_list.append(ttk.Button(self, text='Display Graph',
                                              command=self.display_graph))
        self.button_list.append(ttk.Button(self, text='Display Frames',
                                           command=self.display_frames))
        self.button_list.append(ttk.Button(self, text='Display channel efficiency',
                                              command=self.display_channel_efficiency))
        self.button_list.append(ttk.Button(self, text='Display bytes per second',
                                              command=self.display_bytes_per_second))
        self.button_list.append(ttk.Button(self, text='Display PER',
                                              command=self.display_PER))
        self.button_list.append(ttk.Button(self, text='Save information as text',
                                              command=self.save_information_as_text))
        self.button_list.append(ttk.Button(self, text='Display graph by a specific mac address',
                                              command=self.display_graph_by_specific_mac))
        self.button_list.append(ttk.Button(self, text='Display by time interval',
                                              command=self.display_by_time_interval))

        self.answer_frame = ttk.LabelFrame(self, text='Status',
                                           height=100)
        self.answer_frame.grid(column=0, row=5+len(self.button_list), columnspan=columnspan, sticky='nesw')

        self.answer_label = ttk.Label(self.answer_frame, text='')
        self.answer_label.grid(column=0, row=0)

        # Labels that remain constant throughout execution.
        ttk.Label(self, text='PCAP Parser').grid(column=0, row=0,
                                                 columnspan=columnspan)

        ttk.Separator(self, orient='horizontal').grid(column=0,
                                                      row=1, columnspan=columnspan, sticky='ew')

        for i in range(len(self.button_list)-1):
            temp = self.button_list[i+1]
            temp.grid(column=0, row=4+i, columnspan=columnspan, sticky=W + N + S)
            temp.configure(state='disable')

        # shortcuts
        self.root.bind("<Control-o>", self.load_file)
        self.root.bind("<Control-w>", self.ask_quit)

        for child in self.winfo_children():
            child.grid_configure(padx=10, pady=10)

    def display_by_SSIDs(self):
        self.parser_object.display_by_SSIDs()

    def display_by_receiver(self):
        self.parser_object.display_by_receiver()

    def display_by_sender(self):
        self.parser_object.display_by_sender()

    def display_graph(self):
        self.parser_object.display_graph()

    def display_frames(self):
        self.parser_object.display_frames()

    def display_channel_efficiency(self):
        self.parser_object.display_channel_efficiency()

    def display_bytes_per_second(self):
        self.parser_object.display_bytes_per_second()

    def display_PER(self):
        self.parser_object.display_PER()

    def save_information_as_text(self):
        self.parser_object.save_information_as_text()

    def display_graph_by_specific_mac(self):

        top = self.top = Toplevel(self.root)

        Label(top, text="Value").pack()

        self.e = Entry(top)
        self.e.pack(padx=5)

        b = Button(top, text="OK", command=self.ok)
        b.pack(pady=5)


    def ok(self):

        self.parser_object.display_graph_by_specific_mac(self.e.get())

    def display_by_time_interval(self):

        top = self.top = Toplevel(self.root)
        Label(top, text="MAC address").pack()
        self.e0 = Entry(top)
        self.e0.pack(padx=5)
        self.e1a = Entry(top)
        self.e1a.pack(padx=5)
        Label(self.e1a,text="Start time").pack()
        self.e1 = Entry(top)
        self.e1.pack(padx=5)
        self.e2a = Entry(top)
        self.e2a.pack(padx=5)
        Label(self.e2a, text="End time").pack()
        self.e2 = Entry(top)
        self.e2.pack(padx=5)

        b = Button(top, text="OK", command=self.ok2)
        b.pack(pady=5)

    def ok2(self):

        self.parser_object.display_by_time_interval(self.e0.get(),float(self.e1.get()),float(self.e2.get()))



    def ask_quit(self, event=None):
        if tkinter.messagebox:
            tkinter.messagebox.askokcancel("quit", "Are you sure you want to exit?")
            if (self.parser_object):
                self.parser_object.destroy_fig()
            root.destroy()

if __name__ == '__main__':
    root = tkinter.Tk()
    a = ex3_gui(root)
    root.protocol("WM_DELETE_WINDOW", a.ask_quit)
    root.mainloop()
