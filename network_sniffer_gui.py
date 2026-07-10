#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1
Network Sniffer - GUI Edition (Wireshark-style)
Author: Hamas Ahmad Furqan

A Tkinter GUI packet sniffer:
  * Choose your interface from a dropdown (like Wireshark).
  * Optional BPF capture filter.
  * Live, color-coded packet table (No / Time / Source / Dest / Protocol / Len / Info).
  * Click any packet to see its full decoded layer breakdown.
  * Save the capture to a .pcap file for Wireshark.

RUN (needs root for raw packet capture):
    sudo -E python3 network_sniffer_gui.py
    # -E preserves your display env so the window shows on Wayland/Hyprland.

ETHICS / LEGAL:
    Only run this on networks you own or are explicitly authorised to monitor.
"""

import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

try:
    from scapy.all import (
        AsyncSniffer, get_if_list, wrpcap,
        IP, IPv6, TCP, UDP, ICMP, ARP, DNSQR, Raw,
    )
except ImportError:
    raise SystemExit("scapy is not installed. On Fedora:  sudo dnf install python3-scapy")


# Row background colors per protocol (Wireshark-style colorization)
PROTO_TAGS = {
    "TCP":  "#e7f8e7", "UDP":  "#e7f0ff", "ICMP": "#fff7db",
    "ARP":  "#ffe7f5", "DNS":  "#e0ffff", "HTTP": "#fff0d0", "OTHER": "#f2f2f2",
}


def decode_info(pkt):
    """Build a short protocol + info string for the table row."""
    if ARP in pkt:
        op = "who-has" if pkt[ARP].op == 1 else "is-at"
        return "ARP", f"{op}  {pkt[ARP].psrc} -> {pkt[ARP].pdst}"

    if IP in pkt:
        ipl = pkt[IP]
    elif IPv6 in pkt:
        ipl = pkt[IPv6]
    else:
        return "OTHER", pkt.summary()

    # Application-layer decode takes priority for the label
    if pkt.haslayer(DNSQR):
        try:
            q = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
        except Exception:
            q = "?"
        return "DNS", f"Standard query  {q}"

    if Raw in pkt:
        try:
            data = bytes(pkt[Raw].load).decode(errors="replace")
            first = data.split("\r\n", 1)[0]
            if first.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")):
                return "HTTP", first
        except Exception:
            pass

    if TCP in pkt:
        t = pkt[TCP]
        return "TCP", f"{t.sport} -> {t.dport}  [{t.flags}]  len={len(pkt)}"
    if UDP in pkt:
        u = pkt[UDP]
        return "UDP", f"{u.sport} -> {u.dport}  len={len(pkt)}"
    if ICMP in pkt:
        return "ICMP", f"type={pkt[ICMP].type} code={pkt[ICMP].code}"
    return "OTHER", pkt.summary()


def endpoints(pkt):
    if ARP in pkt:
        return pkt[ARP].psrc, pkt[ARP].pdst
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return "", ""


class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CodeAlpha Packet Sniffer")
        self.root.geometry("1040x680")

        self.sniffer = None
        self.packets = []          # raw packets, index == treeview iid
        self.q = queue.Queue()     # thread-safe handoff from sniffer -> GUI
        self.count = 0

        self._build_controls()
        self._build_table()
        self._build_detail()
        self._build_status()

        self._poll_queue()         # start GUI-side polling loop

    # ---- UI construction --------------------------------------------------
    def _build_controls(self):
        bar = ttk.Frame(self.root, padding=8)
        bar.pack(fill="x")

        ttk.Label(bar, text="Interface:").pack(side="left")
        self.iface_var = tk.StringVar()
        self.iface_box = ttk.Combobox(bar, textvariable=self.iface_var, width=14,
                                      values=get_if_list())
        # Default to first non-loopback interface if available
        for name in get_if_list():
            if name != "lo":
                self.iface_var.set(name)
                break
        self.iface_box.pack(side="left", padx=(4, 2))
        ttk.Button(bar, text="\u21bb", width=3, command=self._refresh_ifaces).pack(side="left")

        ttk.Label(bar, text="  Filter (BPF):").pack(side="left")
        self.filter_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.filter_var, width=24).pack(side="left", padx=4)

        self.start_btn = ttk.Button(bar, text="\u25b6 Start", command=self.start)
        self.start_btn.pack(side="left", padx=(8, 2))
        self.stop_btn = ttk.Button(bar, text="\u25a0 Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=2)
        ttk.Button(bar, text="Clear", command=self.clear).pack(side="left", padx=2)
        ttk.Button(bar, text="Save .pcap", command=self.save).pack(side="left", padx=2)

    def _build_table(self):
        self.pane = ttk.PanedWindow(self.root, orient="vertical")
        self.pane.pack(fill="both", expand=True, padx=8, pady=(0, 4))

        frame = ttk.Frame(self.pane)
        cols = ("no", "time", "src", "dst", "proto", "len", "info")
        widths = (60, 100, 190, 190, 70, 60, 320)
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", height=18)
        for c, w in zip(cols, widths):
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=w, anchor="w")
        for proto, color in PROTO_TAGS.items():
            self.tree.tag_configure(proto.lower(), background=color)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.pane.add(frame, weight=3)

    def _build_detail(self):
        frame = ttk.Frame(self.pane)
        ttk.Label(frame, text="Packet details:").pack(anchor="w")
        self.detail = tk.Text(frame, height=12, wrap="none", font=("monospace", 9))
        self.detail.pack(fill="both", expand=True)
        self.detail.config(state="disabled")
        self.pane.add(frame, weight=1)

    def _build_status(self):
        self.status_var = tk.StringVar(value="Idle. Pick an interface and press Start.")
        ttk.Label(self.root, textvariable=self.status_var, relief="sunken",
                  anchor="w", padding=4).pack(fill="x", side="bottom")

    # ---- actions ----------------------------------------------------------
    def _refresh_ifaces(self):
        self.iface_box["values"] = get_if_list()

    def start(self):
        iface = self.iface_var.get().strip() or None
        bpf = self.filter_var.get().strip() or None
        try:
            self.sniffer = AsyncSniffer(iface=iface, prn=self._on_packet,
                                        filter=bpf, store=False)
            self.sniffer.start()
        except Exception as e:
            messagebox.showerror("Capture error", str(e))
            self.sniffer = None
            return
        self.start_btn["state"] = "disabled"
        self.stop_btn["state"] = "normal"
        self.status_var.set(f"Capturing on {iface or 'default'}"
                            + (f"  filter='{bpf}'" if bpf else "") + " ...")

    def stop(self):
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None
        self.start_btn["state"] = "normal"
        self.stop_btn["state"] = "disabled"
        self.status_var.set(f"Stopped. {self.count} packets captured.")

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.packets.clear()
        self.count = 0
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.config(state="disabled")
        self.status_var.set("Cleared.")

    def save(self):
        if not self.packets:
            messagebox.showinfo("Nothing to save", "No packets captured yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                            filetypes=[("PCAP files", "*.pcap")])
        if path:
            wrpcap(path, self.packets)
            messagebox.showinfo("Saved", f"Saved {len(self.packets)} packets to:\n{path}")

    # ---- capture -> GUI handoff ------------------------------------------
    def _on_packet(self, pkt):
        # Runs in the sniffer thread: never touch Tk here, just enqueue.
        self.q.put(pkt)

    def _poll_queue(self):
        # Runs on the GUI thread; drains a bounded batch to stay responsive.
        processed = 0
        while not self.q.empty() and processed < 200:
            pkt = self.q.get()
            self.count += 1
            self.packets.append(pkt)
            proto, info = decode_info(pkt)
            src, dst = endpoints(pkt)
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            self.tree.insert("", "end", iid=str(len(self.packets) - 1),
                             values=(self.count, ts, src, dst, proto, len(pkt), info),
                             tags=(proto.lower(),))
            processed += 1
        if processed:
            self.tree.yview_moveto(1.0)   # autoscroll to newest
            self.status_var.set(f"{self.count} packets captured.")
        self.root.after(100, self._poll_queue)

    def on_select(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        pkt = self.packets[int(sel[0])]
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        try:
            self.detail.insert("1.0", pkt.show(dump=True))
        except Exception as e:
            self.detail.insert("1.0", f"Could not decode packet: {e}")
        self.detail.config(state="disabled")


def main():
    root = tk.Tk()
    app = SnifferGUI(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.stop(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()
