"""
eddycat - A script to find code paths between two functions in IDA. Inspired by alleycat
"""

import idaapi
import idautils
import idc
import ida_kernwin

try:
    from PyQt5 import QtWidgets
except ImportError:
    from PySide2 import QtWidgets

MAX_DEPTH = 10
MAX_PATHS = 1000

def get_neighbors(func_ea):
    neighbors = set()
    for xref in idautils.XrefsFrom(func_ea):
        callee_func = idaapi.get_func(xref.to)
        if callee_func:
            neighbors.add(callee_func.start_ea)
    for xref in idautils.XrefsTo(func_ea):
        caller_func = idaapi.get_func(xref.frm)
        if caller_func:
            neighbors.add(caller_func.start_ea)
    return neighbors

def find_paths_bidirectional(src_ea, dst_ea, max_depth=MAX_DEPTH, max_paths=MAX_PATHS):
    queue = [(src_ea, [src_ea])]
    results = []
    while queue and len(results) < max_paths:
        current, path = queue.pop(0)
        if current == dst_ea:
            results.append(path)
            continue
        if len(path) > max_depth:
            continue
        for neighbor in get_neighbors(current):
            if neighbor in path:
                continue
            queue.append((neighbor, path + [neighbor]))
    return results

class CallPathsOutputForm(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.text_edit = QtWidgets.QPlainTextEdit()
        self.text_edit.setReadOnly(True)
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.text_edit)
        self.parent.setLayout(layout)

    def SetText(self, text):
        self.text_edit.setPlainText(text)

def display_text_output(title, text):
    form = CallPathsOutputForm()
    form.Show(title, options=ida_kernwin.PluginForm.WOPN_MDI)
    form.SetText(text)

def main():
    src_name = ida_kernwin.ask_str("", 0, "Enter source function name:")
    dst_name = ida_kernwin.ask_str("", 0, "Enter destination function name:")

    if src_name is None or dst_name is None:
        print("Both function names must be provided!")
        return

    src_ea = idc.get_name_ea_simple(src_name)
    dst_ea = idc.get_name_ea_simple(dst_name)
    
    if src_ea == idc.BADADDR:
        print("Source function '%s' not found!" % src_name)
        return
    if dst_ea == idc.BADADDR:
        print("Destination function '%s' not found!" % dst_name)
        return

    print("Searching for paths between '%s' (0x%X) and '%s' (0x%X)..." % (src_name, src_ea, dst_name, dst_ea))
    paths = find_paths_bidirectional(src_ea, dst_ea)
    
    lines = []
    if not paths:
        lines.append("No call paths found within the search limits.")
    else:
        lines.append("Found %d path(s):" % len(paths))
        for i, path in enumerate(paths, 1):
            path_names = [idc.get_func_name(ea) if idc.get_func_name(ea) else hex(ea) for ea in path]
            lines.append("Path %d: %s" % (i, " -> ".join(path_names)))
    
    output_text = "\n".join(lines)
    print(output_text)
    display_text_output("Call Paths", output_text)

if __name__ == '__main__':
    main()
