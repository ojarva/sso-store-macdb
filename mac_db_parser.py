"""
Parser for "arp -an" output.

Input should be one entry per line, on the following format:
<hostname> (<ip address) at <mac address> on <interface>

"""

class MacDbParser:
    """ Parses the output of "arp -an" command """
    def __init__(self, afile):
        self.afile = afile
        self._entries = self.entries

    @property
    def entries(self):
        """ Returns (cached) list of entries """
        if self._entries:
            return self._entries
        self._entries = []
        for line in self.afile:
            line = line.strip().split(" ")
            if len(line) < 6:
                print "Invalid ARP file format."
                return []
            data = {
               "hostname": line[0],
               "ip": line[1].replace("(", "").replace(")", ""),
               "mac": line[3],
               "interface": line[5]
            }
            self._entries.append(data)
        return self._entries

    def get(self, **kwargs):
        """ Returns list of entries matching to all arguments """
        items = []
        for item in self.entries:
            item_valid = True
            for arg in kwargs:
                if item.get(arg) is None or item.get(arg) == kwargs[arg]:
                    item_valid = False
                    break
                    
            if item_valid:
                items.append(item)
        return items
