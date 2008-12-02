class TransportPort(object):
    def __new__(typ, value):
        if value.lower() == "auto":
            return 0
        try:
            return int(value)
        except:
            return None