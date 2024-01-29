import win32evtlog

class EventLogViewer:
    def __init__(self) -> None:
        self.events = {
            "Create Services":[7030,7045],
            "Disable Firewall":[2003]
        }
        self.logType = 'Security'
        self.hand = None

    def connect_log(self):
        self.hand = win32evtlog.OpenEventLog(None,self.logType)

    def disconnect_log(self):
        if self.hand:
            win32evtlog.CloseEventLog(self.hand)

    def read_events(self):
        while True:
            events = win32evtlog.ReadEventLog(self.hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            for event in events:
                event_type = next((_type for _type, ids in self.events.items() if event.EventID in ids), None)
                if event_type:
                    print(f'EventID: {event.EventID}. Evento sospechoso encontrado: {event_type}')
            if not events:
                print('No malicious events found')
                break

try:
    log_events = EventLogViewer()
    log_events.connect_log()
    log_events.read_events()
except Exception as e:
    print(e)
finally:
    log_events.disconnect_log()