"""Windows Service (LocalSystem). Cài: python service.py --startup auto install
Khởi động lại khi lỗi: sc failure OGKAgent reset= 86400 actions= restart/5000/restart/5000/restart/5000"""
import servicemanager
import win32event
import win32service
import win32serviceutil

from ogk.runner import Runner


class OGKService(win32serviceutil.ServiceFramework):
    _svc_name_ = "OGKAgent"
    _svc_display_name_ = "OpenGuard Kids Agent"
    _svc_description_ = "Công cụ đồng hành cùng trẻ: hạn mức thời gian, lọc web/ứng dụng (minh bạch, không theo dõi lén)."

    def __init__(self, args):
        super().__init__(args)
        self.evt = win32event.CreateEvent(None, 0, 0, None)
        self.runner = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.runner:
            self.runner.stop()
        win32event.SetEvent(self.evt)

    def SvcDoRun(self):
        servicemanager.LogInfoMsg("OGKAgent starting")
        self.runner = Runner(system_dns=True, require_tray=True)
        self.runner.start()
        win32event.WaitForSingleObject(self.evt, win32event.INFINITE)


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(OGKService)
