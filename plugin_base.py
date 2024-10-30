from PyQt5.QtWidgets import QWidget

class BasePlugin:
    def __init__(self):
        """Initialize the plugin."""
        self._name = "Base Plugin"  # Default name

    @property
    def name(self):
        """Return the name of the plugin."""
        return self._name

    def create_tab(self):
        """Return the QWidget tab that will be added to the main app."""
        raise NotImplementedError("create_tab must be implemented in the plugin.")

    def start_scan(self, target):
        """Start the scan with the plugin."""
        raise NotImplementedError("start_scan must be implemented in the plugin.")

