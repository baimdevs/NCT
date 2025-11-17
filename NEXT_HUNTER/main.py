#!/usr/bin/env python3
"""
NEXT HUNTER - Main Entry Point
Advanced Kali Linux Tools Collection with GUI
"""

import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFont
from ui.main_window import NextHunterGUI


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    
    # Set application-wide font
    font = QFont("Courier", 10)
    app.setFont(font)
    
    # Create and show main window
    window = NextHunterGUI()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
