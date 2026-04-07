# ESP32-WiFi-Sniffer-SSD1306

This version upgrades the original ESP32 Wi-Fi sniffer into a small capture appliance:

- SSD1306 status display
- LittleFS-backed packet logging
- mirrored SPI microSD logging
- local web dashboard
- CSV export for analysis on a Mac
- channel setting and capture toggle saved in flash

## Hardware

Wiring for the common ESP32 WROOM 32E + 0.96" SSD1306 module:

- SDA -> GPIO21
- SCL -> GPIO22
- VCC -> 3V
- GND -> GND

For the optional SPI microSD breakout, use the board's default VSPI pins:

- CS -> GPIO5
- SCK -> GPIO18
- MISO -> GPIO19
- MOSI -> GPIO23

## Use

The sketch compiles with the Arduino ESP32 core. After flashing, connect to the ESP32 access point:

- SSID: `ESP32-Sniffer`
- Password: `sniffer123`
- Dashboard: `http://192.168.4.1/`

From the dashboard you can review recent packets, toggle capture, clear stored logs, and download CSV data from flash or SD storage for offline analysis.

## Notes

The capture channel is configurable from the dashboard and is applied on reboot so the access point stays stable. Packet logs are rotated in flash and mirrored to SD when present, and the export endpoints combine the saved segments into one CSV stream.
