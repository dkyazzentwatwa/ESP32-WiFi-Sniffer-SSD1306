# Repository Guidelines

## Project Structure & Module Organization
This repository is intentionally small. The main firmware lives in [`ESP32-WiFi-Sniffer-SSD1306.ino`](ESP32-WiFi-Sniffer-SSD1306.ino) at the repository root. Supporting visuals are stored as root-level image assets such as [`wifisniffer.jpg`](wifisniffer.jpg) and [`wifisniffer2.jpg`](wifisniffer2.jpg). There is no `src/` or `tests/` directory, so keep additions simple and obvious.

## Build, Test, and Development Commands
The project is built from Arduino IDE with the ESP32 board package installed.

- `Arduino IDE -> Sketch -> Verify/Compile`: checks that the sketch compiles for the selected ESP32 board.
- `Arduino IDE -> Sketch -> Upload`: flashes the board after selecting the correct port.
- `arduino-cli compile --fqbn esp32:esp32:esp32 --build-path /tmp/esp32-sniffer-build .`: command-line compile example if you prefer CLI workflows.

Runtime validation is hardware-based. Confirm serial output at `115200` baud and verify the SSD1306 display on GPIO21/SDA and GPIO22/SCL.
If SD support is used, confirm SPI wiring on GPIO5/18/19/23 and validate both flash and SD CSV downloads from the dashboard.

## Coding Style & Naming Conventions
Use Arduino/C++ style with 2-space indentation, opening braces on the same line, and descriptive function names such as `initDisplay()` and `wifi_sniffer_init()`. Keep globals near the top of the sketch and prefer small helper functions over large inline blocks. Maintain the existing naming pattern for constants in `UPPER_SNAKE_CASE` and functions in `lowerCamelCase` or `snake_case` only when matching nearby ESP32 APIs.

## Testing Guidelines
There is no automated test suite in this repository. Validate changes by compiling for the target ESP32 board, flashing to hardware, and checking:

- serial logs for packet metadata and errors
- OLED rendering for layout and truncation issues
- the dashboard at `http://192.168.4.1/`
- CSV export, LittleFS log rotation, and SD mirroring

## Commit & Pull Request Guidelines
Git history uses short, direct commit messages such as `Update README.md` and `Added project pictures`. Keep commits similarly concise and imperative. Pull requests should explain the firmware change, list any wiring or library requirements, and include photos or screenshots when display output changes.

## Security & Configuration Tips
This sketch depends on ESP32-specific libraries and an SSD1306 address of `0x3C`. If you change pins, screen size, or I2C address, update the sketch and README together so the hardware setup stays reproducible.
