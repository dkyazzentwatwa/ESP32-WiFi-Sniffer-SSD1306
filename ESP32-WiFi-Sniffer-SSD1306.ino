#include <Arduino.h>
#include <FS.h>
#include <Preferences.h>
#include <LittleFS.h>
#include <SD.h>
#include <SPI.h>
#include <WebServer.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1

static const char* AP_SSID = "ESP32-Sniffer";
static const char* AP_PASSWORD = "sniffer123";
static const uint8_t DEFAULT_CHANNEL = 1;
static const uint8_t MIN_CHANNEL = 1;
static const uint8_t MAX_CHANNEL = 13;
static const uint8_t DEFAULT_SD_CS_PIN = 5;
static const uint32_t LOG_ROTATE_LIMIT = 96UL * 1024UL;
static const uint8_t LOG_ARCHIVE_COUNT = 4;
static const uint8_t LIVE_BUFFER_SIZE = 64;
static const uint8_t RECENT_BUFFER_SIZE = 24;
static const uint32_t STATE_SAVE_INTERVAL_MS = 5000;
static const char* CSV_HEADER = "uptime_ms,channel,rssi,type,addr1,addr2,addr3";
static const char* CURRENT_LOG_PATH = "/packets_current.csv";
static const char* ARCHIVE_PATHS[LOG_ARCHIVE_COUNT] = {
  "/packets_archive_0.csv",
  "/packets_archive_1.csv",
  "/packets_archive_2.csv",
  "/packets_archive_3.csv"
};

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
WebServer server(80);
Preferences prefs;

typedef struct {
  unsigned frame_ctrl : 16;
  unsigned duration_id : 16;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  unsigned sequence_ctrl : 16;
  uint8_t addr4[6];
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0];
} wifi_ieee80211_packet_t;

struct PacketRecord {
  uint32_t uptimeMs;
  uint8_t channel;
  int8_t rssi;
  uint8_t type;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
};

struct RuntimeSettings {
  uint8_t channel = DEFAULT_CHANNEL;
  uint8_t sdCsPin = DEFAULT_SD_CS_PIN;
  bool captureEnabled = true;
  bool sdEnabled = true;
};

struct RuntimeStats {
  uint32_t capturedPackets = 0;
  uint32_t storedPackets = 0;
  uint32_t droppedPackets = 0;
  uint32_t mgmtPackets = 0;
  uint32_t dataPackets = 0;
  uint32_t miscPackets = 0;
  uint32_t logRotations = 0;
  uint32_t sdRotations = 0;
  uint32_t sdWriteFailures = 0;
};

static RuntimeSettings settings;
static RuntimeStats stats;

struct StorageBackend {
  const char* label;
  fs::FS* fs;
  bool mounted = false;
};

static StorageBackend flashStorage{ "LittleFS", &LittleFS };
static StorageBackend sdStorage{ "SD", &SD };

static PacketRecord liveBuffer[LIVE_BUFFER_SIZE];
static volatile size_t liveHead = 0;
static volatile size_t liveTail = 0;
static volatile size_t liveCount = 0;
static portMUX_TYPE liveBufferMux = portMUX_INITIALIZER_UNLOCKED;

static PacketRecord recentBuffer[RECENT_BUFFER_SIZE];
static uint8_t recentCount = 0;
static uint8_t recentHead = 0;

static bool filesystemReady = false;
static bool sdFilesystemReady = false;
static bool captureRunning = false;
static bool rebootPending = false;
static uint32_t rebootAtMs = 0;
static uint32_t lastStateSaveMs = 0;

static void initDisplay();
static void drawDisplay();
static void loadSettings();
static void saveSettings();
static void startAccessPoint();
static void initStorage();
static void initSdStorage();
static void startCapture();
static void stopCapture();
static void scheduleReboot(uint32_t delayMs);
static void clearStoredLogs();
static void ensureCurrentLogHeader(StorageBackend& storage);
static void rotateLogs(StorageBackend& storage);
static bool appendRecordToLog(StorageBackend& storage, const PacketRecord& record);
static void appendRecordToStorage(const PacketRecord& record);
static void flushQueuedPackets();
static void queuePacket(const PacketRecord& record);
static bool dequeuePacket(PacketRecord& out);
static void addToRecent(const PacketRecord& record);
static const char* packetTypeToString(uint8_t type);
static void formatMac(const uint8_t mac[6], char* out, size_t len);
static String recordToCsv(const PacketRecord& record);
static String recordToJson(const PacketRecord& record);
static String buildStatusJson();
static String buildRecentJson(uint8_t limit);
static String getLogUsageSummary();
static String getStorageUsageSummary(StorageBackend& storage);
static void sendDashboard();
static void sendCsvExport();
static void sendSdCsvExport();
static void sendStatusJson();
static void sendRecentJson();
static void sendClearResponse();
static void sendSdClearResponse();
static void handleChannelChange();
static void handleSdChange();
static void handleCaptureToggle();
static void handleRootNotFound();
static void wifiSnifferCallback(void* buff, wifi_promiscuous_pkt_type_t type);
static void renderPacketToSerial(const PacketRecord& record);
static void updateStatsForType(uint8_t type);
static void writeStateIfNeeded(bool force = false);
static bool isValidChannel(int channel);

static const char INDEX_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>ESP32 Sniffer Dashboard</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #09111f;
      --panel: rgba(14, 22, 38, 0.94);
      --panel-2: rgba(19, 29, 49, 0.95);
      --line: rgba(134, 172, 255, 0.18);
      --text: #e8f0ff;
      --muted: #8ea4cc;
      --accent: #6ee7ff;
      --accent-2: #8b5cf6;
      --good: #34d399;
      --warn: #fbbf24;
      --bad: #fb7185;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(110, 231, 255, 0.14), transparent 30%),
        radial-gradient(circle at top right, rgba(139, 92, 246, 0.18), transparent 32%),
        linear-gradient(180deg, #060b14 0%, #09111f 55%, #04070d 100%);
      color: var(--text);
    }
    .wrap { max-width: 1180px; margin: 0 auto; padding: 24px; }
    .hero {
      display: grid;
      grid-template-columns: 1.3fr 0.7fr;
      gap: 18px;
      align-items: stretch;
      margin-bottom: 18px;
    }
    .panel {
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 20px;
      box-shadow: 0 18px 60px rgba(0, 0, 0, 0.35);
      backdrop-filter: blur(14px);
    }
    .hero-main { padding: 24px; }
    .eyebrow {
      display: inline-flex;
      gap: 10px;
      align-items: center;
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(110, 231, 255, 0.1);
      border: 1px solid rgba(110, 231, 255, 0.2);
      color: var(--accent);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .12em;
    }
    h1 { margin: 14px 0 10px; font-size: clamp(30px, 5vw, 54px); line-height: 0.95; }
    .sub { color: var(--muted); max-width: 66ch; line-height: 1.6; margin: 0; }
    .hero-side { padding: 18px; display: grid; gap: 12px; }
    .stat-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .card {
      padding: 16px;
      border-radius: 16px;
      background: var(--panel-2);
      border: 1px solid var(--line);
    }
    .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
    .value { margin-top: 8px; font-size: 26px; font-weight: 700; }
    .tiny { color: var(--muted); margin-top: 4px; font-size: 12px; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; }
    .actions form, .actions a, .actions button { margin: 0; }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 12px 16px;
      border-radius: 12px;
      border: 1px solid var(--line);
      background: linear-gradient(135deg, rgba(110,231,255,0.18), rgba(139,92,246,0.18));
      color: var(--text);
      text-decoration: none;
      cursor: pointer;
      font-weight: 600;
    }
    .btn.secondary { background: rgba(19, 29, 49, 0.95); }
    .btn.danger { background: rgba(251, 113, 133, 0.12); }
    .section { margin-top: 18px; padding: 18px; }
    .section h2 { margin: 0 0 12px; font-size: 18px; }
    .controls {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 14px;
    }
    .field { display: grid; gap: 6px; }
    .field input {
      width: 100%;
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid var(--line);
      background: rgba(6, 11, 20, 0.85);
      color: var(--text);
    }
    table { width: 100%; border-collapse: collapse; }
    th, td {
      padding: 10px 8px;
      border-bottom: 1px solid rgba(134, 172, 255, 0.12);
      font-size: 13px;
      text-align: left;
      white-space: nowrap;
    }
    th { color: var(--muted); font-weight: 600; }
    .muted { color: var(--muted); }
    .status-dot {
      width: 10px; height: 10px; border-radius: 50%;
      display: inline-block; background: var(--good);
      box-shadow: 0 0 18px rgba(52, 211, 153, 0.45);
    }
    @media (max-width: 900px) {
      .hero, .stat-grid, .controls { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 640px) {
      .wrap { padding: 14px; }
      .hero, .stat-grid, .controls { grid-template-columns: 1fr; }
      th:nth-child(1), td:nth-child(1) { display: none; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <section class="panel hero-main">
        <div class="eyebrow"><span class="status-dot"></span> live packet capture</div>
        <h1>ESP32 Sniffer Control Room</h1>
        <p class="sub">Persistent packet summaries, a local dashboard, and CSV export from LittleFS. Use this page to review recent traffic, change the capture channel, or clear stored logs before a new analysis pass.</p>
      </section>
      <aside class="panel hero-side">
      <div class="card">
          <div class="label">Access Point</div>
          <div id="apName" class="value">-</div>
          <div id="apIp" class="tiny">-</div>
        </div>
        <div class="card">
          <div class="label">Capture</div>
          <div id="captureState" class="value">-</div>
          <div id="logState" class="tiny">-</div>
        </div>
        <div class="card">
          <div class="label">SD Card</div>
          <div id="sdState" class="value">-</div>
          <div id="sdLogState" class="tiny">-</div>
        </div>
      </aside>
    </div>

    <section class="panel section">
      <h2>Stats</h2>
      <div class="stat-grid">
        <div class="card"><div class="label">Captured</div><div id="captured" class="value">0</div><div class="tiny">Packets seen by the sniffer</div></div>
        <div class="card"><div class="label">Stored</div><div id="stored" class="value">0</div><div class="tiny">Packets written to flash</div></div>
        <div class="card"><div class="label">Dropped</div><div id="dropped" class="value">0</div><div class="tiny">Packets lost in the ring buffer</div></div>
        <div class="card"><div class="label">Channel</div><div id="channel" class="value">1</div><div id="typeBreakdown" class="tiny">MGMT 0 / DATA 0 / MISC 0</div></div>
      </div>
      <div class="actions" style="margin-top: 14px;">
        <a class="btn" href="/download.csv">Download CSV</a>
        <a class="btn secondary" href="/download_sd.csv">Download SD CSV</a>
        <a class="btn secondary" href="/api/status" target="_blank">Raw JSON</a>
        <button class="btn secondary" onclick="toggleCapture()">Toggle Capture</button>
        <button class="btn danger" onclick="clearLogs()">Clear Stored Logs</button>
      </div>
    </section>

    <section class="panel section">
      <h2>Settings</h2>
      <div class="controls">
        <div class="field">
          <label class="label" for="channelInput">Sniff channel</label>
          <input id="channelInput" type="number" min="1" max="13" value="1" />
        </div>
        <div class="field">
          <label class="label" for="note">Apply</label>
          <button class="btn" onclick="applyChannel()">Save channel and reboot</button>
        </div>
        <div class="field">
          <label class="label">Tip</label>
          <div class="tiny" style="padding-top: 10px;">Channel changes apply after reboot so the AP stays stable.</div>
        </div>
        <div class="field">
          <label class="label">Last refresh</label>
          <div id="lastRefresh" class="tiny" style="padding-top: 10px;">-</div>
        </div>
        <div class="field">
          <label class="label" for="sdCsInput">SD CS pin</label>
          <input id="sdCsInput" type="number" min="0" max="39" value="5" />
        </div>
        <div class="field">
          <label class="label" for="sdEnabledInput">SD logging</label>
          <button class="btn secondary" onclick="applySdSettings()">Save SD settings and reboot</button>
        </div>
        <div class="field">
          <label class="label">SD note</label>
          <div class="tiny" style="padding-top: 10px;">Use a SPI microSD breakout. The default CS pin is GPIO5.</div>
        </div>
      </div>
    </section>

    <section class="panel section">
      <h2>Recent Packets</h2>
      <div class="muted" style="margin-bottom: 12px;">Newest entries first. Export the CSV for deeper analysis on your Mac.</div>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Uptime</th>
              <th>Type</th>
              <th>Channel</th>
              <th>RSSI</th>
              <th>A1</th>
              <th>A2</th>
              <th>A3</th>
            </tr>
          </thead>
          <tbody id="recentRows"></tbody>
        </table>
      </div>
    </section>
  </div>
  <script>
    async function refresh() {
      const status = await (await fetch('/api/status')).json();
      document.getElementById('apName').textContent = status.ap_name;
      document.getElementById('apIp').textContent = status.ap_ip;
      document.getElementById('captureState').textContent = status.capture_enabled ? 'On' : 'Paused';
      document.getElementById('logState').textContent = status.filesystem_ready ? `LittleFS ${status.log_usage}` : 'LittleFS unavailable';
      document.getElementById('sdState').textContent = status.sd_enabled ? (status.sd_mounted ? 'Ready' : 'Missing') : 'Off';
      document.getElementById('sdLogState').textContent = status.sd_enabled ? (status.sd_mounted ? `SD ${status.sd_usage}` : `CS GPIO${status.sd_cs_pin}`) : 'SD logging disabled';
      document.getElementById('captured').textContent = status.captured_packets;
      document.getElementById('stored').textContent = status.stored_packets;
      document.getElementById('dropped').textContent = status.dropped_packets;
      document.getElementById('channel').textContent = status.channel;
      document.getElementById('typeBreakdown').textContent = `MGMT ${status.mgmt_packets} / DATA ${status.data_packets} / MISC ${status.misc_packets}`;
      document.getElementById('channelInput').value = status.channel;
      document.getElementById('sdCsInput').value = status.sd_cs_pin;
      document.getElementById('lastRefresh').textContent = new Date().toLocaleTimeString();

      const recent = await (await fetch('/api/recent?limit=12')).json();
      const tbody = document.getElementById('recentRows');
      tbody.innerHTML = recent.map(r => `
        <tr>
          <td>${r.uptime_ms}</td>
          <td>${r.type}</td>
          <td>${r.channel}</td>
          <td>${r.rssi}</td>
          <td>${r.addr1}</td>
          <td>${r.addr2}</td>
          <td>${r.addr3}</td>
        </tr>`).join('');
    }
    async function toggleCapture() {
      await fetch('/api/capture/toggle', { method: 'POST' });
      refresh();
    }
    async function clearLogs() {
      if (!confirm('Delete stored packet logs from flash?')) return;
      await fetch('/api/logs/clear', { method: 'POST' });
      refresh();
    }
    async function applySdSettings() {
      const sdCs = document.getElementById('sdCsInput').value;
      await fetch(`/api/sd?cs=${encodeURIComponent(sdCs)}`, { method: 'POST' });
      alert('SD settings saved. The ESP32 will reboot to apply them.');
    }
    async function applyChannel() {
      const channel = document.getElementById('channelInput').value;
      await fetch(`/api/channel?value=${encodeURIComponent(channel)}`, { method: 'POST' });
      alert('Channel saved. The ESP32 will reboot to apply it.');
    }
    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
)rawliteral";

static void formatMac(const uint8_t mac[6], char* out, size_t len) {
  snprintf(out, len, "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static const char* packetTypeToString(uint8_t type) {
  switch (type) {
    case WIFI_PKT_MGMT: return "MGMT";
    case WIFI_PKT_DATA: return "DATA";
    default: return "MISC";
  }
}

static bool isValidChannel(int channel) {
  return channel >= MIN_CHANNEL && channel <= MAX_CHANNEL;
}

static void loadSettings() {
  prefs.begin("sniffer", false);
  settings.channel = prefs.getUChar("channel", DEFAULT_CHANNEL);
  if (!isValidChannel(settings.channel)) {
    settings.channel = DEFAULT_CHANNEL;
  }
  settings.sdCsPin = prefs.getUChar("sd_cs", DEFAULT_SD_CS_PIN);
  if (settings.sdCsPin > 39) {
    settings.sdCsPin = DEFAULT_SD_CS_PIN;
  }
  settings.captureEnabled = prefs.getBool("capture", true);
  settings.sdEnabled = prefs.getBool("sd_enabled", true);
  stats.capturedPackets = prefs.getUInt("seen", 0);
  stats.storedPackets = prefs.getUInt("stored", 0);
  stats.droppedPackets = prefs.getUInt("dropped", 0);
  stats.mgmtPackets = prefs.getUInt("mgmt", 0);
  stats.dataPackets = prefs.getUInt("data", 0);
  stats.miscPackets = prefs.getUInt("misc", 0);
  stats.logRotations = prefs.getUInt("rotations", 0);
  stats.sdRotations = prefs.getUInt("sd_rotations", 0);
  stats.sdWriteFailures = prefs.getUInt("sd_failures", 0);
  prefs.end();
}

static void saveSettings() {
  prefs.begin("sniffer", false);
  prefs.putUChar("channel", settings.channel);
  prefs.putUChar("sd_cs", settings.sdCsPin);
  prefs.putBool("capture", settings.captureEnabled);
  prefs.putBool("sd_enabled", settings.sdEnabled);
  prefs.putUInt("seen", stats.capturedPackets);
  prefs.putUInt("stored", stats.storedPackets);
  prefs.putUInt("dropped", stats.droppedPackets);
  prefs.putUInt("mgmt", stats.mgmtPackets);
  prefs.putUInt("data", stats.dataPackets);
  prefs.putUInt("misc", stats.miscPackets);
  prefs.putUInt("rotations", stats.logRotations);
  prefs.putUInt("sd_rotations", stats.sdRotations);
  prefs.putUInt("sd_failures", stats.sdWriteFailures);
  prefs.end();
  lastStateSaveMs = millis();
}

static void initDisplay() {
  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println(F("SSD1306 allocation failed"));
    return;
  }
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setTextWrap(false);
  display.setCursor(0, 0);
  display.println("ESP32 WiFi Sniffer");
  display.println("Starting...");
  display.display();
}

static void startAccessPoint() {
  WiFi.mode(WIFI_AP);
  esp_wifi_set_ps(WIFI_PS_NONE);
  IPAddress localIp(192, 168, 4, 1);
  IPAddress gateway(192, 168, 4, 1);
  IPAddress subnet(255, 255, 255, 0);
  WiFi.softAPConfig(localIp, gateway, subnet);

  if (!WiFi.softAP(AP_SSID, AP_PASSWORD, settings.channel)) {
    Serial.println(F("SoftAP start failed"));
  }

  Serial.printf("AP ready: %s\n", AP_SSID);
  Serial.printf("AP IP: %s\n", WiFi.softAPIP().toString().c_str());
  Serial.printf("AP channel: %u\n", settings.channel);
}

static void initStorage() {
  flashStorage.mounted = false;
  filesystemReady = LittleFS.begin(true);
  if (filesystemReady) {
    Serial.println(F("LittleFS mounted"));
    flashStorage.mounted = true;
    ensureCurrentLogHeader(flashStorage);
  } else {
    Serial.println(F("LittleFS mount failed"));
  }

  initSdStorage();
}

static void initSdStorage() {
  sdFilesystemReady = false;
  sdStorage.mounted = false;
  if (!settings.sdEnabled) {
    return;
  }

  pinMode(settings.sdCsPin, OUTPUT);
  digitalWrite(settings.sdCsPin, HIGH);

  if (!SD.begin(settings.sdCsPin)) {
    Serial.println(F("SD mount failed"));
    return;
  }

  sdFilesystemReady = true;
  sdStorage.mounted = true;
  Serial.println(F("SD mounted"));
  ensureCurrentLogHeader(sdStorage);
}

static void ensureCurrentLogHeader(StorageBackend& storage) {
  if (!storage.mounted) {
    return;
  }
  if (storage.fs->exists(CURRENT_LOG_PATH)) {
    return;
  }
  File file = storage.fs->open(CURRENT_LOG_PATH, FILE_WRITE);
  if (!file) {
    return;
  }
  file.println(CSV_HEADER);
  file.close();
}

static void rotateLogs(StorageBackend& storage) {
  if (!storage.mounted) {
    return;
  }

  for (int i = LOG_ARCHIVE_COUNT - 1; i > 0; --i) {
    if (storage.fs->exists(ARCHIVE_PATHS[i - 1])) {
      if (storage.fs->exists(ARCHIVE_PATHS[i])) {
        storage.fs->remove(ARCHIVE_PATHS[i]);
      }
      storage.fs->rename(ARCHIVE_PATHS[i - 1], ARCHIVE_PATHS[i]);
    }
  }

  if (storage.fs->exists(CURRENT_LOG_PATH)) {
    if (storage.fs->exists(ARCHIVE_PATHS[0])) {
      storage.fs->remove(ARCHIVE_PATHS[0]);
    }
    storage.fs->rename(CURRENT_LOG_PATH, ARCHIVE_PATHS[0]);
  }

  if (storage.fs == &LittleFS) {
    stats.logRotations++;
  } else {
    stats.sdRotations++;
  }
  ensureCurrentLogHeader(storage);
}

static String recordToCsv(const PacketRecord& record) {
  char a1[18];
  char a2[18];
  char a3[18];
  formatMac(record.addr1, a1, sizeof(a1));
  formatMac(record.addr2, a2, sizeof(a2));
  formatMac(record.addr3, a3, sizeof(a3));

  char line[192];
  snprintf(line, sizeof(line), "%lu,%u,%d,%s,%s,%s,%s",
           (unsigned long)record.uptimeMs,
           record.channel,
           record.rssi,
           packetTypeToString(record.type),
           a1,
           a2,
           a3);
  return String(line);
}

static String recordToJson(const PacketRecord& record) {
  char a1[18];
  char a2[18];
  char a3[18];
  formatMac(record.addr1, a1, sizeof(a1));
  formatMac(record.addr2, a2, sizeof(a2));
  formatMac(record.addr3, a3, sizeof(a3));

  String json = "{";
  json += "\"uptime_ms\":";
  json += record.uptimeMs;
  json += ",\"channel\":";
  json += record.channel;
  json += ",\"rssi\":";
  json += record.rssi;
  json += ",\"type\":\"";
  json += packetTypeToString(record.type);
  json += "\",\"addr1\":\"";
  json += a1;
  json += "\",\"addr2\":\"";
  json += a2;
  json += "\",\"addr3\":\"";
  json += a3;
  json += "\"}";
  return json;
}

static bool appendRecordToLog(StorageBackend& storage, const PacketRecord& record) {
  if (!storage.mounted) {
    return false;
  }

  ensureCurrentLogHeader(storage);
  String line = recordToCsv(record);
  line += '\n';

  File file = storage.fs->open(CURRENT_LOG_PATH, FILE_APPEND);
  if (!file) {
    return false;
  }

  if ((uint32_t)file.size() + line.length() > LOG_ROTATE_LIMIT) {
    file.close();
    rotateLogs(storage);
    file = storage.fs->open(CURRENT_LOG_PATH, FILE_APPEND);
    if (!file) {
      return false;
    }
  }

  file.print(line);
  file.close();
  return true;
}

static void appendRecordToStorage(const PacketRecord& record) {
  bool wroteAny = false;
  if (filesystemReady) {
    wroteAny = appendRecordToLog(flashStorage, record) || wroteAny;
  }
  if (sdFilesystemReady) {
    if (appendRecordToLog(sdStorage, record)) {
      wroteAny = true;
    } else {
      stats.sdWriteFailures++;
    }
  }
  if (wroteAny) {
    stats.storedPackets++;
  }
}

static void queuePacket(const PacketRecord& record) {
  portENTER_CRITICAL(&liveBufferMux);
  if (liveCount == LIVE_BUFFER_SIZE) {
    liveTail = (liveTail + 1) % LIVE_BUFFER_SIZE;
    liveCount--;
    stats.droppedPackets++;
  }
  liveBuffer[liveHead] = record;
  liveHead = (liveHead + 1) % LIVE_BUFFER_SIZE;
  liveCount++;
  portEXIT_CRITICAL(&liveBufferMux);
}

static bool dequeuePacket(PacketRecord& out) {
  bool hasItem = false;
  portENTER_CRITICAL(&liveBufferMux);
  if (liveCount > 0) {
    out = liveBuffer[liveTail];
    liveTail = (liveTail + 1) % LIVE_BUFFER_SIZE;
    liveCount--;
    hasItem = true;
  }
  portEXIT_CRITICAL(&liveBufferMux);
  return hasItem;
}

static void addToRecent(const PacketRecord& record) {
  portENTER_CRITICAL(&liveBufferMux);
  recentBuffer[recentHead] = record;
  recentHead = (recentHead + 1) % RECENT_BUFFER_SIZE;
  if (recentCount < RECENT_BUFFER_SIZE) {
    recentCount++;
  }
  portEXIT_CRITICAL(&liveBufferMux);
}

static void updateStatsForType(uint8_t type) {
  stats.capturedPackets++;
  switch (type) {
    case WIFI_PKT_MGMT: stats.mgmtPackets++; break;
    case WIFI_PKT_DATA: stats.dataPackets++; break;
    default: stats.miscPackets++; break;
  }
}

static void renderPacketToSerial(const PacketRecord& record) {
  char a1[18];
  char a2[18];
  char a3[18];
  formatMac(record.addr1, a1, sizeof(a1));
  formatMac(record.addr2, a2, sizeof(a2));
  formatMac(record.addr3, a3, sizeof(a3));
  Serial.printf("[%lu] ch=%u rssi=%d type=%s a1=%s a2=%s a3=%s\n",
                (unsigned long)record.uptimeMs,
                record.channel,
                record.rssi,
                packetTypeToString(record.type),
                a1, a2, a3);
}

static void flushQueuedPackets() {
  PacketRecord record;
  while (dequeuePacket(record)) {
    updateStatsForType(record.type);
    appendRecordToStorage(record);
    addToRecent(record);
    renderPacketToSerial(record);
  }
}

static String getStorageUsageSummary(StorageBackend& storage) {
  if (!storage.mounted) {
    return "offline";
  }
  size_t total = 0;
  size_t used = 0;
  if (storage.fs == &LittleFS) {
    total = LittleFS.totalBytes();
    used = LittleFS.usedBytes();
  } else if (storage.fs == &SD) {
    total = SD.totalBytes();
    used = SD.usedBytes();
  } else {
    return "offline";
  }
  char buf[64];
  snprintf(buf, sizeof(buf), "%u%% used (%lu/%lu KB)",
           total ? (unsigned int)((used * 100UL) / total) : 0,
           (unsigned long)(used / 1024UL),
           (unsigned long)(total / 1024UL));
  return String(buf);
}

static String getLogUsageSummary() {
  return getStorageUsageSummary(flashStorage);
}

static String buildStatusJson() {
  String json = "{";
  json += "\"ap_name\":\"";
  json += AP_SSID;
  json += "\",\"ap_ip\":\"";
  json += WiFi.softAPIP().toString();
  json += "\",\"capture_enabled\":";
  json += settings.captureEnabled ? "true" : "false";
  json += ",\"filesystem_ready\":";
  json += filesystemReady ? "true" : "false";
  json += ",\"log_usage\":\"";
  json += getLogUsageSummary();
  json += "\",\"sd_enabled\":";
  json += settings.sdEnabled ? "true" : "false";
  json += ",\"sd_mounted\":";
  json += sdFilesystemReady ? "true" : "false";
  json += ",\"sd_usage\":\"";
  json += getStorageUsageSummary(sdStorage);
  json += "\",\"sd_cs_pin\":";
  json += settings.sdCsPin;
  json += ",\"channel\":";
  json += settings.channel;
  json += ",\"captured_packets\":";
  json += stats.capturedPackets;
  json += ",\"stored_packets\":";
  json += stats.storedPackets;
  json += ",\"dropped_packets\":";
  json += stats.droppedPackets;
  json += ",\"mgmt_packets\":";
  json += stats.mgmtPackets;
  json += ",\"data_packets\":";
  json += stats.dataPackets;
  json += ",\"misc_packets\":";
  json += stats.miscPackets;
  json += ",\"log_rotations\":";
  json += stats.logRotations;
  json += ",\"sd_rotations\":";
  json += stats.sdRotations;
  json += ",\"sd_write_failures\":";
  json += stats.sdWriteFailures;
  json += ",\"buffered_packets\":";
  json += liveCount;
  json += "}";
  return json;
}

static String buildRecentJson(uint8_t limit) {
  if (limit == 0) {
    limit = 1;
  }
  if (limit > RECENT_BUFFER_SIZE) {
    limit = RECENT_BUFFER_SIZE;
  }

  uint8_t snapshotCount;
  uint8_t snapshotHead;
  portENTER_CRITICAL(&liveBufferMux);
  snapshotCount = recentCount;
  snapshotHead = recentHead;
  portEXIT_CRITICAL(&liveBufferMux);

  String json = "[";
  uint8_t emitted = 0;
  for (uint8_t i = 0; i < snapshotCount && emitted < limit; ++i) {
    int index = (int)snapshotHead - 1 - i;
    while (index < 0) {
      index += RECENT_BUFFER_SIZE;
    }
    const PacketRecord& record = recentBuffer[index];
    if (emitted > 0) {
      json += ",";
    }
    json += recordToJson(record);
    emitted++;
  }
  json += "]";
  return json;
}

static void sendDashboard() {
  server.send_P(200, "text/html; charset=utf-8", INDEX_HTML);
}

static void sendStatusJson() {
  server.send(200, "application/json", buildStatusJson());
}

static void sendRecentJson() {
  int limit = server.hasArg("limit") ? server.arg("limit").toInt() : 12;
  server.send(200, "application/json", buildRecentJson((uint8_t)limit));
}

static void sendCsvExport() {
  if (!filesystemReady) {
    server.send(503, "text/plain", "LittleFS unavailable");
    return;
  }
  server.sendHeader("Content-Disposition", "attachment; filename=\"esp32-sniffer.csv\"");
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "text/csv", "");
  server.sendContent(String(CSV_HEADER) + "\n");

  const char* paths[LOG_ARCHIVE_COUNT + 1];
  uint8_t count = 0;
  for (int i = LOG_ARCHIVE_COUNT - 1; i >= 0; --i) {
    paths[count++] = ARCHIVE_PATHS[i];
  }
  paths[count++] = CURRENT_LOG_PATH;

  for (uint8_t i = 0; i < count; ++i) {
    if (!flashStorage.fs->exists(paths[i])) {
      continue;
    }
    File file = flashStorage.fs->open(paths[i], FILE_READ);
    if (!file) {
      continue;
    }

    bool headerSkipped = false;
    while (file.available()) {
      String line = file.readStringUntil('\n');
      line.trim();
      if (line.length() == 0) {
        continue;
      }
      if (!headerSkipped && line == CSV_HEADER) {
        headerSkipped = true;
        continue;
      }
      headerSkipped = true;
      server.sendContent(line + "\n");
    }
    file.close();
  }
}

static void sendSdCsvExport() {
  if (!sdFilesystemReady) {
    server.send(503, "text/plain", "SD unavailable");
    return;
  }

  server.sendHeader("Content-Disposition", "attachment; filename=\"esp32-sniffer-sd.csv\"");
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "text/csv", "");
  server.sendContent(String(CSV_HEADER) + "\n");

  const char* paths[LOG_ARCHIVE_COUNT + 1];
  uint8_t count = 0;
  for (int i = LOG_ARCHIVE_COUNT - 1; i >= 0; --i) {
    paths[count++] = ARCHIVE_PATHS[i];
  }
  paths[count++] = CURRENT_LOG_PATH;

  for (uint8_t i = 0; i < count; ++i) {
    if (!sdStorage.fs->exists(paths[i])) {
      continue;
    }
    File file = sdStorage.fs->open(paths[i], FILE_READ);
    if (!file) {
      continue;
    }

    bool headerSkipped = false;
    while (file.available()) {
      String line = file.readStringUntil('\n');
      line.trim();
      if (line.length() == 0) {
        continue;
      }
      if (!headerSkipped && line == CSV_HEADER) {
        headerSkipped = true;
        continue;
      }
      headerSkipped = true;
      server.sendContent(line + "\n");
    }
    file.close();
  }
}

static void clearStoredLogs() {
  if (filesystemReady) {
    if (flashStorage.fs->exists(CURRENT_LOG_PATH)) {
      flashStorage.fs->remove(CURRENT_LOG_PATH);
    }
    for (uint8_t i = 0; i < LOG_ARCHIVE_COUNT; ++i) {
      if (flashStorage.fs->exists(ARCHIVE_PATHS[i])) {
        flashStorage.fs->remove(ARCHIVE_PATHS[i]);
      }
    }
    ensureCurrentLogHeader(flashStorage);
  }

  if (sdFilesystemReady) {
    if (sdStorage.fs->exists(CURRENT_LOG_PATH)) {
      sdStorage.fs->remove(CURRENT_LOG_PATH);
    }
    for (uint8_t i = 0; i < LOG_ARCHIVE_COUNT; ++i) {
      if (sdStorage.fs->exists(ARCHIVE_PATHS[i])) {
        sdStorage.fs->remove(ARCHIVE_PATHS[i]);
      }
    }
    ensureCurrentLogHeader(sdStorage);
  }

  stats.storedPackets = 0;
  stats.droppedPackets = 0;
  stats.logRotations = 0;
  stats.sdRotations = 0;
  stats.sdWriteFailures = 0;
  recentCount = 0;
  recentHead = 0;
  saveSettings();
}

static void handleChannelChange() {
  if (!server.hasArg("value")) {
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"missing value\"}");
    return;
  }

  int channel = server.arg("value").toInt();
  if (!isValidChannel(channel)) {
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"channel must be 1-13\"}");
    return;
  }

  settings.channel = (uint8_t)channel;
  saveSettings();
  scheduleReboot(1500);
  String response = "{\"ok\":true,\"reboot\":true,\"channel\":";
  response += settings.channel;
  response += "}";
  server.send(200, "application/json", response);
}

static void handleSdChange() {
  if (server.hasArg("enabled")) {
    String enabled = server.arg("enabled");
    settings.sdEnabled = (enabled == "1" || enabled == "true" || enabled == "on");
  }

  if (server.hasArg("cs")) {
    int cs = server.arg("cs").toInt();
    if (cs >= 0 && cs <= 39) {
      settings.sdCsPin = (uint8_t)cs;
    } else {
      server.send(400, "application/json", "{\"ok\":false,\"error\":\"cs must be 0-39\"}");
      return;
    }
  }

  saveSettings();
  scheduleReboot(1500);
  String response = "{\"ok\":true,\"reboot\":true,\"sd_enabled\":";
  response += settings.sdEnabled ? "true" : "false";
  response += ",\"sd_cs_pin\":";
  response += settings.sdCsPin;
  response += "}";
  server.send(200, "application/json", response);
}

static void handleCaptureToggle() {
  settings.captureEnabled = !settings.captureEnabled;
  if (settings.captureEnabled) {
    startCapture();
  } else {
    stopCapture();
  }
  saveSettings();
  server.send(200, "application/json",
              String("{\"ok\":true,\"capture_enabled\":") + (settings.captureEnabled ? "true" : "false") + "}");
}

static void sendClearResponse() {
  clearStoredLogs();
  server.send(200, "application/json", "{\"ok\":true}");
}

static void sendSdClearResponse() {
  clearStoredLogs();
  server.send(200, "application/json", "{\"ok\":true}");
}

static void handleRootNotFound() {
  server.send(404, "text/plain", "Not found");
}

static void startCapture() {
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_channel(settings.channel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(&wifiSnifferCallback);
  esp_wifi_set_promiscuous(true);
  captureRunning = true;
}

static void stopCapture() {
  esp_wifi_set_promiscuous(false);
  captureRunning = false;
}

static void scheduleReboot(uint32_t delayMs) {
  rebootPending = true;
  rebootAtMs = millis() + delayMs;
}

static void wifiSnifferCallback(void* buff, wifi_promiscuous_pkt_type_t type) {
  if (!settings.captureEnabled) {
    return;
  }
  const wifi_promiscuous_pkt_t* ppkt = (wifi_promiscuous_pkt_t*)buff;
  const wifi_ieee80211_packet_t* ipkt = (wifi_ieee80211_packet_t*)ppkt->payload;

  PacketRecord record{};
  record.uptimeMs = millis();
  record.channel = ppkt->rx_ctrl.channel;
  record.rssi = ppkt->rx_ctrl.rssi;
  record.type = (uint8_t)type;
  memcpy(record.addr1, ipkt->hdr.addr1, sizeof(record.addr1));
  memcpy(record.addr2, ipkt->hdr.addr2, sizeof(record.addr2));
  memcpy(record.addr3, ipkt->hdr.addr3, sizeof(record.addr3));
  queuePacket(record);
}

static void drawDisplay() {
  PacketRecord last{};
  bool hasLast = false;
  uint8_t snapshotCount;
  uint8_t snapshotHead;
  portENTER_CRITICAL(&liveBufferMux);
  snapshotCount = recentCount;
  snapshotHead = recentHead;
  if (snapshotCount > 0) {
    last = recentBuffer[(snapshotHead + RECENT_BUFFER_SIZE - 1) % RECENT_BUFFER_SIZE];
    hasLast = true;
  }
  portEXIT_CRITICAL(&liveBufferMux);

  display.clearDisplay();
  display.setCursor(0, 0);
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  display.println(F("ESP32 WiFi Sniffer"));
  display.print(F("AP: "));
  display.println(AP_SSID);
  display.print(F("IP: "));
  display.println(WiFi.softAPIP());
  display.print(F("Ch: "));
  display.print(settings.channel);
  display.print(F(" Cap: "));
  display.println(settings.captureEnabled ? F("ON") : F("OFF"));
  display.print(F("Seen: "));
  display.println(stats.capturedPackets);
  display.print(F("SD: "));
  display.println(settings.sdEnabled ? (sdFilesystemReady ? F("READY") : F("MISSING")) : F("OFF"));

  if (hasLast) {
    display.print(F("Last "));
    display.print(packetTypeToString(last.type));
    display.print(F(" RSSI "));
    display.println(last.rssi);
  }

  display.display();
}

static void writeStateIfNeeded(bool force) {
  if (!force && (millis() - lastStateSaveMs) < STATE_SAVE_INTERVAL_MS) {
    return;
  }
  saveSettings();
}

void setup() {
  Serial.begin(115200);
  delay(100);

  initDisplay();
  loadSettings();
  initStorage();

  startAccessPoint();

  if (settings.captureEnabled) {
    startCapture();
  } else {
    captureRunning = false;
  }

  server.on("/", HTTP_GET, sendDashboard);
  server.on("/api/status", HTTP_GET, sendStatusJson);
  server.on("/api/recent", HTTP_GET, sendRecentJson);
  server.on("/download.csv", HTTP_GET, sendCsvExport);
  server.on("/download_sd.csv", HTTP_GET, sendSdCsvExport);
  server.on("/api/logs/clear", HTTP_POST, sendClearResponse);
  server.on("/api/sd", HTTP_POST, handleSdChange);
  server.on("/api/capture/toggle", HTTP_POST, handleCaptureToggle);
  server.on("/api/channel", HTTP_POST, handleChannelChange);
  server.onNotFound(handleRootNotFound);
  server.begin();

  saveSettings();

  Serial.println(F("Dashboard ready"));
  Serial.printf("Open http://%s/\n", WiFi.softAPIP().toString().c_str());
}

void loop() {
  server.handleClient();
  flushQueuedPackets();
  drawDisplay();
  writeStateIfNeeded(false);

  if (rebootPending && millis() >= rebootAtMs) {
    writeStateIfNeeded(true);
    delay(250);
    ESP.restart();
  }

  delay(5);
}
