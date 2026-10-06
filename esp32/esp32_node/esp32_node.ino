/*
 * Adaptive IoT Honeypot door node.
 * All network and pin settings that normally change are grouped here.
 */
#include <WiFi.h>
#include <PubSubClient.h>

#define BUTTON 1
#define PIR 2
#define REED 3
#define DHT11 4
#define LDR 5
#define SENSOR_TYPE BUTTON
#define RELAY_ACTIVE_LOW true

// ---------- EDIT THIS CONFIG BLOCK BEFORE FLASHING ----------
const char* WIFI_SSID = "YOUR_WIFI_NAME";
const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";
const char* PI_IP = "192.168.1.10";
const char* MQTT_USER = "iotuser";
const char* MQTT_PASS = "change-this-before-demo";
IPAddress ESP32_STATIC_IP(192, 168, 1, 50);
IPAddress GATEWAY(192, 168, 1, 1);
IPAddress SUBNET(255, 255, 255, 0);
const int SENSOR_PIN = 27;
const int RELAY_PIN = 26;
const int STATUS_LED_PIN = 2;
// -----------------------------------------------------------

#if SENSOR_TYPE == DHT11
// Our mode selector uses the readable DHT11 name; let the library now replace
// it with the sensor model number expected by its constructor.
#undef DHT11
#include <DHT.h>
DHT dht(SENSOR_PIN, DHT11);
#endif

WiFiClient networkClient;
PubSubClient mqtt(networkClient);
unsigned long lastWifiAttempt = 0;
unsigned long lastMqttAttempt = 0;
unsigned long lastSensorPublish = 0;
bool locked = true;

void driveRelay(bool shouldLock) {
  locked = shouldLock;
  // Many relay boards are active-low: LOW energizes the coil. Never feed 5 V
  // into an ESP32 GPIO; use a 3.3 V-compatible module or a transistor driver.
  bool active = !shouldLock; // energize the demonstration actuator to unlock
  int level = RELAY_ACTIVE_LOW ? (active ? LOW : HIGH) : (active ? HIGH : LOW);
  digitalWrite(RELAY_PIN, level);
  digitalWrite(STATUS_LED_PIN, shouldLock ? HIGH : LOW);
}

void publishStatus() {
  const char* payload = locked
    ? "{\"locked\":true,\"source\":\"esp32\"}"
    : "{\"locked\":false,\"source\":\"esp32\"}";
  mqtt.publish("home/door/status", payload, true);
}

void onMessage(char* topic, byte* payload, unsigned int length) {
  String command;
  for (unsigned int i = 0; i < length; i++) command += (char)payload[i];
  command.trim();
  command.toLowerCase();
  if (String(topic) != "home/door/lock") return;
  if (command == "lock") driveRelay(true);
  else if (command == "unlock") driveRelay(false);
  else {
    Serial.printf("Ignored invalid command: %s\n", command.c_str());
    return;
  }
  Serial.printf("Command applied: %s\n", command.c_str());
  publishStatus();
}

void startWifiIfNeeded() {
  if (WiFi.status() == WL_CONNECTED) return;
  unsigned long now = millis();
  if (now - lastWifiAttempt < 5000) return;
  lastWifiAttempt = now;
  Serial.println("Connecting WiFi...");
  WiFi.disconnect();
  WiFi.config(ESP32_STATIC_IP, GATEWAY, SUBNET);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
}

void startMqttIfNeeded() {
  if (WiFi.status() != WL_CONNECTED || mqtt.connected()) return;
  unsigned long now = millis();
  if (now - lastMqttAttempt < 3000) return;
  lastMqttAttempt = now;
  String clientId = "esp32-door-" + String((uint32_t)ESP.getEfuseMac(), HEX);
  Serial.printf("Connecting MQTT to %s:1883...\n", PI_IP);
  if (mqtt.connect(clientId.c_str(), MQTT_USER, MQTT_PASS)) {
    Serial.println("MQTT connected");
    mqtt.subscribe("home/door/lock");
    publishStatus();
  } else {
    Serial.printf("MQTT connect failed, state=%d\n", mqtt.state());
  }
}

String readSensor() {
#if SENSOR_TYPE == BUTTON || SENSOR_TYPE == PIR || SENSOR_TYPE == REED
  return digitalRead(SENSOR_PIN) == HIGH ? "1" : "0";
#elif SENSOR_TYPE == DHT11
  float humidity = dht.readHumidity();
  float temperature = dht.readTemperature();
  if (isnan(humidity) || isnan(temperature)) return "{\"error\":\"dht-read\"}";
  return "{\"temperature_c\":" + String(temperature, 1) +
         ",\"humidity\":" + String(humidity, 1) + "}";
#elif SENSOR_TYPE == LDR
  return String(analogRead(SENSOR_PIN));
#else
  return "0";
#endif
}

void setup() {
  Serial.begin(115200);
  pinMode(RELAY_PIN, OUTPUT);
  pinMode(STATUS_LED_PIN, OUTPUT);
#if SENSOR_TYPE == BUTTON || SENSOR_TYPE == REED
  pinMode(SENSOR_PIN, INPUT_PULLUP);
#elif SENSOR_TYPE == PIR
  pinMode(SENSOR_PIN, INPUT);
#elif SENSOR_TYPE == DHT11
  dht.begin();
#endif
  driveRelay(true); // fail secure at boot
  mqtt.setServer(PI_IP, 1883);
  mqtt.setCallback(onMessage);
  mqtt.setBufferSize(512);
  startWifiIfNeeded();
}

void loop() {
  startWifiIfNeeded();
  startMqttIfNeeded();
  if (mqtt.connected()) mqtt.loop();
  unsigned long now = millis();
  if (mqtt.connected() && now - lastSensorPublish >= 2000) {
    lastSensorPublish = now;
    String value = readSensor();
    mqtt.publish("home/door/motion", value.c_str());
    Serial.printf("Sensor published: %s\n", value.c_str());
  }
  delay(5); // yield to WiFi; reconnection remains timer-driven and non-blocking
}
