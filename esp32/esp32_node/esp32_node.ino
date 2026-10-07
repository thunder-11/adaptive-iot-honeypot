/*
 * Adaptive IoT Honeypot door node.
 *
 * External LED convention:
 *   LED ON  = LOCKED
 *   LED OFF = UNLOCKED
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include "secrets.h"

// Sensor selection constants
#define BUTTON 1
#define PIR 2
#define REED 3
#define DHT11_SENSOR 4
#define LDR 5

#define SENSOR_TYPE BUTTON

// Change these if your relay or LED uses inverted logic.
#define RELAY_ACTIVE_LOW true
#define LED_ACTIVE_HIGH true

// ---------- EDIT THIS CONFIG BLOCK BEFORE FLASHING ----------


// Raspberry Pi's LAN IP address
const char* PI_IP = "192.168.1.10";

// Must match config.env on the Raspberry Pi
const char* MQTT_USER = "iotuser";

// Update these addresses for your network
IPAddress ESP32_STATIC_IP(192, 168, 1, 50);
IPAddress GATEWAY(192, 168, 1, 1);
IPAddress SUBNET(255, 255, 255, 0);
IPAddress DNS_SERVER(8, 8, 8, 8);

// ESP32 GPIO pins
const int SENSOR_PIN = 27;
const int RELAY_PIN = 26;
const int STATUS_LED_PIN = 2;

// MQTT configuration
const int MQTT_PORT = 1883;
const char* COMMAND_TOPIC = "home/door/lock";
const char* STATUS_TOPIC = "home/door/status";
const char* SENSOR_TOPIC = "home/door/motion";

// -----------------------------------------------------------

#if SENSOR_TYPE == DHT11_SENSOR
#include <DHT.h>
#define DHT_MODEL DHT11
DHT dht(SENSOR_PIN, DHT_MODEL);
#endif

WiFiClient networkClient;
PubSubClient mqtt(networkClient);

unsigned long lastWifiAttempt = 0;
unsigned long lastMqttAttempt = 0;
unsigned long lastSensorPublish = 0;

bool locked = true;
bool ledOn = true;

void driveRelay(bool shouldLock) {
  locked = shouldLock;

  // The relay is energized only when the door is unlocked.
  bool relayActive = !shouldLock;

  int relayLevel;

  if (RELAY_ACTIVE_LOW) {
    relayLevel = relayActive ? LOW : HIGH;
  } else {
    relayLevel = relayActive ? HIGH : LOW;
  }

  digitalWrite(RELAY_PIN, relayLevel);

  // Demo convention:
  // LOCKED   = LED ON
  // UNLOCKED = LED OFF
  ledOn = shouldLock;

  int ledLevel;

  if (LED_ACTIVE_HIGH) {
    ledLevel = ledOn ? HIGH : LOW;
  } else {
    ledLevel = ledOn ? LOW : HIGH;
  }

  digitalWrite(STATUS_LED_PIN, ledLevel);

  Serial.print("REAL DEVICE: ");
  Serial.print(locked ? "LOCKED" : "UNLOCKED");
  Serial.print(" | EXTERNAL LED: ");
  Serial.println(ledOn ? "ON" : "OFF");
}

void publishStatus() {
  if (!mqtt.connected()) {
    return;
  }

  const char* payload;

  if (locked) {
    payload =
      "{\"locked\":true,"
      "\"led_on\":true,"
      "\"source\":\"esp32\"}";
  } else {
    payload =
      "{\"locked\":false,"
      "\"led_on\":false,"
      "\"source\":\"esp32\"}";
  }

  bool published = mqtt.publish(STATUS_TOPIC, payload, true);

  if (published) {
    Serial.print("Status published: ");
    Serial.println(payload);
  } else {
    Serial.println("Failed to publish device status");
  }
}

void onMessage(
  char* topic,
  byte* payload,
  unsigned int length
) {
  String command;

  for (unsigned int i = 0; i < length; i++) {
    command += static_cast<char>(payload[i]);
  }

  command.trim();
  command.toLowerCase();

  Serial.print("MQTT message received on ");
  Serial.print(topic);
  Serial.print(": ");
  Serial.println(command);

  if (String(topic) != COMMAND_TOPIC) {
    return;
  }

  if (command == "lock") {
    driveRelay(true);
  } else if (command == "unlock") {
    driveRelay(false);
  } else {
    Serial.print("Ignored invalid command: ");
    Serial.println(command);
    return;
  }

  Serial.print("Command applied on REAL broker path: ");
  Serial.println(command);

  publishStatus();
}

void startWifiIfNeeded() {
  if (WiFi.status() == WL_CONNECTED) {
    return;
  }

  unsigned long now = millis();

  if (now - lastWifiAttempt < 5000) {
    return;
  }

  lastWifiAttempt = now;

  Serial.println("Connecting to Wi-Fi...");

  WiFi.disconnect();

  bool configured = WiFi.config(
    ESP32_STATIC_IP,
    GATEWAY,
    SUBNET,
    DNS_SERVER
  );

  if (!configured) {
    Serial.println("Failed to configure static IP");
  }

  WiFi.begin(WIFI_SSID, WIFI_PASS);
}

void printWifiStatus() {
  Serial.println("Wi-Fi connected");

  Serial.print("ESP32 IP: ");
  Serial.println(WiFi.localIP());

  Serial.print("Raspberry Pi: ");
  Serial.println(PI_IP);

  Serial.print("Wi-Fi signal: ");
  Serial.print(WiFi.RSSI());
  Serial.println(" dBm");
}

void startMqttIfNeeded() {
  if (WiFi.status() != WL_CONNECTED) {
    return;
  }

  if (mqtt.connected()) {
    return;
  }

  unsigned long now = millis();

  if (now - lastMqttAttempt < 3000) {
    return;
  }

  lastMqttAttempt = now;

  uint64_t chipId = ESP.getEfuseMac();

  String clientId = "esp32-door-";
  clientId += String(
    static_cast<uint32_t>(chipId),
    HEX
  );

  Serial.print("Connecting MQTT to ");
  Serial.print(PI_IP);
  Serial.print(":");
  Serial.println(MQTT_PORT);

  bool connected = mqtt.connect(
    clientId.c_str(),
    MQTT_USER,
    MQTT_PASS
  );

  if (connected) {
    Serial.println("MQTT connected");

    bool subscribed = mqtt.subscribe(COMMAND_TOPIC);

    if (subscribed) {
      Serial.print("Subscribed to: ");
      Serial.println(COMMAND_TOPIC);
    } else {
      Serial.println("Failed to subscribe to command topic");
    }

    publishStatus();
  } else {
    Serial.print("MQTT connection failed, state=");
    Serial.println(mqtt.state());
  }
}

String readSensor() {
#if SENSOR_TYPE == BUTTON || SENSOR_TYPE == PIR || SENSOR_TYPE == REED

  return digitalRead(SENSOR_PIN) == HIGH ? "1" : "0";

#elif SENSOR_TYPE == DHT11_SENSOR

  float humidity = dht.readHumidity();
  float temperature = dht.readTemperature();

  if (isnan(humidity) || isnan(temperature)) {
    return "{\"error\":\"dht-read\"}";
  }

  return
    "{\"temperature_c\":" +
    String(temperature, 1) +
    ",\"humidity\":" +
    String(humidity, 1) +
    "}";

#elif SENSOR_TYPE == LDR

  return String(analogRead(SENSOR_PIN));

#else

  return "0";

#endif
}

void configurePins() {
  pinMode(RELAY_PIN, OUTPUT);
  pinMode(STATUS_LED_PIN, OUTPUT);

#if SENSOR_TYPE == BUTTON || SENSOR_TYPE == REED

  pinMode(SENSOR_PIN, INPUT_PULLUP);

#elif SENSOR_TYPE == PIR

  pinMode(SENSOR_PIN, INPUT);

#elif SENSOR_TYPE == DHT11_SENSOR

  dht.begin();

#elif SENSOR_TYPE == LDR

  pinMode(SENSOR_PIN, INPUT);

#endif
}

void setup() {
  Serial.begin(115200);

  delay(500);

  Serial.println();
  Serial.println("Adaptive IoT Honeypot ESP32 starting...");

  configurePins();

  // Fail-secure state when the device boots.
  driveRelay(true);

  WiFi.mode(WIFI_STA);

  mqtt.setServer(PI_IP, MQTT_PORT);
  mqtt.setCallback(onMessage);
  mqtt.setBufferSize(512);
  mqtt.setKeepAlive(30);

  startWifiIfNeeded();
}

void loop() {
  static bool wifiWasConnected = false;

  startWifiIfNeeded();

  bool wifiConnected = WiFi.status() == WL_CONNECTED;

  if (wifiConnected && !wifiWasConnected) {
    printWifiStatus();
  }

  wifiWasConnected = wifiConnected;

  startMqttIfNeeded();

  if (mqtt.connected()) {
    mqtt.loop();
  }

  unsigned long now = millis();

  if (
    mqtt.connected() &&
    now - lastSensorPublish >= 2000
  ) {
    lastSensorPublish = now;

    String value = readSensor();

    bool published = mqtt.publish(
      SENSOR_TOPIC,
      value.c_str()
    );

    if (published) {
      Serial.print("Sensor published: ");
      Serial.println(value);
    } else {
      Serial.println("Sensor publish failed");
    }
  }

  delay(5);
}
