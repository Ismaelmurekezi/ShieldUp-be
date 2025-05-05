#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>

// Wi-Fi credentials
const char* ssid = "Airtel_4G_SMARTBOX_0202";
const char* password = "password123";

// MQTT broker
const char* mqtt_server = "192.168.1.15";
const int mqtt_port = 1883;

WiFiClient espClient;
PubSubClient client(espClient);

const char* device_id = "esp1";
const char* target_topic = "device/esp2/inbox";
const char* inbox_topic = "device/esp1/inbox";

const uint8_t buttonPins[4] ={D1, D2, D3, D7};
const uint8_t buzzerPin = D8;

unsigned long lastDebounceTime[4] = {0, 0, 0, 0};
const unsigned long debounceDelay = 300;

bool hasUnreadMessage = false;
String messageId = "";

// LCD display timer
bool lcdMessageActive = false;
unsigned long lcdMessageStartTime = 0;
const unsigned long lcdDisplayDuration = 36000;
String lcdLine1 = "";
String lcdLine2 = "";

LiquidCrystal_I2C lcd(0x27, 16, 2);

// Buzzer state variables
bool buzzerActive = false;
unsigned long buzzerStartTime = 0;
const unsigned long buzzerDuration = 500;

void activateTempBuzzer() {
  
  digitalWrite(buzzerPin, HIGH);
  buzzerActive = true;
  buzzerStartTime = millis();
  Serial.println("🔔 Buzzer activated for temporary notification");
}

void setup_wifi() {
  delay(10);
  Serial.println("Connecting to WiFi...");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500); Serial.print(".");
  }
  Serial.println("\n✅ WiFi connected! IP: " + WiFi.localIP().toString());
}

void callback(char* topic, byte* payload, unsigned int length) {
  String received = "";
  for (int i = 0; i < length; i++) {
    received += (char)payload[i];
  }

  Serial.println("\n📩 Message received: " + received);
  
  DynamicJsonDocument doc(1024);
  DeserializationError error = deserializeJson(doc, received);
  if (error) {
    Serial.println("❌ Failed to parse JSON");
    return;
  }

  // Check if this is an acknowledgment message
  bool isAck = doc["acknowledge"] | false;

  if (isAck) {
    // This is an acknowledgment of our message
    String ackMessageId = doc["message_id"].as<String>();
    Serial.println("✅ Acknowledgment received for message ID: " + ackMessageId);
    
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("Ack received");
    lcd.setCursor(0, 1);
    lcd.print("Message ID: " + ackMessageId.substring(0, 8));
    lcdMessageActive = true;
    lcdMessageStartTime = millis();

    // Activate buzzer for acknowledgment - this was the problem area
    activateTempBuzzer();
    Serial.println("🔔 Buzzer activated for acknowledgment");
    lcd.clear();

  } else if (doc.containsKey("message") && doc.containsKey("message_id")) {
    // This is a new message, not an acknowledgment
    String message = doc["message"].as<String>();
    messageId = doc["message_id"].as<String>();
    Serial.println("Received message: " + message);

    // Turn on buzzer for new messages (stay on until button 4)
    hasUnreadMessage = true;
    digitalWrite(buzzerPin, HIGH);
    Serial.println("🔔 Buzzer turned ON for new message");
    
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("New Message:");
    lcd.setCursor(0, 1);
    lcd.print(message.substring(0, 16));
    lcdMessageActive = true;
    lcdMessageStartTime = millis();
  }
}

void sendAcknowledgment(String msgId) {
  String ackMessage = "{\"from\": \"" + String(device_id) + 
                    "\", \"acknowledge\": true, \"message_id\": \"" + 
                    msgId + "\"}";
  
  Serial.println("📤 Sending acknowledgment to the other device.");
  client.publish(target_topic, ackMessage.c_str());
  
  // Don't turn off our buzzer when sending acknowledgment - it needs to stay on
  // until the user explicitly acknowledges with button 4
  Serial.println("🔔 Buzzer state maintained until user presses acknowledge button");
}

void reconnect() {
  int retries = 0;
  // Modified to avoid blocking loop
  while (!client.connected() && retries < 3) {
    Serial.print("Attempting MQTT connection...");
    if (client.connect(device_id)) {
      Serial.println("✅ Connected!");
      client.subscribe(inbox_topic);
      
      // Test buzzer functionality again after connection
      digitalWrite(buzzerPin, HIGH);
      delay(100);
      digitalWrite(buzzerPin, LOW);
      Serial.println("✅ Buzzer test after MQTT connection");
    } else {
      Serial.print("❌ Failed (rc=");
      Serial.print(client.state());
      Serial.println("). Will retry...");
      delay(2000);
      retries++;
    }
  }
}

void sendMessageToDB(String msg) {
  String newMessageId = String(millis());
  messageId = newMessageId;
  Serial.println("Sending MQTT msg with ID: " + messageId);

  String mqttMsg = String("{\"from\": \"") + String(device_id) + 
                 "\", \"message\": \"" + String(msg) + 
                 "\", \"message_id\": \"" + String(messageId) + "\"}";

  client.publish(target_topic, mqttMsg.c_str());
  activateTempBuzzer();
}

void startLcdMessage(String line1, String line2) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(line1);
  if (line2.length() > 0) {
    lcd.setCursor(0, 1);
    lcd.print(line2);
  }
  lcdMessageActive = true;
  lcdMessageStartTime = millis();
}

void setup() {
  Serial.begin(115200);
  
  // Set up buzzer pin first to ensure it's off during setup
  pinMode(buzzerPin, OUTPUT);
  digitalWrite(buzzerPin, LOW);
  
  // Test the buzzer briefly to ensure it works
  digitalWrite(buzzerPin, HIGH);
  delay(300);
  digitalWrite(buzzerPin, LOW);
  Serial.println("Buzzer test complete");
  
  // Initialize buttons
  for (int i = 0; i < 4; i++) {
    pinMode(buttonPins[i], INPUT_PULLUP);
  }
   Wire.begin(D5, D6);
  // Initialize LCD
  lcd.init();
  lcd.setBacklight(1);
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Connecting WiFi...");
  
  // Connect to WiFi
  setup_wifi();
  
  // Set up MQTT
  client.setServer(mqtt_server, mqtt_port);
  client.setCallback(callback);
  
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("ESP1 Ready");
  lcd.setCursor(0, 1);
  lcd.print("B1-B3: Send Msg");
  delay(2000);
  lcd.clear();
}

void loop() {
  if (!client.connected()) {
    reconnect();
  }
  client.loop();

  // Handle temporary buzzer timeout (fixed logic)
  if (buzzerActive && (millis() - buzzerStartTime >= buzzerDuration)) {
    // Only turn off the buzzer if there's no unread message
    if (!hasUnreadMessage) {
      digitalWrite(buzzerPin, LOW);
      Serial.println("🔕 Temporary buzzer notification ended");
    }
    buzzerActive = false;
  }

  // Handle LCD display timeout
  if (lcdMessageActive && (millis() - lcdMessageStartTime >= lcdDisplayDuration)) {
    lcd.clear();
    lcdMessageActive = false;
  }

  // Check buttons
  for (int i = 0; i < 4; i++) {
    int buttonState = digitalRead(buttonPins[i]);
    if (buttonState == LOW && (millis() - lastDebounceTime[i] > debounceDelay)) {
      lastDebounceTime[i] = millis();

      if (i < 3) {
        // Send message buttons (1-3)
        String msg = "Button " + String(i + 1) + " pressed";
        sendMessageToDB(msg);
        startLcdMessage("Sent: Button " + String(i + 1), "");
      } else if (i == 3 && hasUnreadMessage) {
        // Acknowledge button (4)
        // Turn off buzzer locally
        hasUnreadMessage = false;
        digitalWrite(buzzerPin, LOW);
        Serial.println("🔕 Buzzer off, acknowledged locally");
        startLcdMessage("Acknowledged!", "");
        lcd.clear();
        
        // Send acknowledgment to the other device
        sendAcknowledgment(messageId);
        
        // For debugging, print buzzer stat`e
        Serial.println("Buzzer pin state after acknowledgment: " + String(digitalRead(buzzerPin)));
      }
    }
  }
}
