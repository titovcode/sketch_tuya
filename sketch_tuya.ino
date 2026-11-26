// =================== github.com/titovcode ===================
// ============================================================


#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <UniversalTelegramBot.h>
#include <ArduinoJson.h>
#include <time.h>
#include <mbedtls/md.h>

// =================== ПОДКЛЮЧЕНИЕ ===================
const char* ssid = "";
const char* password = "";

#define BOT_TOKEN ""

// ID пользователей
const String ALLOWED_ID_1 = "";
const String ALLOWED_ID_2 = "";

const String TUYA_CLIENT_ID  = "";
const String TUYA_SECRET     = "";
const char* TUYA_HOST        = "openapi.tuyaeu.com";

// ПИН ДИНАМИКА
const int BUZZER_PIN = 23; 

struct Device {
  String name;
  String id;
};

Device myDevices[] = {
  {"- 🔆 управление светом на улице", ""}
};
const int myDevicesCount = sizeof(myDevices) / sizeof(myDevices[0]);

WiFiClientSecure secured_client;
UniversalTelegramBot bot(BOT_TOKEN, secured_client);

unsigned long lastTimeBotRan = 0;
String tuya_token = "";
unsigned long tokenExpireTime = 0;
String activeDeviceId = "";

// === ПЕРЕМЕННЫЕ ДЛЯ ТАЙМЕРА ===
bool isTimerRunning = false;
unsigned long timerStartTime = 0;
unsigned long timerDuration = 0;
String timerDeviceId = ""; 
// =============================

const String EMPTY_HASH = "";

// =================== ЗВУКОВЫЕ ФУНКЦИИ ===================
void beepStart() {
  tone(BUZZER_PIN, 523, 100); delay(100);
  tone(BUZZER_PIN, 659, 100); delay(100);
  tone(BUZZER_PIN, 784, 200); delay(200);
  noTone(BUZZER_PIN);
}
void beepOn() {
  tone(BUZZER_PIN, 1000, 150); delay(150); noTone(BUZZER_PIN);
}
void beepOff() {
  tone(BUZZER_PIN, 400, 150); delay(150); noTone(BUZZER_PIN);
}

unsigned long long getTimestampMs() {
  return (unsigned long long)time(nullptr) * 1000ULL;
}

String sha256(const String& data) {
  byte hash[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char*)data.c_str(), data.length());
  mbedtls_md_finish(&ctx, hash);
  mbedtls_md_free(&ctx);
  char buf[65] = {0};
  for (int i=0; i<32; i++) sprintf(buf + i*2, "%02x", hash[i]);
  return String(buf);
}

String hmacSHA256(const String& key, const String& msg) {
  byte hash[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_setup(&ctx, info, 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)key.c_str(), key.length());
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)msg.c_str(), msg.length());
  mbedtls_md_hmac_finish(&ctx, hash);
  mbedtls_md_free(&ctx);
  char buf[65] = {0};
  for (int i=0; i<32; i++) sprintf(buf + i*2, "%02X", hash[i]);
  return String(buf);
}

String createMessageToSign(const String& method, const String& path, const String& bodyHash, const String& t, const String& accessId, const String& accessToken) {
  String s = method + "\n" + bodyHash + "\n\n" + path;
  if (accessToken == "") return accessId + t + s;
  else return accessId + accessToken + t + s;
}

String getTuyaToken() {
  if (millis() < tokenExpireTime && tuya_token != "") return tuya_token;
  String t = String(getTimestampMs());
  String path = "/v1.0/token?grant_type=1";
  String signMessage = createMessageToSign("GET", path, EMPTY_HASH, t, TUYA_CLIENT_ID, "");
  String sign = hmacSHA256(TUYA_SECRET, signMessage);

  WiFiClientSecure client;
  client.setInsecure();
  if (!client.connect(TUYA_HOST, 443)) {
    Serial.println("[Tuya] Ошибка подключения к серверу для получения токена");
    return "";
  }
  
  String req = String("GET ") + path + " HTTP/1.1\r\n" +
               "Host: " + TUYA_HOST + "\r\n" +
               "client_id: " + TUYA_CLIENT_ID + "\r\n" +
               "sign: " + sign + "\r\n" +
               "t: " + t + "\r\n" +
               "sign_method: HMAC-SHA256\r\n" +
               "Connection: close\r\n\r\n";
  client.print(req);
  String resp = client.readString();
  client.stop();

  int jsonPos = resp.indexOf("{");
  if (jsonPos == -1) return "";
  StaticJsonDocument<1024> doc;
  if (deserializeJson(doc, resp.substring(jsonPos))) return "";
  if (!doc["success"].as<bool>()) {
    Serial.printf("[Tuya Token Error]: %s\n", resp.c_str());
    return "";
  }

  tuya_token = doc["result"]["access_token"].as<String>();
  int expire = doc["result"]["expire_time"].as<int>();
  tokenExpireTime = millis() + (expire - 60) * 1000UL;
  return tuya_token;
}

bool tuyaSendCommand(bool state) {
  if (activeDeviceId == "") return false;

  String token = getTuyaToken();
  if (token == "") {
    Serial.println("[Tuya] Токен пустой, команда отменена.");
    return false;
  }
  
  String t = String(getTimestampMs());
  String path = "/v1.0/iot-03/devices/" + activeDeviceId + "/commands";

  StaticJsonDocument<256> doc;
  JsonArray arr = doc.createNestedArray("commands");
  JsonObject obj = arr.createNestedObject();
  obj["code"] = "switch_1";
  obj["value"] = state;

  String body;
  serializeJson(doc, body);
  String bodyHash = sha256(body);
  String signMessage = createMessageToSign("POST", path, bodyHash, t, TUYA_CLIENT_ID, token);
  String sign = hmacSHA256(TUYA_SECRET, signMessage);

  WiFiClientSecure client;
  client.setInsecure();
  if (!client.connect(TUYA_HOST, 443)) {
    Serial.println("[Tuya] Ошибка 443 при отправке команды");
    return false;
  }
  
  String req = String("POST ") + path + " HTTP/1.1\r\n" +
               "Host: " + TUYA_HOST + "\r\n" +
               "client_id: " + TUYA_CLIENT_ID + "\r\n" +
               "access_token: " + token + "\r\n" +
               "sign: " + sign + "\r\n" +
               "t: " + t + "\r\n" +
               "sign_method: HMAC-SHA256\r\n" +
               "Content-Type: application/json\r\n" +
               "Content-Length: " + String(body.length()) + "\r\n" +
               "Connection: close\r\n\r\n" + body;
               
  client.print(req);
  String resp = client.readString();
  client.stop();

  Serial.println("\n[Tuya Command Response]:");
  Serial.println(resp);

  return resp.indexOf("\"success\":true") != -1;
}

void startTimer(String chat_id, int minutes) {
  if (minutes <= 0) {
    bot.sendMessage(chat_id, "⚠ Время должно быть больше 0.");
    return;
  }
  
  if (activeDeviceId == "") activeDeviceId = myDevices[0].id;

  if (tuyaSendCommand(true)) {
    beepOn();
    isTimerRunning = true;
    timerDuration = minutes * 60 * 1000UL;
    timerStartTime = millis();
    timerDeviceId = activeDeviceId;
    
    bot.sendMessage(chat_id, "⏳ Таймер запущен на " + String(minutes) + " мин.\nУстройство выключится автоматически.");
  } else {
    bot.sendMessage(chat_id, "❌ Ошибка включения (API Tuya). Таймер не запущен.");
  }
}

void handleNewMessages(int numNewMessages) {
  for (int i = 0; i < numNewMessages; i++) {
    String chat_id = bot.messages[i].chat_id;
    String text = bot.messages[i].text;

    Serial.println("Сообщение: " + text);

    if (chat_id != ALLOWED_ID_1 && chat_id != ALLOWED_ID_2) {
      bot.sendMessage(chat_id, "⛔ Доступ запрещен!");
      continue; 
    }

    if (text == "/start") {
      String msg = "👋 *Список доступных устройств:*\n";
      for (int i = 0; i < myDevicesCount; i++) {
        msg += "/device" + String(i+1) + " " + myDevices[i].name + "\n";
      }
      bot.sendMessage(chat_id, msg, "Markdown");
    }
    
    else if (text == "/ping" || text == "/status") {
      String statusMsg = "📊 *Диагностика системы:*\n";
      statusMsg += "📶 Wi-Fi: " + String(WiFi.RSSI()) + " dBm\n";
      
      String token = getTuyaToken();
      if (token != "") {
        statusMsg += "✅ Tuya API: подключено\n";
      } else {
        statusMsg += "❌ Tuya API: ошибка токена\n";
      }

      time_t now = time(nullptr);
      statusMsg += "🕒 Время UTC: " + String(ctime(&now));
      bot.sendMessage(chat_id, statusMsg, "Markdown");
    }

    else if (text.startsWith("/device")) {
      int idx = text.substring(7).toInt() - 1;
      if (idx >= 0 && idx < myDevicesCount) {
        activeDeviceId = myDevices[idx].id;
        String devName = myDevices[idx].name;
        
        String msg = "Выбрано: " + devName + "\n\n";
        msg += "/on" + String(idx+1) + " - включить\n";
        msg += "/off" + String(idx+1) + " - выключить\n\n";
        msg += "🕚 Установить таймер:\n\n";
        msg += "/time - остаток времени\n";
        msg += "/time5 - на 5 мин\n";
        msg += "/time10 - на 10 мин\n";
        msg += "/time15 - на 15 мин\n";
        msg += "/timeset - установить значение (напр. /timeset 30)\n";
        msg += "/timereset - сброс таймера\n\n";
        msg += "Выбрать другое устройство - /start";
        
        bot.sendMessage(chat_id, msg);
      } else {
        bot.sendMessage(chat_id, "Устройство не найдено.");
      }
    }
    
    else if (text.startsWith("/on") || text.startsWith("/off")) {
      bool turnOn = text.startsWith("/on");
      int idx = turnOn ? text.substring(3).toInt() - 1 : text.substring(4).toInt() - 1;
      
      if (idx >= 0 && idx < myDevicesCount) {
        activeDeviceId = myDevices[idx].id;
        
        if (!turnOn) isTimerRunning = false; 
        
        bool success = tuyaSendCommand(turnOn);
        if (success) {
          if (turnOn) beepOn(); else beepOff();
        }
        bot.sendMessage(chat_id, success ? (turnOn ? "✅ Включено" : "❌ Выключено") : "Ошибка API");
      }
    }
    
    else if (text == "/time5")  startTimer(chat_id, 5);
    else if (text == "/time10") startTimer(chat_id, 10);
    else if (text == "/time15") startTimer(chat_id, 15);
    
    else if (text.startsWith("/timeset")) {
      String arg = text.substring(8);
      arg.trim();
      int minutes = arg.toInt();
      
      if (minutes > 0) {
        startTimer(chat_id, minutes);
      } else {
        bot.sendMessage(chat_id, "⚠ Используйте формат: /timeset 30 (где 30 - минуты)");
      }
    }

    else if (text == "/time") {
      if (isTimerRunning) {
        unsigned long passed = millis() - timerStartTime;
        if (passed < timerDuration) {
          unsigned long remainingMs = timerDuration - passed;
          int remainingMin = (remainingMs / 1000) / 60;
          int remainingSec = (remainingMs / 1000) % 60;
          bot.sendMessage(chat_id, "⏳ Осталось: " + String(remainingMin) + " мин " + String(remainingSec) + " сек");
        } else {
           bot.sendMessage(chat_id, "Таймер истекает...");
        }
      } else {
        bot.sendMessage(chat_id, "⛔ Таймер не запущен.");
      }
    }
    
    else if (text == "/timereset") {
      if (isTimerRunning) {
        isTimerRunning = false;
        String deviceToTurnOff = timerDeviceId;
        if (deviceToTurnOff == "") deviceToTurnOff = activeDeviceId;

        String originalActiveDeviceId = activeDeviceId; 
        activeDeviceId = deviceToTurnOff; 

        if (tuyaSendCommand(false)) {
          beepOff();
          bot.sendMessage(chat_id, "⏹ Таймер остановлен. Устройство выключено.");
        } else {
          bot.sendMessage(chat_id, "⏹ Таймер остановлен, но ошибка выключения (API).");
        }
        activeDeviceId = originalActiveDeviceId;
      } else {
        bot.sendMessage(chat_id, "Таймер и так не был запущен.");
      }
    }

    if (bot.last_message_received < bot.messages[i].message_id) {
      bot.last_message_received = bot.messages[i].message_id;
    }
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);

  delay(1000);
  Serial.println("\nЗапуск системы...");

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWi-Fi подключен!");
  
  beepStart();
  activeDeviceId = myDevices[0].id;

  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  setenv("TZ", "UTC0", 1);
  tzset();

  Serial.print("Синхронизация времени");
  time_t now = time(nullptr);
  int retry = 0;
  while (now < 100000 && retry < 20) {
    delay(500);
    Serial.print(".");
    now = time(nullptr);
    retry++;
  }
  
  struct tm timeinfo;
  gmtime_r(&now, &timeinfo);
  Serial.printf("\nТекущее время UTC: %s", asctime(&timeinfo));
  
  secured_client.setInsecure();

  // Тестовая проверка токена при старте
  String testToken = getTuyaToken();
  if (testToken != "") {
    Serial.println("✅ Tuya API авторизован успешно!");
  } else {
    Serial.println("❌ Ошибка получения токена Tuya при старте!");
  }

  // Очистка очереди сообщений
  int num = bot.getUpdates(bot.last_message_received + 1);
  while(num) {
    bot.last_message_received = bot.messages[num - 1].message_id;
    num = bot.getUpdates(bot.last_message_received + 1);
  }

  String startMsg = "⚡ Бот запущен! Сигнал: " + String(WiFi.RSSI()) + " dBm, IP: " + WiFi.localIP().toString();
  bot.sendMessage(ALLOWED_ID_1, startMsg);
}

void loop() {
  if (isTimerRunning) {
    if (millis() - timerStartTime >= timerDuration) {
      String originalActiveDeviceId = activeDeviceId;
      activeDeviceId = timerDeviceId; 

      if (tuyaSendCommand(false)) {
        beepOff();
        bot.sendMessage(ALLOWED_ID_1, "⏰ Время вышло! Устройство выключено.");
      } else {
        bot.sendMessage(ALLOWED_ID_1, "⚠ Время вышло, но ошибка выключения (API)!");
      }
      isTimerRunning = false;
      activeDeviceId = originalActiveDeviceId;
    }
  }

  if (millis() - lastTimeBotRan > 300) {
    int numNewMessages = bot.getUpdates(bot.last_message_received + 1);
    if (numNewMessages) {
      handleNewMessages(numNewMessages);
    }
    lastTimeBotRan = millis();
  }
}
