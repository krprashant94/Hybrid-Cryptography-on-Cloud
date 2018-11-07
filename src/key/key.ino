#include <rBase64.h>
/*----------Save to memory---------*/
String des = "12345678123456781234567812345678";
String aes = "700102030405060708090a0b0c0d0e0f";
String rsa = "18285:57067";
String shift = "3";

void setup() {
  // put your setup code here, to run once:
  Serial.begin(9600);
}


void loop() {
  // put your main code here, to run repeatedly:
  rbase64.encode("['"+des +"', '"+ aes +"', '"+ rsa +"', '"+ shift +"']");
  Serial.println(rbase64.result());
  delay(500);
}
