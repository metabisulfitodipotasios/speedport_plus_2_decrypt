# speedport_plus_2_decrypt
speedport_plus_2_decrypt

<!DOCTYPE html>
<html lang="el">
<head>
 <meta charset="UTF-8">
 <meta name="viewport" content="width=device-width, initial-scale=1.0">

 <title>Speedport plus2 Configuration Backup Decryptor</title>

 <!-- Βιβλιοθήκη για AES, SHA-256 και MD5 -->
<script
  src="https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/crypto-js.min.js"
  onerror="this.onerror=null; this.src='crypto-js.min.js';">
</script>
 <style>
 body { font-family: Arial, sans-serif; max-width: 700px; margin: 40px auto; padding: 20px; color: #222; }
 h1 { font-size: 24px; }
 .box { border: 1px solid #ccc; border-radius: 8px; padding: 20px; background: #f8f8f8; }
 label { display: block; margin-top: 15px; margin-bottom: 5px; font-weight: bold; }
 input[type="file"], input[type="password"] { width: 100%; box-sizing: border-box; padding: 10px; font-size: 15px; }
 button { margin-top: 20px; padding: 11px 20px; font-size: 16px; cursor: pointer; }
 #message { margin-top: 20px; padding: 12px; white-space: pre-line; line-height: 1.5; }
 .success { color: #125c12; background: #e7f6e7; border: 1px solid #9ccc9c; }
 .error { color: #8b0000; background: #ffeaea; border: 1px solid #dd9999; }
 </style>
</head>

<body style="background:#888">
 <h3>Speedport Plus 2 Decryptor for<br>configurationBackup.cfg</h3>
 <div class="box"> Στο speedport plus 2 πηγαινετε να σωσετε το <br>
configurationBackup.cfg<br>
 και σας ζητα να δωσετε κι εναν κωδικο.
 <label for="backupFile"> Επιλέξτε το αποθηκευμενο configurationBackup.cfg: </label>
 <input type="file" id="backupFile" accept=".cfg">
 <label for="password"> Δωστε τον Κωδικό backup: </label>
 <input type="password" id="password" placeholder="Πληκτρολογήστε τον κωδικό" style="max-width:300px" ><br>
 <button id="decryptButton"> Αποκρυπτογράφηση </button>
 <div id="message"></div> </div>

 <script>
 const OPENSSL_MAGIC = "Salted__";
 const GZIP_MAGIC_1 = 0x1f;
 const GZIP_MAGIC_2 = 0x8b;

 const KEY_LENGTH = 32; // AES-256
 const IV_LENGTH = 16; // AES block size

 function setMessage(text, type) {
 const message = document.getElementById("message");

 message.textContent = text;
 message.className = type || "";
 }

 function bytesToWordArray(bytes) {
 const words = [];

 for (let i = 0; i < bytes.length; i++) {
 words[i >>> 2] =
 (words[i >>> 2] || 0) |
 (bytes[i] << (24 - (i % 4) * 8));
 }

 return CryptoJS.lib.WordArray.create(words, bytes.length);
 }

 function wordArrayToBytes(wordArray) {
 const words = wordArray.words;
 const bytes = new Uint8Array(wordArray.sigBytes);

 for (let i = 0; i < wordArray.sigBytes; i++) {
 bytes[i] =
 (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
 }

 return bytes;
 }

 function startsWithBytes(data, prefix) {
 if (data.length < prefix.length) {
 return false;
 }

 for (let i = 0; i < prefix.length; i++) {
 if (data[i] !== prefix[i]) {
 return false;
 }
 }

 return true;
 }


 function evpBytesToKey(password, salt, hashName) {
 let output = CryptoJS.lib.WordArray.create();
 let previous = CryptoJS.lib.WordArray.create();

 while (output.sigBytes < KEY_LENGTH + IV_LENGTH) {
 const input = previous
 .concat(password)
 .concat(salt);

 if (hashName === "sha256") {
 previous = CryptoJS.SHA256(input);
 } else if (hashName === "md5") {
 previous = CryptoJS.MD5(input);
 } else {
 throw new Error("Άγνωστος αλγόριθμος hash.");
 }

 output = output.concat(previous);
 }

 const key = CryptoJS.lib.WordArray.create(
 output.words.slice(0, KEY_LENGTH / 4),
 KEY_LENGTH
 );

 const iv = CryptoJS.lib.WordArray.create(
 output.words.slice(
 KEY_LENGTH / 4,
 (KEY_LENGTH + IV_LENGTH) / 4
 ),
 IV_LENGTH
 );

 return {
 key: key,
 iv: iv
 };
 }

 function decryptBackup(encryptedBytes, passwordText) {
 const magicBytes = new TextEncoder().encode(OPENSSL_MAGIC);

 const gzipMagic = new Uint8Array([
 GZIP_MAGIC_1,
 GZIP_MAGIC_2
 ]);

 if (!startsWithBytes(encryptedBytes, magicBytes)) {
 throw new Error(
 "Το αρχείο δεν είναι έγκυρο OpenSSL Salted__ αρχείο."
 );
 }

 if (encryptedBytes.length < 32) {
 throw new Error(
 "Το αρχείο είναι πολύ μικρό ή κατεστραμμένο."
 );
 }

 const saltBytes = encryptedBytes.slice(8, 16);
 const bodyBytes = encryptedBytes.slice(16);

 const salt = bytesToWordArray(saltBytes);
 const body = bytesToWordArray(bodyBytes);

 const password = CryptoJS.enc.Utf8.parse(passwordText);

 for (const hashName of ["sha256", "md5"]) {
 try {
 const result = evpBytesToKey(
 password,
 salt,
 hashName
 );

 const decrypted = CryptoJS.AES.decrypt(
 {
 ciphertext: body
 },
 result.key,
 {
 iv: result.iv,
 mode: CryptoJS.mode.CBC,
 padding: CryptoJS.pad.Pkcs7
 }
 );

 const plaintext = wordArrayToBytes(decrypted);

 if (startsWithBytes(plaintext, gzipMagic)) {
 return {
 data: plaintext,
 hashName: hashName
 };
 }
 } catch (error) {
 // Συνεχίζει με τον επόμενο KDF.
 }
 }

 throw new Error(
 "Η αποκρυπτογράφηση απέτυχε. " +
 "Ελέγξτε το αρχείο και τον κωδικό."
 );
 }

 function downloadFile(data, filename) {
 const blob = new Blob(
 [data],
 {
 type: "application/gzip"
 }
 );

 const url = URL.createObjectURL(blob);
 const link = document.createElement("a");

 link.href = url;
 link.download = filename;

 document.body.appendChild(link);
 link.click();
 document.body.removeChild(link);

 setTimeout(() => {
 URL.revokeObjectURL(url);
 }, 1000);
 }

 document
 .getElementById("decryptButton")
 .addEventListener("click", async function() {
 try {
 const fileInput = document.getElementById("backupFile");
 const passwordInput = document.getElementById("password");

 if (!fileInput.files || fileInput.files.length === 0) {
 throw new Error(
 "Επιλέξτε πρώτα το configurationBackup.cfg."
 );
 }

 if (!passwordInput.value) {
 throw new Error(
 "Πληκτρολογήστε τον κωδικό του backup."
 );
 }

 setMessage(
 "Γίνεται αποκρυπτογράφηση...",
 ""
 );

 const inputFile = fileInput.files[0];
 const arrayBuffer = await inputFile.arrayBuffer();
 const encryptedBytes = new Uint8Array(arrayBuffer);

 const result = decryptBackup(
 encryptedBytes,
 passwordInput.value
 );

 downloadFile(
 result.data,
 "configurationBackup.tar.gz"
 );

 setMessage(
 "Η αποκρυπτογράφηση ολοκληρώθηκε.\n\n" +
 "Δημιουργήθηκε το αρχείο:\n" +
 "configurationBackup.tar.gz\n\n" +
 "Αποσυμπιέστε το .gz με το WinRAR και " +
 "δείτε μέσα στον φάκελο:\n" +
 "VD4224BDT_Config\n\n" +
"Εκεί θα βρείτε στο αρχείο syscfg.db κ.λπ.\n\nΑΝΑΖΗΤΕΙΣΤΕ ΤΑ ΕΞΗΣ:\n\n" +
"wan_proto_username=.....@otenet.gr\n\n" + 
"wan_proto_password=.....\n\n" + 
"ntp_server1=ntp2.otenet.gr\n\n" +
"ntp_server2=time.otenet.gr\n\n" + 
"VoiceService.1.SIP.Client.1.AuthUserName=+30.....@ims.otenet.gr\n\n" + 
"VoiceService.1.SIP.Client.1.AuthPassword=.............\n\n" +
"VoiceService.1.SIP.Client.1.RegisterURI=+30.....\n\n" +
"VoiceService.1.VoIPProfile.1.X_RDK-Central_COM_EmergencyDigitMap=100|112|166|197|199|1056|116000|13818|11112|11188|1305|13888|13820|116111\n\n" +
"VoiceService.1.Interwork.1.Map.1.DigitMap=[134]xxx.T|5xxxxxxxxx.T|7xxxxxxxxx.T|807xxxx|00xxxxxxxx.T|xx.#|[268]xxxxxxxxx|9xxxxxxxxx.T|*xx#|#xx#|*xx*xxxxxxxxxx.#|#xx*x.#|*xx*xxxx#|*31*xxxxxxxxxx.T|*xxxxxxxx|xx*x.T|*xx*xxxx*x.#|*xx*x.*x.#|*031*xxxx*xxxx*xxxx#|**xx#|*#xx.#|*521*xxxxxxxxxx#|#521*xxxx*xxxxxxxxxx#\n\n" +
"Εμεις θελουμε να κοβει τους αριθμους υψηλης χρεωσης και το εξωτερικο 00\n\n" +
"Γι αυτο θα κρατησουμε μονο το εξης:\n" +
"2xxxxxxxxx|69xxxxxxxx|800xxxxxxx|801xxxxxxx|100|112|166|197|199|1056|11112|11188|116000|116111|11888|1252|1305|13700|13738|13788|13800|13818|13820|13830|13840|13888|*xx#|#xx#|*xx*xxxxxxxxxx.#|#xx*x.#|*xx*xxxx#|*31*xxxxxxxxxx.T|*xxxxxxxx|xx*x.T|*xx*xxxx*x.#|*xx*x.*x.#|*031*xxxx*xxxx*xxxx#|**xx#|*#xx.#|*521*xxxxxxxxxx#|#521*xxxx*xxxxxxxxxx#\n\n"+
 "KDF που χρησιμοποιήθηκε: " +
 result.hashName,
 "success"
 );
 } catch (error) {
 setMessage(
 "Σφάλμα:\n" + error.message,
 "error"
 );
 }
 });
 </script>
</body>
</html>
