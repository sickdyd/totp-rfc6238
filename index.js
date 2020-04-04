const crypto = require("crypto");

// TOTP and HOTP use the same algorithm, the only difference
// is that the "count" param in TOTPs is time based
function generateTOTP(algorithm, secret, count, digits) {

  // Convert the string to binary data in the form of a sequence of bytes
  secret = Buffer.from(secret);

  // Writes value to buf at the specified offset with the specified endianness
  let countBuffer = Buffer.alloc(8, 0);
  countBuffer.writeUInt32BE(count, 4);

  // Creates and returns an Hmac object that uses the given algorithm and key
  const hmac_result = crypto.createHmac(algorithm, secret)
    .update(countBuffer)
    .digest("hex");

  // Chose the last byte of the hmac to do the dynamic truncation
  const offset = parseInt(hmac_result.charAt(hmac_result.length - 1), 16);

  // Dynamic truncation
  let totp = parseInt(hmac_result.substr(offset * 2, 2 * 4), 16);
  totp = totp & 0x7fffffff;
  // Get only the digits needed
  totp = totp % (10 ** digits);
  // If there are not enough digits pad with 0
  totp = totp.toString().padStart(digits, "0");

  return totp;
}

// Date is a string. From where should calculate the unix epoch time in steps of 30 seconds
function getCount(date = new Date().toString()) {
  const epoch = Math.round(new Date(date).getTime() / 1000.0);
  return Math.floor(epoch / 30);
}

// The code will generate TOTPs for sha1, sha256 and sha512

// Copied from: https://www.rfc-editor.org/rfc/rfc6238.txt
// PAGE 15

// +-------------+--------------+------------------+----------+--------+
// |  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
// +-------------+--------------+------------------+----------+--------+
// |      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
// |             |   00:00:59   |                  |          |        |
// |      59     |  1970-01-01  | 0000000000000001 | 46119246 | SHA256 |
// |             |   00:00:59   |                  |          |        |
// |      59     |  1970-01-01  | 0000000000000001 | 90693936 | SHA512 |
// |             |   00:00:59   |                  |          |        |
// |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
// |             |   01:58:29   |                  |          |        |
// |  1111111109 |  2005-03-18  | 00000000023523EC | 68084774 | SHA256 |
// |             |   01:58:29   |                  |          |        |
// |  1111111109 |  2005-03-18  | 00000000023523EC | 25091201 | SHA512 |
// |             |   01:58:29   |                  |          |        |
// |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
// |             |   01:58:31   |                  |          |        |
// |  1111111111 |  2005-03-18  | 00000000023523ED | 67062674 | SHA256 |
// |             |   01:58:31   |                  |          |        |
// |  1111111111 |  2005-03-18  | 00000000023523ED | 99943326 | SHA512 |
// |             |   01:58:31   |                  |          |        |
// |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
// |             |   23:31:30   |                  |          |        |
// |  1234567890 |  2009-02-13  | 000000000273EF07 | 91819424 | SHA256 |
// |             |   23:31:30   |                  |          |        |
// |  1234567890 |  2009-02-13  | 000000000273EF07 | 93441116 | SHA512 |
// |             |   23:31:30   |                  |          |        |
// |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
// |             |   03:33:20   |                  |          |        |
// |  2000000000 |  2033-05-18  | 0000000003F940AA | 90698825 | SHA256 |
// |             |   03:33:20   |                  |          |        |
// |  2000000000 |  2033-05-18  | 0000000003F940AA | 38618901 | SHA512 |
// |             |   03:33:20   |                  |          |        |
// | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
// |             |   11:33:20   |                  |          |        |
// | 20000000000 |  2603-10-11  | 0000000027BC86AA | 77737706 | SHA256 |
// |             |   11:33:20   |                  |          |        |
// | 20000000000 |  2603-10-11  | 0000000027BC86AA | 47863826 | SHA512 |
// |             |   11:33:20   |                  |          |        |
// +-------------+--------------+------------------+----------+--------+

// Use getCount() with no params to get the counter for the unix epoch time
// in steps of 30 seconds

// Test with the first date
let time = getCount("1970-01-01 00:00:59 UTC");

let secret = "12345678901234567890";
let totp = generateTOTP("sha1", secret, time, 8);
console.log("sha1  ", totp, "should be 94287082");

// To create a TOTP password with sha256 and sha512 the secret length must
// be 32 for sha256 and 64 for sha512.
// Look up the errata of 6238 for more (https://www.rfc-editor.org/errata/eid5132)

secret = "12345678901234567890";
// Extend the length of the secret by repeating it until 32 chars
secret = secret + secret;
secret = secret.substr(0, 32);
totp = generateTOTP("sha256", secret, time, 8)
console.log("sha256", totp, "should be 46119246");

secret = "12345678901234567890";
// Extend the length of the secret by repeating it until 64 chars
secret = secret + secret + secret + secret;
secret = secret.substr(0, 64);
totp = generateTOTP("sha512", secret, time, 8)
console.log("sha512", totp, "should be 90693936");

// Testing with second date
time = getCount("2005-03-18 01:58:29 UTC");

secret = "12345678901234567890";
totp = generateTOTP("sha1", secret, time, 8);
console.log("sha1  ", totp, "should be 07081804");

secret = "12345678901234567890";
secret = secret + secret;
secret = secret.substr(0, 32);
totp = generateTOTP("sha256", secret, time, 8)
console.log("sha256", totp, "should be 68084774");

secret = "12345678901234567890";
secret = secret + secret + secret + secret;
secret = secret.substr(0, 64);
totp = generateTOTP("sha512", secret, time, 8)
console.log("sha512", totp, "should be 25091201");