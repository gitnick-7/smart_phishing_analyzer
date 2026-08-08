const { analyzeUrl } = require('./analyzer');

console.log("=== Testing Safe URL ===");
const safeResult = analyzeUrl("https://google.com");
console.log(JSON.stringify(safeResult, null, 2));

console.log("\n=== Testing Phishing URL ===");
const phishingResult = analyzeUrl("http://login.paypal.verify-account.info/auth?token=12345");
console.log(JSON.stringify(phishingResult, null, 2));
