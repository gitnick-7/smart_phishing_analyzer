/**
 * Level 3 Cognitive Manipulation & NLP Profiler
 */

const URGENCY_TRIGGERS = [
  'immediate action required', 'account suspended within 24 hours',
  'unauthorized sign-in detected', 'verify your identity now',
  'urgent security update', 'prevent permanent lockout',
  'unusual login attempt', 'billing failure alert', 'confirm passcode'
];

const BRAND_SPOOF_TOKENS = [
  'paypal', 'google', 'apple', 'microsoft', 'chase', 'wellsfargo',
  'netflix', 'amazon', 'metamask', 'binance', 'coinbase'
];

function analyzeCognitiveManipulation(urlString, htmlContent = '') {
  const combinedText = (urlString + ' ' + htmlContent).toLowerCase();
  
  let cognitiveScore = 0;
  const urgencyPhrasesFound = [];
  const brandSpoofsFound = [];
  
  URGENCY_TRIGGERS.forEach(phrase => {
    if (combinedText.includes(phrase) || urlString.toLowerCase().includes(phrase.split(' ')[0])) {
      urgencyPhrasesFound.push(phrase);
      cognitiveScore += 25;
    }
  });

  BRAND_SPOOF_TOKENS.forEach(brand => {
    if (combinedText.includes(brand)) {
      brandSpoofsFound.push(brand);
    }
  });

  cognitiveScore = Math.min(cognitiveScore, 100);

  let manipulationRisk = 'LOW';
  if (cognitiveScore >= 50) manipulationRisk = 'HIGH';
  else if (cognitiveScore >= 25) manipulationRisk = 'MODERATE';

  return {
    cognitive_manipulation_score: cognitiveScore,
    manipulation_risk_level: manipulationRisk,
    urgency_phrases_found: urgencyPhrasesFound,
    target_brands_detected: brandSpoofsFound,
    psychological_triggers: urgencyPhrasesFound.length > 0 ? ['FEAR_OF_LOCKOUT', 'ARTIFICIAL_URGENCY'] : ['NONE']
  };
}

module.exports = {
  analyzeCognitiveManipulation
};
