import crypto from 'node:crypto';
import {
  VerdictEnum,
  SocialEngineeringTacticEnum,
  FindingSeverityEnum,
  type Verdict,
  type FindingSeverity,
  type MessageChannel,
  type ISocialEngineeringFinding,
  type IExtractedIndicators,
  type IThreatIntelMatch,
  type IAIExplanation,
  type IMessageAnalysis,
} from '@sentrix/shared';
import { ScanModel } from '../models/Scan.js';
import { MessageAnalysisModel } from '../models/MessageAnalysis.js';
import { ThreatIndicatorModel } from '../models/ThreatIndicator.js';

interface ExtractResult {
  indicators: IExtractedIndicators;
  findings: ISocialEngineeringFinding[];
  threatIntelMatches: IThreatIntelMatch[];
  riskScore: number;
  confidence: number;
  classification: Verdict;
  preview: string;
}

// Common impersonated brands and entities
const RECOGNIZED_ENTITIES: Record<string, string[]> = {
  'Banking & Payments': [
    'chase', 'wells fargo', 'bank of america', 'citi', 'citibank', 'sbi', 'state bank of india',
    'hdfc', 'icici', 'axis bank', 'barclays', 'hsbc', 'paypal', 'venmo', 'zelle', 'cashapp', 'stripe'
  ],
  'Tech & Cloud Ecosystem': [
    'apple', 'icloud', 'microsoft', 'office 365', 'google', 'gmail', 'amazon', 'netflix',
    'meta', 'facebook', 'instagram', 'whatsapp', 'telegram', 'dropbox', 'linkedin'
  ],
  'Logistics & Couriers': [
    'fedex', 'ups', 'dhl', 'usps', 'postal service', 'royal mail', 'india post', 'aramex'
  ],
  'Government & Tax Authorities': [
    'irs', 'internal revenue service', 'income tax', 'social security', 'ssa', 'customs',
    'border protection', 'police', 'interpol', 'fbi', 'gov.in', 'hmrc'
  ],
  'Web3 & Crypto Platforms': [
    'binance', 'coinbase', 'metamask', 'trust wallet', 'ledger', 'trezor', 'kraken',
    'kucoin', 'opensea', 'phantom', 'solana', 'ethereum', 'bitcoin'
  ],
};

export class MessageAnalyzerService {
  /**
   * Main entry point: extracts indicators, audits social engineering tactics,
   * checks historical threat intelligence, and produces explainable score.
   */
  public async analyze(
    messageText: string,
    channel: MessageChannel = 'OTHER',
    senderInfo?: string,
    userIp?: string
  ): Promise<IMessageAnalysis> {
    const trimmed = messageText.trim();
    const messageHash = crypto.createHash('sha256').update(trimmed).digest('hex');

    // 1. Run deterministic extractor & heuristic engine
    const analysis = await this.extractAndScore(trimmed, channel, senderInfo);

    // 2. Build grounded AI/heuristic explanation
    const aiExplanation = this.generateGroundedExplanation(trimmed, analysis);

    // 3. User IP privacy hash
    const userIpHash = userIp
      ? crypto.createHash('sha256').update(userIp).digest('hex')
      : undefined;

    // 4. Save to MongoDB
    const record = await MessageAnalysisModel.create({
      messageHash,
      channel,
      senderInfo,
      preview: analysis.preview,
      messageText: trimmed,
      classification: analysis.classification,
      riskScore: analysis.riskScore,
      confidence: analysis.confidence,
      detectedPatterns: analysis.findings,
      extractedIndicators: analysis.indicators,
      threatIntelMatches: analysis.threatIntelMatches,
      aiExplanation,
      userIpHash,
    });

    // 5. Index extracted atomic indicators for correlation
    await this.indexIndicators(record._id, analysis.indicators, analysis.classification);

    return {
      _id: record._id.toString(),
      messageHash,
      channel,
      senderInfo,
      preview: analysis.preview,
      classification: analysis.classification,
      riskScore: analysis.riskScore,
      confidence: analysis.confidence,
      detectedPatterns: analysis.findings,
      extractedIndicators: analysis.indicators,
      threatIntelMatches: analysis.threatIntelMatches,
      aiExplanation,
      createdAt: record.createdAt.toISOString(),
    };
  }

  private async extractAndScore(
    text: string,
    channel: MessageChannel,
    senderInfo?: string
  ): Promise<ExtractResult> {
    const preview = text.slice(0, 140).replace(/\s+/g, ' ').trim() + (text.length > 140 ? '...' : '');
    const findings: ISocialEngineeringFinding[] = [];
    const threatIntelMatches: IThreatIntelMatch[] = [];

    // --- Indicator Extraction ---
    // URLs (including de-fanged and plain)
    const urlMatches = text.match(/(?:https?|hxxps?):\/\/[^\s<>"'{}|\\^`]+|[a-zA-Z0-9-]+\.(?:com|org|net|xyz|top|biz|info|cc|club|live|site|link|me|app)(?:\/[^\s<>"']*)?/gi) || [];
    const rawUrls = Array.from(new Set(urlMatches)).map((u) => u.replace(/^hxxps?:\/\//i, 'https://'));
    const domains: string[] = [];
    for (const u of rawUrls) {
      try {
        const fullUrl = u.startsWith('http') ? u : `https://${u}`;
        const parsed = new URL(fullUrl);
        if (parsed.hostname && parsed.hostname.includes('.')) {
          domains.push(parsed.hostname.toLowerCase());
        }
      } catch {
        // Ignore malformed URL
      }
    }
    const uniqueDomains = Array.from(new Set(domains));

    // Emails
    const emailMatches = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi) || [];
    const emails = Array.from(new Set(emailMatches.map((e) => e.toLowerCase())));

    // Phone numbers (International and national patterns, WhatsApp links)
    const phoneMatches = text.match(/(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\+\d{10,14}/g) || [];
    const waMatches = text.match(/wa\.me\/(\d+)/gi) || [];
    const rawPhones = [...phoneMatches, ...waMatches.map((w) => w.replace(/wa\.me\//i, '+'))];
    const phones = Array.from(new Set(rawPhones.map((p) => p.replace(/\s+/g, ''))));

    // Crypto Wallets (BTC, ETH, SOL)
    const wallets: Array<{ address: string; network: string }> = [];
    const ethMatches = text.match(/\b0x[a-fA-F0-9]{40}\b/g) || [];
    ethMatches.forEach((addr) => wallets.push({ address: addr, network: 'Ethereum' }));
    const btcMatches = text.match(/\b(bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g) || [];
    btcMatches.forEach((addr) => wallets.push({ address: addr, network: 'Bitcoin' }));
    const solMatches = text.match(/\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g) || [];
    // Only accept solana if context mentions crypto or sol
    if (/(?:sol|solana|phantom|crypto|airdrop|wallet)/i.test(text)) {
      solMatches.slice(0, 3).forEach((addr) => {
        if (!wallets.some((w) => w.address === addr)) {
          wallets.push({ address: addr, network: 'Solana' });
        }
      });
    }

    // Payment References (UPI, CashApp, Invoices, Routing)
    const paymentRefs: string[] = [];
    const upiMatches = text.match(/\b[a-zA-Z0-9._-]+@(ok[a-zA-Z]+|paytm|ybl|upi|axisbank|sbi|icici|hdfcbank)\b/gi) || [];
    paymentRefs.push(...upiMatches.map((u) => u.toLowerCase()));
    const cashAppMatches = text.match(/\$[a-zA-Z0-9_-]{2,30}\b/g) || [];
    paymentRefs.push(...cashAppMatches);
    const invoiceMatches = text.match(/(?:invoice|receipt|order|txn|ref)\s*#?\s*[:\-]?\s*([A-Za-z0-9\-]{5,20})/gi) || [];
    paymentRefs.push(...invoiceMatches);
    const uniquePaymentRefs = Array.from(new Set(paymentRefs));

    // Entity Impersonation Detection
    const detectedEntities: string[] = [];
    const lowerText = text.toLowerCase();
    for (const [category, names] of Object.entries(RECOGNIZED_ENTITIES)) {
      for (const name of names) {
        const regex = new RegExp(`\\b${name.replace(/\s+/g, '\\s+')}\\b`, 'i');
        if (regex.test(lowerText) || (senderInfo && regex.test(senderInfo.toLowerCase()))) {
          detectedEntities.push(`${name} (${category})`);
        }
      }
    }
    const uniqueEntities = Array.from(new Set(detectedEntities));

    const indicators: IExtractedIndicators = {
      urls: rawUrls,
      domains: uniqueDomains,
      emails,
      phones,
      wallets,
      paymentRefs: uniquePaymentRefs,
      entities: uniqueEntities,
    };

    // --- Social Engineering Audit & Scoring ---
    let rawScore = 0;

    // 1. Urgency & Fear Tactics
    const urgencyPatterns = [
      /\b(?:immediately|urgently|within\s+(?:24|12|48|2)\s*hours?|urgent\s+action)\b/i,
      /\b(?:account\s+(?:suspended|blocked|terminated|disabled|locked))\b/i,
      /\b(?:legal\s+action|arrest\s+warrant|police\s+case|court\s+summons|lawsuit)\b/i,
      /\b(?:final\s+notice|last\s+warning|service\s+cutoff|disconnected)\b/i,
      /\b(?:unauthorized\s+(?:transaction|login|device|activity|access))\b/i,
    ];
    const matchedUrgency = urgencyPatterns
      .filter((re) => re.test(text))
      .map((re) => text.match(re)?.[0] || '');

    if (matchedUrgency.length > 0) {
      const sev: FindingSeverity = matchedUrgency.length >= 2 ? 'HIGH' : 'MEDIUM';
      const weight = sev === 'HIGH' ? 25 : 12;
      rawScore += weight;
      findings.push({
        tactic: SocialEngineeringTacticEnum.URGENCY_FEAR,
        severity: sev,
        title: 'Psychological Urgency & Fear-Inducing Language',
        description:
          'Message employs strict deadlines, threats of account suspension, or legal repercussions to provoke rushed action without verification.',
        matchedPatterns: matchedUrgency,
      });
    }

    // 2. Credential & OTP Harvesting Requests
    const credentialPatterns = [
      /\b(?:otp|one[- ]time\s+password|verification\s+code|security\s+code)\b/i,
      /\b(?:enter\s+your\s+(?:password|pin|mpin|credentials))\b/i,
      /\b(?:seed\s+phrase|recovery\s+phrase|12[- ]word|24[- ]word|private\s+key)\b/i,
      /\b(?:kyc\s+(?:verification|update|mandatory|expired))\b/i,
      /\b(?:confirm\s+identity|verify\s+your\s+identity\s+now)\b/i,
    ];
    const matchedCredentials = credentialPatterns
      .filter((re) => re.test(text))
      .map((re) => text.match(re)?.[0] || '');

    if (matchedCredentials.length > 0) {
      const sev: FindingSeverity = 'CRITICAL';
      rawScore += 40;
      findings.push({
        tactic: SocialEngineeringTacticEnum.CREDENTIAL_OTP_HARVESTING,
        severity: sev,
        title: 'Credential or OTP Authentication Harvesting',
        description:
          'Message directly requests authentication credentials, one-time passwords (OTP), recovery seed phrases, or urgent KYC verification.',
        matchedPatterns: matchedCredentials,
      });
    }

    // 3. Authority & Brand Impersonation
    if (uniqueEntities.length > 0) {
      const authorityPatterns = [
        /\b(?:official|department|fraud\s+prevention|security\s+team|compliance|customer\s+support|helpdesk)\b/i,
        /\b(?:manager|officer|agent|director|admin)\b/i,
      ];
      const matchedAuthority = authorityPatterns
        .filter((re) => re.test(text))
        .map((re) => text.match(re)?.[0] || '');

      const isHighImpersonation = uniqueEntities.length >= 1 && (rawUrls.length > 0 || matchedCredentials.length > 0 || matchedAuthority.length > 0);
      const sev: FindingSeverity = isHighImpersonation ? 'HIGH' : 'MEDIUM';
      rawScore += isHighImpersonation ? 25 : 12;

      findings.push({
        tactic: SocialEngineeringTacticEnum.AUTHORITY_IMPERSONATION,
        severity: sev,
        title: 'Institutional or Brand Impersonation',
        description: `Message claims representation from reputable institutions (${uniqueEntities.slice(0, 3).join(', ')}) to establish false trust.`,
        matchedPatterns: [...uniqueEntities, ...matchedAuthority],
      });
    }

    // 4. Financial Manipulation & Fee Advance
    const financialPatterns = [
      /\b(?:refund\b|claim\s+refund|full\s+refund)\b/i,
      /\b(?:charged\b|\$\d+|\d+\s*dollars?)\b/i,
      /\b(?:wire\s+transfer|send\s+money|deposit\s+funds|wire\s+advance)\b/i,
      /\b(?:processing\s+fee|customs\s+fee|clearance\s+charge|advance\s+payment)\b/i,
      /\b(?:double\s+your\s+money|guaranteed\s+(?:profit|roi|returns))\b/i,
      /\b(?:payout|inheritance|claim\s+reward|bonus\s+credited)\b/i,
    ];
    const matchedFinancial = financialPatterns
      .filter((re) => re.test(text))
      .map((re) => text.match(re)?.[0] || '');

    if (matchedFinancial.length > 0) {
      const sev: FindingSeverity = rawUrls.length > 0 || uniquePaymentRefs.length > 0 ? 'HIGH' : 'MEDIUM';
      rawScore += sev === 'HIGH' ? 25 : 12;
      findings.push({
        tactic: SocialEngineeringTacticEnum.FINANCIAL_MANIPULATION,
        severity: sev,
        title: 'Financial Incentive or Advance-Fee Solicitation',
        description:
          'Message references unexpected refunds, required processing fees, guaranteed investment yields, or unauthorized transactions.',
        matchedPatterns: matchedFinancial,
      });
    }

    // 5. Suspicious Payment Instructions (Crypto, Gift Cards, UPI)
    if (wallets.length > 0 || /gift\s*card|itunes|steam\s*card|untraceable/i.test(text)) {
      rawScore += 25;
      findings.push({
        tactic: SocialEngineeringTacticEnum.SUSPICIOUS_PAYMENT,
        severity: 'HIGH',
        title: 'Irreversible or Untraceable Payment Demands',
        description:
          'Solicits funds through cryptocurrency transfer, prepaid gift cards, or unconventional transaction channels that resist recall.',
        matchedPatterns: wallets.map((w) => `${w.network}: ${w.address}`),
      });
    }

    // 6. Unrealistic Rewards & Recruitment Scams
    const rewardPatterns = [
      /\b(?:you\s+have\s+won|selected\s+as\s+the\s+winner|congratulations\s+winner)\b/i,
      /\b(?:lottery|lucky\s+draw|prize\s+money|gift\s+voucher)\b/i,
      /\b(?:part-time\s+job|work\s+from\s+home\s+(?:\$|₹|€)?\d{3,5}|daily\s+salary)\b/i,
      /\b(?:free\s+airdrop|claim\s+tokens|nft\s+giveaway)\b/i,
    ];
    const matchedRewards = rewardPatterns
      .filter((re) => re.test(text))
      .map((re) => text.match(re)?.[0] || '');

    if (matchedRewards.length > 0) {
      rawScore += 20;
      findings.push({
        tactic: SocialEngineeringTacticEnum.UNREALISTIC_REWARD,
        severity: 'MEDIUM',
        title: 'Unsolicited Reward or Lucrative Job Proposition',
        description:
          'Proposes unrealistic financial gains, unearned lottery prizes, or inflated daily salaries designed to elicit engagement.',
        matchedPatterns: matchedRewards,
      });
    }

    // 7. Tech Support & Remote Access
    const techPatterns = [
      /\b(?:anydesk|teamviewer|ultraviewer|quick\s*support)\b/i,
      /\b(?:computer\s+is\s+infected|virus\s+detected|call\s+microsoft\s+support)\b/i,
      /\b(?:remote\s+access|connect\s+to\s+technician|screen\s+share)\b/i,
    ];
    const matchedTech = techPatterns
      .filter((re) => re.test(text))
      .map((re) => text.match(re)?.[0] || '');

    if (matchedTech.length > 0) {
      rawScore += 40;
      findings.push({
        tactic: SocialEngineeringTacticEnum.TECH_SUPPORT_REMOTE_ACCESS,
        severity: 'CRITICAL',
        title: 'Remote-Access Tool Solicitation',
        description:
          'Instructs target to install desktop remote management software (AnyDesk, TeamViewer) or contact fraudulent technical support.',
        matchedPatterns: matchedTech,
      });
    }

    // --- Threat Intelligence Cross-Correlation ---
    for (const domain of uniqueDomains) {
      try {
        const matchingScans = await ScanModel.find({
          normalizedDomain: domain,
          verdict: { $in: ['MALICIOUS', 'SUSPICIOUS'] },
        })
          .sort({ createdAt: -1 })
          .limit(1)
          .lean();

        if (matchingScans.length > 0) {
          const matchedScan = matchingScans[0];
          threatIntelMatches.push({
            indicatorType: 'DOMAIN',
            indicatorValue: domain,
            matchSource: 'SENTRIX Internal Threat Registry',
            severity: matchedScan.verdict === 'MALICIOUS' ? 'CRITICAL' : 'HIGH',
            details: `Extracted domain was previously verified as ${matchedScan.verdict} (Risk Score: ${matchedScan.riskScore}) in scan ${matchedScan._id}.`,
          });
          rawScore += matchedScan.verdict === 'MALICIOUS' ? 35 : 20;
        }
      } catch {
        // Fallback gracefully if database read encounters transient issue
      }

      // Check high-risk TLDs
      if (/\.(?:xyz|top|biz|info|club|live|work|click|country|kim)$/i.test(domain)) {
        rawScore += 15;
        findings.push({
          tactic: SocialEngineeringTacticEnum.SUSPICIOUS_PAYMENT,
          severity: 'MEDIUM',
          title: 'Suspicious Domain Infrastructure (High-Abuse TLD)',
          description: `Extracted URL points to high-risk top-level domain (.${domain.split('.').pop()}) commonly leveraged in disposable phishing lures.`,
          matchedPatterns: [domain],
        });
      }
    }

    // --- Final Classification & Confidence ---
    const riskScore = Math.min(100, Math.max(0, rawScore));
    let classification: Verdict;
    if (riskScore >= 70) {
      classification = VerdictEnum.MALICIOUS;
    } else if (riskScore >= 26) {
      classification = VerdictEnum.SUSPICIOUS;
    } else {
      classification = VerdictEnum.BENIGN;
    }

    // Grounded Guard: If text is merely persuasive or informational with no links, credentials, or manipulation
    if (findings.length === 0 && rawUrls.length === 0 && wallets.length === 0) {
      classification = VerdictEnum.BENIGN;
    }

    const confidence = Math.min(
      98,
      Math.max(
        60,
        50 + findings.length * 10 + (threatIntelMatches.length > 0 ? 15 : 0) + (rawUrls.length > 0 ? 10 : 0)
      )
    );

    return {
      indicators,
      findings,
      threatIntelMatches,
      riskScore,
      confidence,
      classification,
      preview,
    };
  }

  private generateGroundedExplanation(
    messageText: string,
    analysis: ExtractResult
  ): IAIExplanation {
    const { classification, riskScore, findings, indicators, threatIntelMatches } = analysis;

    const reasoning: string[] = [];
    const precautions: string[] = [];
    const limitations: string[] = [
      'Analysis evaluated content lexically and cryptographically; legitimate organizations never solicit OTPs or seed phrases via unsolicited messages.',
      'Always confirm communication independently through official phone numbers listed on the back of credit cards or company websites.',
    ];

    if (classification === VerdictEnum.MALICIOUS) {
      findings.forEach((f) => {
        reasoning.push(`${f.title}: ${f.description}`);
      });
      threatIntelMatches.forEach((m) => {
        reasoning.push(`${m.matchSource}: ${m.details}`);
      });

      precautions.push('DO NOT click any links, open attachments, or reply to the sender.');
      precautions.push('Never disclose one-time passcodes (OTP), account passwords, or seed phrases.');
      precautions.push('Block the sender address/phone number and report to your carrier or platform fraud desk.');
      if (indicators.wallets.length > 0) {
        precautions.push('DO NOT send cryptocurrency to the listed addresses; transactions on public blockchains cannot be reversed.');
      }
    } else if (classification === VerdictEnum.SUSPICIOUS) {
      findings.forEach((f) => {
        reasoning.push(`${f.title}: ${f.description}`);
      });
      precautions.push('Exercise caution: verify the sender identity through a trusted alternative channel.');
      precautions.push('Avoid clicking links directly; manually navigate to the known official portal in your browser.');
    } else {
      reasoning.push(
        'No direct credential harvesting, social engineering coercion, or blacklisted threat indicators were observed in the text.'
      );
      precautions.push('Message appears routine, but maintain standard security vigilance for unprompted communications.');
    }

    const summary =
      classification === VerdictEnum.MALICIOUS
        ? `High-risk social engineering attack detected (Risk Score: ${riskScore}/100). The message exhibits predatory techniques including ${findings.map((f) => f.title.toLowerCase()).join(', ')}.`
        : classification === VerdictEnum.SUSPICIOUS
        ? `Suspicious message characteristics identified (Risk Score: ${riskScore}/100). Exercise caution before interacting with included links or contacts.`
        : `Benign / Low-risk communication (Risk Score: ${riskScore}/100). No deceptive manipulation or phishing indicators found.`;

    return {
      summary,
      reasoning,
      precautions,
      limitations,
    };
  }

  private async indexIndicators(
    messageId: any,
    indicators: IExtractedIndicators,
    classification: Verdict
  ): Promise<void> {
    const severity = classification === 'MALICIOUS' ? 'CRITICAL' : classification === 'SUSPICIOUS' ? 'HIGH' : 'INFO';

    const tasks: Array<{ type: string; value: string }> = [];
    indicators.domains.forEach((d) => tasks.push({ type: 'DOMAIN', value: d }));
    indicators.emails.forEach((e) => tasks.push({ type: 'EMAIL', value: e }));
    indicators.phones.forEach((p) => tasks.push({ type: 'PHONE', value: p }));
    indicators.wallets.forEach((w) => tasks.push({ type: 'WALLET', value: w.address }));
    indicators.paymentRefs.forEach((r) => tasks.push({ type: 'WALLET', value: r }));

    for (const item of tasks) {
      try {
        await ThreatIndicatorModel.findOneAndUpdate(
          { type: item.type, normalizedValue: item.value.toLowerCase() },
          {
            $set: {
              value: item.value,
              severity,
              lastSeen: new Date(),
            },
            $inc: { occurrences: 1 },
            $addToSet: {
              relatedMessageIds: messageId,
              tags: classification,
            },
            $setOnInsert: {
              firstSeen: new Date(),
            },
          },
          { upsert: true }
        );
      } catch {
        // Continue on collision or race condition
      }
    }
  }
}

export const messageAnalyzer = new MessageAnalyzerService();
