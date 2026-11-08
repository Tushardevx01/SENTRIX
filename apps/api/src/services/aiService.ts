import { env } from '../utils/config.js';
import { type IAIExplanation } from '@sentrix/shared';

interface ExplainRequest {
  contextType: 'SCAN' | 'MESSAGE' | 'CERTIFICATE' | 'CORRELATION';
  target: string;
  findingsSummary?: string[];
  riskScore?: number;
  verdict?: string;
  evidence?: Record<string, unknown>;
}

export class AIService {
  private apiKey: string | undefined;

  constructor() {
    this.apiKey = env.LLM_API_KEY || process.env.OPENAI_API_KEY || process.env.GEMINI_API_KEY;
  }

  /**
   * Generates an explainable cybersecurity breakdown for an investigation.
   * If external LLM is configured and reachable, prompts the model under strict
   * security boundaries; otherwise seamlessly executes grounded deterministic analysis.
   */
  public async explain(req: ExplainRequest): Promise<IAIExplanation> {
    if (this.apiKey) {
      try {
        const llmResponse = await this.queryExternalLLM(req);
        if (llmResponse) {
          return llmResponse;
        }
      } catch (err) {
        console.warn('[AIService] External LLM query failed, falling back to deterministic explanation:', (err as Error).message);
      }
    }

    return this.generateDeterministicExplanation(req);
  }

  private async queryExternalLLM(req: ExplainRequest): Promise<IAIExplanation | null> {
    const prompt = `
You are SENTRIX Cyber Intelligence AI, an explainable security advisor.
Analyze the following verified investigation findings for target: "${req.target.slice(0, 500)}".

CONTEXT TYPE: ${req.contextType}
VERDICT: ${req.verdict || 'UNKNOWN'}
RISK SCORE: ${req.riskScore ?? 'N/A'}/100
OBSERVED FINDINGS:
${(req.findingsSummary || []).map((f) => `- ${f}`).join('\n') || 'None recorded'}

EVIDENCE DETAILS:
${JSON.stringify(req.evidence || {}, null, 2).slice(0, 2000)}

RULES:
1. ONLY reference evidence provided above. Do NOT invent external threat records, CVEs, or certifications.
2. If evidence is missing, state that clearly in the limitations.
3. Output MUST be valid JSON adhering exactly to this schema:
{
  "summary": "Concise 1-2 sentence executive summary of the threat level and primary risk factors.",
  "reasoning": ["Bullet point 1 explaining finding", "Bullet point 2 explaining technical impact"],
  "precautions": ["Actionable defensive step 1", "Actionable defensive step 2"],
  "limitations": ["Boundary of this automated analysis"]
}
`;

    // Support OpenAI or compatible endpoints
    const endpoint = 'https://api.openai.com/v1/chat/completions';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    try {
      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          messages: [
            {
              role: 'system',
              content:
                'You are an authoritative cybersecurity analyst. Provide strictly structured, evidence-grounded security explanations in JSON format.',
            },
            { role: 'user', content: prompt },
          ],
          temperature: 0.2,
          response_format: { type: 'json_object' },
        }),
        signal: controller.signal,
      });

      if (!resp.ok) {
        return null;
      }

      const data = (await resp.json()) as any;
      const content = data.choices?.[0]?.message?.content;
      if (!content) return null;

      const parsed = JSON.parse(content);
      if (parsed.summary && Array.isArray(parsed.reasoning)) {
        return {
          summary: String(parsed.summary),
          reasoning: parsed.reasoning.map(String),
          precautions: Array.isArray(parsed.precautions) ? parsed.precautions.map(String) : [],
          limitations: Array.isArray(parsed.limitations) ? parsed.limitations.map(String) : [],
        };
      }
    } finally {
      clearTimeout(timeout);
    }

    return null;
  }

  public generateDeterministicExplanation(req: ExplainRequest): IAIExplanation {
    const verdict = (req.verdict || 'UNKNOWN').toUpperCase();
    const riskScore = req.riskScore ?? 0;
    const findings = req.findingsSummary || [];
    const reasoning: string[] = [];
    const precautions: string[] = [];
    const limitations: string[] = [
      'Automated passive security inspection evaluates current observable parameters without testing invasive exploit payloads.',
      'A low risk score does not guarantee absolute safety against newly registered or polymorphic attack campaigns.',
    ];

    if (req.contextType === 'SCAN') {
      if (verdict === 'MALICIOUS') {
        reasoning.push(
          `Target exhibits critical indicators of malicious infrastructure with a composite risk score of ${riskScore}/100.`
        );
        findings.forEach((f) => reasoning.push(`Observed Threat: ${f}`));
        precautions.push('Block all inbound/outbound corporate traffic to this destination at the DNS and perimeter firewall level.');
        precautions.push('If users entered credentials on this target, immediately trigger password reset and revoke active session tokens.');
        precautions.push('Inspect endpoint proxy logs for recent connections from internal workstations.');
      } else if (verdict === 'SUSPICIOUS') {
        reasoning.push(
          `Target presents multiple anomalous security characteristics (Risk Score: ${riskScore}/100), but lacks confirmed weaponized distribution payloads.`
        );
        findings.forEach((f) => reasoning.push(`Suspicious Characteristic: ${f}`));
        precautions.push('Isolate destination in a secure web browser sandbox before conducting manual investigation.');
        precautions.push('Verify domain ownership through WHOIS registration history and authentic brand portals.');
      } else if (verdict === 'UNVERIFIED_INFRASTRUCTURE') {
        reasoning.push(
          `Target is classified as unverified staging or parked infrastructure (Risk Score: ${riskScore}/100). No active weaponized lures were observed.`
        );
        precautions.push('Do not treat this destination as an authorized corporate service.');
        precautions.push('Maintain monitoring in case the infrastructure is later weaponized.');
      } else {
        reasoning.push(
          `Target satisfies authentic identity verification, valid cryptographic TLS parameters, and shows no active threat indicators (Risk Score: ${riskScore}/100).`
        );
        precautions.push('Destination appears authentic, but always practice standard operational vigilance.');
      }
    } else if (req.contextType === 'CERTIFICATE') {
      if (verdict === 'MALICIOUS' || verdict === 'SUSPICIOUS') {
        reasoning.push('Cryptographic auditing revealed non-compliant or high-risk certificate parameters.');
        findings.forEach((f) => reasoning.push(`TLS Audit Finding: ${f}`));
        precautions.push('Do not bypass browser TLS warnings or accept unverified root certificates.');
        precautions.push('Verify whether certificate was issued by an authorized public Certificate Authority.');
      } else {
        reasoning.push('Cryptographic X.509 leaf certificate is valid, properly signed, and meets CA/Browser Forum baseline standards.');
        precautions.push('Ensure TLS 1.3 is preferred and weak cipher suites remain disabled.');
      }
    } else if (req.contextType === 'MESSAGE') {
      if (verdict === 'MALICIOUS') {
        reasoning.push(
          `Message content exhibits predatory social engineering manipulation techniques (Risk Score: ${riskScore}/100).`
        );
        findings.forEach((f) => reasoning.push(`Tactical Pattern: ${f}`));
        precautions.push('Do NOT open any included URLs or execute payment instructions.');
        precautions.push('Delete message and report sender to network provider or internal SOC.');
      } else {
        reasoning.push('Message does not contain coercive social engineering patterns or known threat links.');
        precautions.push('Standard caution advised for unsolicited messages.');
      }
    } else {
      reasoning.push(`Correlation analysis evaluated related indicators across SENTRIX threat datasets.`);
      findings.forEach((f) => reasoning.push(`Correlated Pattern: ${f}`));
      precautions.push('Monitor related cluster assets for synchronized phishing operations.');
    }

    const summary =
      verdict === 'MALICIOUS'
        ? `High-confidence malicious threat detected for ${req.target} (Risk Score: ${riskScore}/100). Immediate defensive isolation recommended.`
        : verdict === 'SUSPICIOUS'
        ? `Suspicious risk profile identified for ${req.target} (Risk Score: ${riskScore}/100). Review detailed forensic evidence.`
        : verdict === 'UNVERIFIED_INFRASTRUCTURE'
        ? `Unverified infrastructure profile for ${req.target}. Parked or staging asset without verified corporate identity.`
        : `Verified benign profile for ${req.target} (Risk Score: ${riskScore}/100). Inspection confirmed standard security baseline.`;

    return {
      summary,
      reasoning,
      precautions,
      limitations,
    };
  }
}

export const aiService = new AIService();
