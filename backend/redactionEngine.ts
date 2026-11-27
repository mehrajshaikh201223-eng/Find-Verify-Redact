/**
 * Blackline Enterprise Redaction Engine (TypeScript / Node.js)
 * Implements strict precedence detection, mod-10 Luhn verification,
 * non-destructive span reconstruction, and deterministic pseudonymization.
 */

export interface DetectedEntity {
  type: 'cc' | 'aadhaar' | 'pan' | 'email' | 'ip' | 'phone';
  start: number;
  end: number;
  rawText: string;
  label: string;
}

export interface DetectionResult {
  entities: DetectedEntity[];
  blockedLuhn: number;
  counts: {
    cc: number;
    aadhaar: number;
    pan: number;
    email: number;
    ip: number;
    phone: number;
    total: number;
  };
}

export interface RedactionResult {
  sanitizedText: string;
  uniquePseudoCount: number;
  pseudonymMap: Record<string, string>;
}

// 1. Mod-10 Luhn Checksum Verification
export function validateLuhn(numStr: string): boolean {
  const digits = numStr.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

// 2. Canonical Key Normalizer for Pseudonymization
export function keyOf(entity: DetectedEntity): string {
  const raw = entity.rawText;
  switch (entity.type) {
    case 'email':
      return raw.toLowerCase().trim();
    case 'pan':
      return raw.toUpperCase().trim();
    case 'cc':
    case 'aadhaar':
      return raw.replace(/\D/g, '');
    case 'phone': {
      const digits = raw.replace(/\D/g, '');
      return digits.length > 10 ? digits.slice(-10) : digits;
    }
    case 'ip':
      return raw.toLowerCase().trim();
    default:
      return raw.trim();
  }
}

// 3. Partial Masking Generator
export function partialMask(entity: DetectedEntity): string {
  const raw = entity.rawText;
  switch (entity.type) {
    case 'email': {
      const atIdx = raw.indexOf('@');
      if (atIdx === -1) return '***@domain.com';
      const user = raw.slice(0, atIdx);
      const domain = raw.slice(atIdx);
      const visible = user.slice(0, Math.min(2, user.length));
      return `${visible}***${domain}`;
    }
    case 'cc': {
      const digits = raw.replace(/\D/g, '');
      const last4 = digits.slice(-4);
      return `XXXX-XXXX-XXXX-${last4}`;
    }
    case 'aadhaar': {
      const digits = raw.replace(/\D/g, '');
      const last4 = digits.slice(-4);
      return `XXXX-XXXX-${last4}`;
    }
    case 'pan': {
      const clean = raw.toUpperCase().trim();
      if (clean.length < 10) return 'XXXXXXXXXX';
      return `${clean.slice(0, 2)}XXXXXXX${clean.slice(-1)}`;
    }
    case 'phone': {
      const digits = raw.replace(/\D/g, '');
      const last2 = digits.slice(-2);
      let prefix = '';
      if (raw.trim().startsWith('+')) {
        const m = raw.match(/^\+(\d{1,3})/);
        if (m) prefix = `+${m[1]}-`;
      }
      return `${prefix}XXXXXXXX${last2}`;
    }
    case 'ip': {
      if (raw.includes('.')) {
        const octets = raw.split('.');
        return `${octets[0]}.XXX.XXX.XXX`;
      } else {
        const groups = raw.split(':');
        const first = groups[0] || 'XXXX';
        return `${first}:XXXX:XXXX:XXXX`;
      }
    }
    default:
      return '[REDACTED]';
  }
}

// 4. Strict Precedence Entity Detector
export function detectEntities(text: string): DetectionResult {
  if (!text) {
    return {
      entities: [],
      blockedLuhn: 0,
      counts: { cc: 0, aadhaar: 0, pan: 0, email: 0, ip: 0, phone: 0, total: 0 }
    };
  }

  const claimedRanges: [number, number][] = [];
  const entities: DetectedEntity[] = [];
  let blockedLuhn = 0;

  function isOverlapping(start: number, end: number): boolean {
    for (const [cs, ce] of claimedRanges) {
      if (Math.max(start, cs) < Math.min(end, ce)) {
        return true;
      }
    }
    return false;
  }

  // Precedence 1: Credit Card
  const ccRegex = /(?<!\d)(?:(?:\d[ -]?){13,19})(?!\d)/g;
  let match: RegExpExecArray | null;
  while ((match = ccRegex.exec(text)) !== null) {
    const raw = match[0].replace(/[ -]+$/, '');
    const start = match.index;
    const end = start + raw.length;
    const digits = raw.replace(/\D/g, '');

    if (digits.length >= 13 && digits.length <= 19) {
      if (validateLuhn(digits)) {
        if (!isOverlapping(start, end)) {
          claimedRanges.push([start, end]);
          entities.push({
            type: 'cc',
            start,
            end,
            rawText: raw,
            label: 'Credit Card (Luhn Valid)'
          });
        }
      } else {
        blockedLuhn++;
        claimedRanges.push([start, end]);
      }
    }
  }

  // Precedence 2: Indian Aadhaar
  const aadhaarRegex = /(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)/g;
  while ((match = aadhaarRegex.exec(text)) !== null) {
    const raw = match[0];
    const start = match.index;
    const end = start + raw.length;
    if (!isOverlapping(start, end)) {
      claimedRanges.push([start, end]);
      entities.push({
        type: 'aadhaar',
        start,
        end,
        rawText: raw,
        label: 'Indian Aadhaar (UIDAI)'
      });
    }
  }

  // Precedence 3: Indian PAN
  const panRegex = /\b[A-Z]{5}\d{4}[A-Z]\b/g;
  while ((match = panRegex.exec(text)) !== null) {
    const raw = match[0];
    const start = match.index;
    const end = start + raw.length;
    if (!isOverlapping(start, end)) {
      claimedRanges.push([start, end]);
      entities.push({
        type: 'pan',
        start,
        end,
        rawText: raw,
        label: 'Indian PAN'
      });
    }
  }

  // Precedence 4: Email Addresses
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  while ((match = emailRegex.exec(text)) !== null) {
    const raw = match[0];
    const start = match.index;
    const end = start + raw.length;
    if (!isOverlapping(start, end)) {
      claimedRanges.push([start, end]);
      entities.push({
        type: 'email',
        start,
        end,
        rawText: raw,
        label: 'Email Address'
      });
    }
  }

  // Precedence 5: IPv4 & IPv6
  const ipv4Regex = /(?<![0-9.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![0-9.])/g;
  while ((match = ipv4Regex.exec(text)) !== null) {
    const raw = match[0];
    const start = match.index;
    const end = start + raw.length;
    if (!isOverlapping(start, end)) {
      claimedRanges.push([start, end]);
      entities.push({
        type: 'ip',
        start,
        end,
        rawText: raw,
        label: 'IPv4 Address'
      });
    }
  }

  const ipv6Regex = /(?<![a-zA-Z0-9:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::)(?![a-zA-Z0-9:])/g;
  while ((match = ipv6Regex.exec(text)) !== null) {
    const raw = match[0];
    const start = match.index;
    const end = start + raw.length;
    if (raw.length > 2 && !isOverlapping(start, end)) {
      claimedRanges.push([start, end]);
      entities.push({
        type: 'ip',
        start,
        end,
        rawText: raw,
        label: 'IPv6 Address'
      });
    }
  }

  // Precedence 6: Phone Numbers
  const phoneRegex = /(?<![\w+])(?:(?:\+?91[\s-]?)?(?:0)?[6-9]\d{4}[\s-]?\d{5}|(?:\+?91[\s-]?)?(?:0)?[6-9]\d{9}|(?:\+?1[\s-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4})(?!\d)/g;
  while ((match = phoneRegex.exec(text)) !== null) {
    const raw = match[0];
    const start = match.index;
    const end = start + raw.length;
    if (!isOverlapping(start, end)) {
      claimedRanges.push([start, end]);
      entities.push({
        type: 'phone',
        start,
        end,
        rawText: raw,
        label: 'Phone Number'
      });
    }
  }

  entities.sort((a, b) => a.start - b.start);

  const counts = { cc: 0, aadhaar: 0, pan: 0, email: 0, ip: 0, phone: 0, total: entities.length };
  for (const e of entities) {
    counts[e.type]++;
  }

  return { entities, blockedLuhn, counts };
}

// 5. Redaction Application Pipeline
export function applyRedaction(
  text: string,
  entities: DetectedEntity[],
  mode: 'full' | 'partial' | 'pseudonymize'
): RedactionResult {
  if (!text || entities.length === 0) {
    return {
      sanitizedText: text,
      uniquePseudoCount: 0,
      pseudonymMap: {}
    };
  }

  const fullMaskMap: Record<string, string> = {
    email: '[REDACTED_EMAIL]',
    phone: '[REDACTED_PHONE]',
    ip: '[REDACTED_IP]',
    pan: '[REDACTED_PAN]',
    aadhaar: '[REDACTED_AADHAAR]',
    cc: '[REDACTED_CC]'
  };

  const pseudoMap = new Map<string, string>();
  const pseudoCounters: Record<string, number> = { cc: 0, aadhaar: 0, pan: 0, email: 0, ip: 0, phone: 0 };
  const prefixMap: Record<string, string> = {
    email: 'EMAIL',
    phone: 'PHONE',
    ip: 'IP',
    pan: 'PAN',
    aadhaar: 'AADHAAR',
    cc: 'CC'
  };

  for (const e of entities) {
    const normKey = `${e.type}:${keyOf(e)}`;
    if (!pseudoMap.has(normKey)) {
      pseudoCounters[e.type] = (pseudoCounters[e.type] || 0) + 1;
      const seq = String(pseudoCounters[e.type]).padStart(2, '0');
      const token = `${prefixMap[e.type] || 'ENTITY'}_${seq}`;
      pseudoMap.set(normKey, token);
    }
  }

  let sanitized = '';
  let lastIndex = 0;

  for (const entity of entities) {
    sanitized += text.slice(lastIndex, entity.start);

    let token = '';
    if (mode === 'full') {
      token = fullMaskMap[entity.type] || '[REDACTED]';
    } else if (mode === 'partial') {
      token = partialMask(entity);
    } else if (mode === 'pseudonymize') {
      const normKey = `${entity.type}:${keyOf(entity)}`;
      token = pseudoMap.get(normKey) || '[REDACTED]';
    }

    sanitized += token;
    lastIndex = entity.end;
  }

  sanitized += text.slice(lastIndex);

  const jsonMap: Record<string, string> = {};
  pseudoMap.forEach((v, k) => {
    jsonMap[k] = v;
  });

  return {
    sanitizedText: sanitized,
    uniquePseudoCount: pseudoMap.size,
    pseudonymMap: jsonMap
  };
}
