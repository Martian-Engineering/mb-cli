const TAG_START = 0xe0000;
const TAG_END = 0xe007f;
const TAG_CANCEL = 0xe007f;
const BLACK_FLAG = 0x1f3f4;

const ALLOWED_TAG_SEQUENCES = new Set(["gbeng", "gbsct", "gbwls"]);

export type SanitizationResult = {
  text: string;
  warnings: string[];
  changed: boolean;
};

function isTag(cp: number): boolean {
  return cp >= TAG_START && cp <= TAG_END;
}

function isVariationSelector(cp: number): boolean {
  return (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
}

function isZeroWidth(cp: number): boolean {
  return cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0x2060;
}

function isBidiOverride(cp: number): boolean {
  return (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
}

function isInterlinear(cp: number): boolean {
  return cp >= 0xfff9 && cp <= 0xfffb;
}

function tagSequenceToAscii(seq: number[]): string {
  return seq.map((cp) => String.fromCodePoint(cp - TAG_START)).join("");
}

export function sanitizeText(text: string): SanitizationResult {
  const chars = Array.from(text);
  const warnings = new Set<string>();
  let changed = false;
  let output = "";

  for (let i = 0; i < chars.length; i += 1) {
    const ch = chars[i];
    const cp = ch.codePointAt(0) ?? 0;

    if (cp === BLACK_FLAG) {
      let j = i + 1;
      const tagSequence: number[] = [];
      while (j < chars.length) {
        const nextCp = chars[j].codePointAt(0) ?? 0;
        if (nextCp === TAG_CANCEL) {
          break;
        }
        if (isTag(nextCp)) {
          tagSequence.push(nextCp);
          j += 1;
          continue;
        }
        break;
      }

      if (
        tagSequence.length > 0 &&
        j < chars.length &&
        (chars[j].codePointAt(0) ?? 0) === TAG_CANCEL
      ) {
        const tagAscii = tagSequenceToAscii(tagSequence);
        if (ALLOWED_TAG_SEQUENCES.has(tagAscii)) {
          output += ch;
          for (let k = i + 1; k <= j; k += 1) {
            output += chars[k];
          }
        } else {
          output += ch;
          changed = true;
          warnings.add("Stripped Unicode tag characters");
        }
        i = j;
        continue;
      }
    }

    if (isTag(cp)) {
      changed = true;
      warnings.add("Stripped Unicode tag characters");
      continue;
    }

    if (isVariationSelector(cp)) {
      changed = true;
      warnings.add("Stripped Unicode variation selectors");
      continue;
    }

    if (isZeroWidth(cp)) {
      changed = true;
      warnings.add("Stripped zero-width characters");
      continue;
    }

    if (isBidiOverride(cp)) {
      changed = true;
      warnings.add("Stripped bidirectional override characters");
      continue;
    }

    if (isInterlinear(cp)) {
      changed = true;
      warnings.add("Stripped interlinear annotation characters");
      continue;
    }

    output += ch;
  }

  return { text: output, warnings: Array.from(warnings), changed };
}

export function sanitizeData(value: unknown): {
  value: unknown;
  warnings: string[];
  changed: boolean;
} {
  const warnings = new Set<string>();
  let changed = false;

  const sanitizeAny = (input: unknown): unknown => {
    if (typeof input === "string") {
      const result = sanitizeText(input);
      result.warnings.forEach((w) => warnings.add(w));
      if (result.changed) {
        changed = true;
      }
      return result.text;
    }
    if (Array.isArray(input)) {
      return input.map((item) => sanitizeAny(item));
    }
    if (input && typeof input === "object") {
      const entries = Object.entries(input as Record<string, unknown>);
      const output: Record<string, unknown> = {};
      for (const [key, val] of entries) {
        output[key] = sanitizeAny(val);
      }
      return output;
    }
    return input;
  };

  return { value: sanitizeAny(value), warnings: Array.from(warnings), changed };
}
