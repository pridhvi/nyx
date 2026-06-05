export const darkSurfaceColor = "#10111b";

export const severityColorTokens: Record<string, string> = {
  critical: "#ff5f7a",
  high: "#ff9f45",
  medium: "#f9d65c",
  low: "#45e2a0",
  info: "#72b7ff",
};

export function contrastRatio(foreground: string, background: string) {
  const fg = relativeLuminance(hexToRGB(foreground));
  const bg = relativeLuminance(hexToRGB(background));
  const lighter = Math.max(fg, bg);
  const darker = Math.min(fg, bg);
  return (lighter + 0.05) / (darker + 0.05);
}

function hexToRGB(hex: string) {
  const normalized = hex.replace("#", "");
  return {
    r: parseInt(normalized.slice(0, 2), 16) / 255,
    g: parseInt(normalized.slice(2, 4), 16) / 255,
    b: parseInt(normalized.slice(4, 6), 16) / 255,
  };
}

function relativeLuminance({ r, g, b }: { r: number; g: number; b: number }) {
  return [r, g, b]
    .map((value) => value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
    .reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
}
