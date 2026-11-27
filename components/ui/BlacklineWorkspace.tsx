"use client";

import React, { useState, useEffect, useRef, useTransition } from "react";
import { ArrowRight, Copy, Check, ShieldCheck, Eye, EyeOff, Trash2, Upload, FileText } from "lucide-react";
import { detectEntities, applyRedaction, DetectedEntity, DetectionResult } from "@/backend/redactionEngine";

export default function BlacklineWorkspace() {
  const [rawText, setRawText] = useState("");
  const [redactionMode, setRedactionMode] = useState<"full" | "partial" | "pseudonymize">("full");
  const [isPreviewOn, setIsPreviewOn] = useState(false);
  const [isCopied, setIsCopied] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  // Process data locally or via API
  const [detection, setDetection] = useState<DetectionResult>({
    entities: [],
    blockedLuhn: 0,
    counts: { cc: 0, aadhaar: 0, pan: 0, email: 0, ip: 0, phone: 0, total: 0 }
  });

  const [sanitizedOutput, setSanitizedOutput] = useState("");
  const [uniquePseudonyms, setUniquePseudonyms] = useState(0);

  // Pipeline execution on input or mode change
  useEffect(() => {
    startTransition(() => {
      const result = detectEntities(rawText);
      setDetection(result);

      const redResult = applyRedaction(rawText, result.entities, redactionMode);
      setSanitizedOutput(redResult.sanitizedText);
      setUniquePseudonyms(redResult.uniquePseudoCount);
    });
  }, [rawText, redactionMode]);

  // Copy handler
  const handleCopy = async () => {
    if (!sanitizedOutput) return;
    await navigator.clipboard.writeText(sanitizedOutput);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  // Sample data loader
  const handleLoadSample = () => {
    setFileName("incident_sample.txt");
    setRawText(`INCIDENT REPORT // ESCALATION TICKET #SEC-98421
Author: alex.vance@blackline-sec.internal (escalated from ALEX.VANCE@blackline-sec.internal)
Permanent Account Number (PAN): ABCDE1234F
Aadhaar Identity Verification: 2345 6789 0123 / 9876-5432-1098
Contact: +91 98765 43210 (Alternate: 09876543210, US: (415) 555-2671)
Gateway IP: 192.168.1.105 (IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334)
Active Visa: 4532-0150-1234-5671 (MC: 5424 1801 2345 6789)
Failed Luhn Batch ID: 8821940182740192 (16 digits, fails mod-10)`);
  };

  return (
    <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 py-8 text-zinc-100 font-sans">
      
      {/* 1. TOP HEADER & TELEMETRY ROW (SaaS Frosted Glass Styling) */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-8 border-b border-gray-800/80 pb-6">
        <div>
          <aside className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full border border-gray-700 bg-gray-800/50 backdrop-blur-sm text-xs font-mono text-zinc-300 mb-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            100% In-Memory Sandbox · Zero Telemetry Egress
          </aside>
          <h1 className="text-3xl font-semibold tracking-tight text-white" style={{ letterSpacing: "-0.05em" }}>
            Blackline Redaction Core
          </h1>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleLoadSample}
            className="px-3.5 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-xs font-mono font-medium text-white border border-gray-700/80 transition-all active:scale-95 flex items-center gap-2"
          >
            <FileText size={14} className="text-emerald-400" />
            Load sample
          </button>

          {/* Segmented Mode Selector */}
          <div className="flex p-1 rounded-lg bg-black/80 border border-gray-800 text-xs font-mono">
            {(["full", "partial", "pseudonymize"] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setRedactionMode(mode)}
                className={`px-3 py-1 rounded-md transition-all capitalize ${
                  redactionMode === mode ? "bg-gray-800 text-white font-medium" : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                {mode === "pseudonymize" ? `Pseudonymize (${uniquePseudonyms})` : `${mode} Mask`}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* 2. TELEMETRY ROW (8 SaaS Cards) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3.5 mb-8">
        {[
          { label: "Credit Cards", val: detection.counts.cc, sub: "Luhn Verified", color: "rose" },
          { label: "Aadhaar", val: detection.counts.aadhaar, sub: "12-Digit UIDAI", color: "orange" },
          { label: "PAN Cards", val: detection.counts.pan, sub: "IT Alphanumeric", color: "fuchsia" },
          { label: "Emails", val: detection.counts.email, sub: "RFC Compliant", color: "sky" },
          { label: "IP Endpoints", val: detection.counts.ip, sub: "IPv4 & IPv6", color: "violet" },
          { label: "Phones", val: detection.counts.phone, sub: "Natl & Intl", color: "amber" },
          { label: "Total Redacted", val: detection.counts.total, sub: "Active Targets", color: "emerald" },
          { label: "Blocked (Luhn)", val: detection.blockedLuhn, sub: "Failed Mod-10", color: "rose", danger: true }
        ].map((item, idx) => (
          <div
            key={idx}
            className={`rounded-xl p-3.5 flex flex-col justify-between border backdrop-blur-xl relative overflow-hidden transition-all hover:-translate-y-0.5 ${
              item.danger
                ? "bg-rose-950/15 border-rose-500/30"
                : "bg-gradient-to-b from-zinc-900/90 to-zinc-950/95 border-white/10"
            }`}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] font-mono text-zinc-400 truncate">{item.label}</span>
              <span className={`w-1.5 h-1.5 rounded-full ${item.danger ? "bg-rose-500 animate-pulse" : "bg-white/60"}`} />
            </div>
            <div
              className="text-2xl font-mono font-bold my-1"
              style={{
                background: item.danger
                  ? "linear-gradient(180deg, #fecdd3 0%, #f43f5e 100%)"
                  : "linear-gradient(180deg, #ffffff 0%, rgba(255, 255, 255, 0.6) 100%)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent"
              }}
            >
              {item.val}
            </div>
            <div className="pt-2 border-t border-white/5 text-[10px] font-mono text-zinc-400">{item.sub}</div>
          </div>
        ))}
      </div>

      {/* 3. DUAL-STREAM IN-MEMORY WORKSPACE */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
        
        {/* LEFT PANE: RAW INPUT */}
        <div className="rounded-2xl border border-white/10 bg-gradient-to-b from-zinc-900/80 to-black/90 backdrop-blur-xl flex flex-col min-h-[580px] shadow-2xl relative overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5 bg-black/40">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              <span className="text-sm font-mono font-semibold text-white">Raw input buffer</span>
              <span className="text-xs font-mono text-zinc-400 bg-zinc-800/80 px-2.5 py-0.5 rounded-full">
                {rawText.length.toLocaleString()} chars
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setIsPreviewOn(!isPreviewOn)}
                className="px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-xs font-mono text-zinc-200 transition-all flex items-center gap-1.5 border border-zinc-700/80"
              >
                {isPreviewOn ? <EyeOff size={13} /> : <Eye size={13} />}
                <span>Preview: <strong>{isPreviewOn ? "ON" : "OFF"}</strong></span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setRawText("");
                  setFileName(null);
                }}
                className="p-1.5 rounded-lg text-zinc-400 hover:text-rose-400 hover:bg-rose-950/30 transition-all"
                title="Clear input"
              >
                <Trash2 size={15} />
              </button>
            </div>
          </div>

          <div className="relative flex-1 p-5 flex flex-col">
            {!isPreviewOn ? (
              <textarea
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                placeholder="Paste payload or drag-and-drop .txt / .csv here..."
                className="w-full flex-1 bg-transparent text-zinc-100 font-mono text-xs sm:text-sm leading-relaxed resize-none focus:outline-none placeholder:text-zinc-600"
              />
            ) : (
              <div className="w-full flex-1 overflow-auto font-mono text-xs sm:text-sm leading-relaxed text-zinc-200 whitespace-pre-wrap">
                {rawText || <span className="text-zinc-600 italic">No buffer data to preview.</span>}
              </div>
            )}
          </div>

          <div className="px-5 py-2.5 border-t border-white/5 bg-black/40 text-[11px] font-mono text-zinc-500 flex justify-between">
            <span>{fileName || "Direct Memory Buffer"}</span>
            <span className="text-zinc-400">UTF-8 Sandboxed</span>
          </div>
        </div>

        {/* RIGHT PANE: SANITIZED OUTPUT */}
        <div className="rounded-2xl border border-white/10 bg-gradient-to-b from-zinc-900/80 to-black/90 backdrop-blur-xl flex flex-col min-h-[580px] shadow-2xl relative overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5 bg-black/40">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              <span className="text-sm font-mono font-semibold text-white">Sanitized stream</span>
              <span className="text-xs font-mono text-emerald-400 bg-emerald-950/40 border border-emerald-500/30 px-2 py-0.5 rounded">
                Verified Clean
              </span>
            </div>

            <button
              type="button"
              onClick={handleCopy}
              className="px-4 py-1.5 rounded-lg bg-gradient-to-b from-white via-white/95 to-white/70 text-black font-mono text-xs font-semibold shadow-md hover:scale-105 active:scale-95 transition-all flex items-center gap-1.5"
            >
              {isCopied ? <Check size={14} className="text-emerald-600" /> : <Copy size={14} />}
              <span>{isCopied ? "Copied!" : "Copy to clipboard"}</span>
            </button>
          </div>

          <div className="relative flex-1 p-5 overflow-auto">
            <div className="font-mono text-xs sm:text-sm leading-relaxed text-zinc-200 whitespace-pre-wrap">
              {sanitizedOutput || (
                <span className="text-zinc-600 italic font-sans text-xs">Awaiting input data stream...</span>
              )}
            </div>
          </div>

          <div className="px-5 py-2.5 border-t border-white/5 bg-black/40 text-[11px] font-mono text-zinc-500 flex justify-between items-center">
            <span>{detection.counts.total} items redacted · {detection.blockedLuhn} blocked</span>
            <span className="text-emerald-400 flex items-center gap-1">
              <ShieldCheck size={14} /> Zero Leak Boundary
            </span>
          </div>
        </div>

      </div>

    </div>
  );
}
