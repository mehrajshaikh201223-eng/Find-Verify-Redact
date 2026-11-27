import express, { Request, Response } from 'express';
import cors from 'cors';
import crypto from 'crypto';
import { PrismaClient } from '@prisma/client';
import { detectEntities, applyRedaction } from './redactionEngine';

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '25mb' }));

// Helper: Compute SHA-256 checksum
function sha256(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------
// 1. HEALTH CHECK
// ---------------------------------------------------------------------
app.get('/api/health', (req: Request, res: Response) => {
  res.json({
    status: 'ONLINE',
    service: 'Blackline Redaction Core API',
    timestamp: new Date().toISOString()
  });
});

// ---------------------------------------------------------------------
// 2. REAL-TIME SYNCHRONOUS SANITIZE ENDPOINT
// ---------------------------------------------------------------------
app.post('/api/sanitize', async (req: Request, res: Response) => {
  const startTime = Date.now();
  try {
    const { text, mode = 'full', fileName, recordAudit = true } = req.body;

    if (typeof text !== 'string') {
      return res.status(400).json({ error: 'Payload must contain a "text" string.' });
    }

    const inputHash = sha256(text);

    // 1. Detection Pass
    const { entities, blockedLuhn, counts } = detectEntities(text);

    // 2. Redaction Pass
    const validMode = (['full', 'partial', 'pseudonymize'].includes(mode) ? mode : 'full') as
      | 'full'
      | 'partial'
      | 'pseudonymize';
    const { sanitizedText, uniquePseudoCount, pseudonymMap } = applyRedaction(text, entities, validMode);
    const outputHash = sha256(sanitizedText);
    const executionMs = Date.now() - startTime;

    // 3. Optional Database Audit & Metrics Persistence
    let savedJobId: string | null = null;
    if (recordAudit) {
      try {
        const job = await prisma.sanitizationJob.create({
          data: {
            fileName: fileName || 'direct_buffer.txt',
            fileType: fileName?.split('.').pop() || 'txt',
            fileSizeBytes: Buffer.byteLength(text, 'utf8'),
            charCount: text.length,
            lineCount: text ? text.split(/\r\n|\r|\n/).length : 0,
            redactionMode:
              validMode === 'partial'
                ? 'PARTIAL_MASK'
                : validMode === 'pseudonymize'
                ? 'PSEUDONYMIZE'
                : 'FULL_MASK',
            status: 'COMPLETED',
            executionMs,
            inputChecksum: inputHash,
            outputChecksum: outputHash,
            sanitizedOutput: sanitizedText, // zero-leak: raw text is NEVER saved
            completedAt: new Date(),
            metric: {
              create: {
                creditCardCount: counts.cc,
                aadhaarCount: counts.aadhaar,
                panCount: counts.pan,
                emailCount: counts.email,
                ipCount: counts.ip,
                phoneCount: counts.phone,
                totalRedacted: counts.total,
                blockedLuhnCount: blockedLuhn
              }
            },
            auditLogs: {
              create: {
                action: 'BUFFER_SANITIZED',
                ipAddress: (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress,
                userAgent: req.headers['user-agent'],
                status: 'SUCCESS',
                details: {
                  mode: validMode,
                  totalRedacted: counts.total,
                  blockedLuhn
                }
              }
            }
          }
        });
        savedJobId = job.id;
      } catch (dbErr) {
        // If DB is offline or not yet migrated, still return sanitized output cleanly
        console.warn('Database write skipped (offline or not migrated):', (dbErr as Error).message);
      }
    }

    return res.json({
      success: true,
      jobId: savedJobId,
      executionMs,
      inputChecksum: inputHash,
      outputChecksum: outputHash,
      counts: {
        ...counts,
        blockedLuhn
      },
      uniquePseudonyms: uniquePseudoCount,
      sanitizedText,
      pseudonymMap: validMode === 'pseudonymize' ? pseudonymMap : undefined
    });
  } catch (error) {
    console.error('Sanitization Error:', error);
    return res.status(500).json({ error: 'Internal sanitization error.' });
  }
});

// ---------------------------------------------------------------------
// 3. ASYNCHRONOUS JOB RETRIEVAL
// ---------------------------------------------------------------------
app.get('/api/jobs/:id', async (req: Request, res: Response) => {
  try {
    const job = await prisma.sanitizationJob.findUnique({
      where: { id: req.params.id },
      include: { metric: true, auditLogs: true }
    });

    if (!job) {
      return res.status(404).json({ error: 'Job not found.' });
    }

    res.json({ job });
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve job details.' });
  }
});

// ---------------------------------------------------------------------
// 4. AGGREGATE TELEMETRY METRICS
// ---------------------------------------------------------------------
app.get('/api/telemetry', async (req: Request, res: Response) => {
  try {
    const aggregates = await prisma.jobMetric.aggregate({
      _sum: {
        creditCardCount: true,
        aadhaarCount: true,
        panCount: true,
        emailCount: true,
        ipCount: true,
        phoneCount: true,
        totalRedacted: true,
        blockedLuhnCount: true
      },
      _count: {
        id: true
      }
    });

    res.json({
      totalJobs: aggregates._count.id,
      telemetry: {
        creditCardsVerified: aggregates._sum.creditCardCount || 0,
        aadhaarVerified: aggregates._sum.aadhaarCount || 0,
        panDetected: aggregates._sum.panCount || 0,
        emailsRedacted: aggregates._sum.emailCount || 0,
        ipAddressesRedacted: aggregates._sum.ipCount || 0,
        phonesRedacted: aggregates._sum.phoneCount || 0,
        totalRedacted: aggregates._sum.totalRedacted || 0,
        blockedLuhn: aggregates._sum.blockedLuhnCount || 0
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Database unavailable for telemetry query.' });
  }
});

// ---------------------------------------------------------------------
// 5. AUDIT LOGS
// ---------------------------------------------------------------------
app.get('/api/audit-logs', async (req: Request, res: Response) => {
  try {
    const logs = await prisma.auditLog.findMany({
      take: 50,
      orderBy: { createdAt: 'desc' }
    });
    res.json({ logs });
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve audit records.' });
  }
});

app.listen(PORT, () => {
  console.log(`[Blackline Core Backend] Listening on http://localhost:${PORT}`);
});
