import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import type { Env } from '../src/types';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const INIT_MIGRATION_PATH = resolve(__dirname, '../migrations/0001_init.sql');

function normalizeParam(v: unknown): SQLInputValue {
  if (v === undefined || v === null) return null;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (typeof v === 'string' || typeof v === 'number' || v instanceof Uint8Array) {
    return v;
  }
  return String(v);
}

function toPlainObject<T>(row: unknown): T {
  return { ...(row as Record<string, unknown>) } as T;
}

class SqliteD1PreparedStatement implements D1PreparedStatement {
  private readonly db: DatabaseSync;
  private readonly sql: string;
  private readonly params: SQLInputValue[];

  constructor(db: DatabaseSync, sql: string, params: SQLInputValue[] = []) {
    this.db = db;
    this.sql = sql;
    this.params = params;
  }

  bind(...values: unknown[]): D1PreparedStatement {
    return new SqliteD1PreparedStatement(
      this.db,
      this.sql,
      values.map((v) => normalizeParam(v))
    );
  }

  async first<T = unknown>(colName?: string): Promise<T | null> {
    const stmt = this.db.prepare(this.sql);
    const row = stmt.get(...this.params);
    if (!row) return null;
    const plain = toPlainObject<Record<string, unknown>>(row);
    if (colName !== undefined) {
      return (plain[colName] as T) ?? null;
    }
    return plain as T;
  }

  async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    const stmt = this.db.prepare(this.sql);
    const info = stmt.run(...this.params);
    return {
      results: [],
      success: true,
      meta: {
        duration: 0,
        size_after: 0,
        rows_read: 0,
        rows_written: Number(info.changes ?? 0),
        last_row_id: Number(info.lastInsertRowid ?? 0),
        changed_db: Number(info.changes ?? 0) > 0,
        changes: Number(info.changes ?? 0),
        served_by: 'node-sqlite',
      },
    };
  }

  async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    const stmt = this.db.prepare(this.sql);
    const rows = stmt.all(...this.params).map((r: Record<string, unknown>) => toPlainObject<T>(r));
    return {
      results: rows,
      success: true,
      meta: {
        duration: 0,
        size_after: 0,
        rows_read: rows.length,
        rows_written: 0,
        last_row_id: 0,
        changed_db: false,
        changes: 0,
        served_by: 'node-sqlite',
      },
    };
  }

  raw<T = unknown[]>(options: { columnNames: true }): Promise<[string[], ...T[]]>;
  raw<T = unknown[]>(options?: { columnNames?: false }): Promise<T[]>;
  async raw<T = unknown[]>(options?: {
    columnNames?: boolean;
  }): Promise<T[] | [string[], ...T[]]> {
    const stmt = this.db.prepare(this.sql);
    const rows = stmt
      .all(...this.params)
      .map((r: Record<string, unknown>) => toPlainObject<Record<string, unknown>>(r));
    if (rows.length === 0) {
      return options?.columnNames ? ([[]] as unknown as [string[], ...T[]]) : [];
    }
    const cols = Object.keys(rows[0]);
    const values = rows.map((r: Record<string, unknown>) => cols.map((c) => r[c])) as unknown as T[];
    if (options?.columnNames) {
      return [cols, ...values] as [string[], ...T[]];
    }
    return values;
  }
}

export class SqliteD1Mock implements D1Database {
  public readonly sqlite: DatabaseSync;

  constructor(applyMigrations = true) {
    this.sqlite = new DatabaseSync(':memory:');
    this.sqlite.exec('PRAGMA foreign_keys = ON;');
    if (applyMigrations) {
      const sql = readFileSync(INIT_MIGRATION_PATH, 'utf8');
      this.sqlite.exec(sql);
    }
  }

  prepare(query: string): D1PreparedStatement {
    return new SqliteD1PreparedStatement(this.sqlite, query);
  }

  async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    const results: D1Result<T>[] = [];
    for (const stmt of statements) {
      results.push(await stmt.all<T>());
    }
    return results;
  }

  async exec(query: string): Promise<D1ExecResult> {
    this.sqlite.exec(query);
    return { count: 1, duration: 0 };
  }

  async dump(): Promise<ArrayBuffer> {
    return new ArrayBuffer(0);
  }

  withSession(): D1DatabaseSession {
    throw new Error('withSession not implemented in test mock');
  }
}

interface StoredR2Entry {
  key: string;
  data: Uint8Array;
  httpMetadata?: R2HTTPMetadata;
  customMetadata?: Record<string, string>;
  uploaded: Date;
  etag: string;
}

export class MemoryR2BucketMock implements R2Bucket {
  public readonly store = new Map<string, StoredR2Entry>();

  private toBytes(
    value: ReadableStream | ArrayBuffer | ArrayBufferView | string | null | Blob
  ): Promise<Uint8Array> {
    if (value === null) return Promise.resolve(new Uint8Array(0));
    if (typeof value === 'string') return Promise.resolve(new TextEncoder().encode(value));
    if (value instanceof ArrayBuffer) return Promise.resolve(new Uint8Array(value));
    if (ArrayBuffer.isView(value)) {
      return Promise.resolve(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
    }
    if (typeof (value as Blob).arrayBuffer === 'function') {
      return (value as Blob).arrayBuffer().then((buf) => new Uint8Array(buf));
    }
    return new Response(value).arrayBuffer().then((buf) => new Uint8Array(buf));
  }

  private buildObject(entry: StoredR2Entry): R2ObjectBody {
    const bytes = entry.data;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      },
    });

    return {
      key: entry.key,
      version: 'v1',
      size: bytes.byteLength,
      etag: entry.etag,
      httpEtag: `"${entry.etag}"`,
      checksums: { toJSON: () => ({}) },
      uploaded: entry.uploaded,
      httpMetadata: entry.httpMetadata ?? {},
      customMetadata: entry.customMetadata ?? {},
      storageClass: 'Standard',
      body: stream,
      bodyUsed: false,
      writeHttpMetadata(headers: Headers) {
        if (entry.httpMetadata?.contentType) {
          headers.set('content-type', entry.httpMetadata.contentType);
        }
      },
      async arrayBuffer() {
        return bytes.slice().buffer;
      },
      async bytes() {
        return bytes.slice();
      },
      async text() {
        return new TextDecoder().decode(bytes);
      },
      async json<T>() {
        return JSON.parse(new TextDecoder().decode(bytes)) as T;
      },
      async blob() {
        return new Blob([bytes.slice()]);
      },
    } as R2ObjectBody;
  }

  async put(
    key: string,
    value: ReadableStream | ArrayBuffer | ArrayBufferView | string | null | Blob,
    options?: R2PutOptions
  ): Promise<R2Object> {
    const data = await this.toBytes(value);
    const entry: StoredR2Entry = {
      key,
      data,
      httpMetadata:
        options?.httpMetadata instanceof Headers
          ? { contentType: options.httpMetadata.get('content-type') ?? undefined }
          : options?.httpMetadata,
      customMetadata: options?.customMetadata,
      uploaded: new Date(),
      etag: `etag-${key}-${data.byteLength}`,
    };
    this.store.set(key, entry);
    return this.buildObject(entry);
  }

  async get(key: string): Promise<R2ObjectBody | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    return this.buildObject(entry);
  }

  async head(key: string): Promise<R2Object | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    return this.buildObject(entry);
  }

  async delete(keys: string | string[]): Promise<void> {
    const list = Array.isArray(keys) ? keys : [keys];
    for (const k of list) {
      this.store.delete(k);
    }
  }

  async list(options?: R2ListOptions): Promise<R2Objects> {
    const prefix = options?.prefix ?? '';
    const objects = Array.from(this.store.values())
      .filter((e) => e.key.startsWith(prefix))
      .map((e) => this.buildObject(e));
    return {
      objects,
      truncated: false,
      delimitedPrefixes: [],
    };
  }

  createMultipartUpload(): Promise<R2MultipartUpload> {
    throw new Error('Multipart upload not implemented in test mock');
  }

  resumeMultipartUpload(): R2MultipartUpload {
    throw new Error('Multipart upload not implemented in test mock');
  }
}

export function createTestEnv(overrides: Partial<Env> = {}): Env & {
  DB: SqliteD1Mock;
  EVIDENCE_BUCKET: MemoryR2BucketMock;
} {
  const db = new SqliteD1Mock(true);
  const bucket = new MemoryR2BucketMock();
  return {
    DB: db,
    EVIDENCE_BUCKET: bucket,
    ALLOWED_ORIGINS: 'http://localhost:5173,http://127.0.0.1:5173',
    ENABLE_DEMO_TOOLS: 'true',
    ENVIRONMENT: 'development',
    CONTROL_PLANE_ENV: 'development',
    VEKTOR81_DEV_API_KEY: 'test-mssp-dev-key',
    ...overrides,
  } as Env & { DB: SqliteD1Mock; EVIDENCE_BUCKET: MemoryR2BucketMock };
}
