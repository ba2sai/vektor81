interface ImportMeta {
  url: string;
}

declare module 'node:fs' {
  export function readFileSync(path: string, encoding: 'utf8'): string;
}

declare module 'node:path' {
  export function dirname(p: string): string;
  export function resolve(...paths: string[]): string;
}

declare module 'node:url' {
  export function fileURLToPath(url: string): string;
}

declare module 'node:sqlite' {
  export type SQLInputValue = null | number | bigint | string | Uint8Array;
  export interface StatementResultingChanges {
    changes: number | bigint;
    lastInsertRowid: number | bigint;
  }
  export interface StatementSync {
    get(...anonymousParameters: SQLInputValue[]): Record<string, unknown> | undefined;
    all(...anonymousParameters: SQLInputValue[]): Array<Record<string, unknown>>;
    run(...anonymousParameters: SQLInputValue[]): StatementResultingChanges;
  }
  export class DatabaseSync {
    constructor(location: string);
    exec(sql: string): void;
    prepare(sql: string): StatementSync;
    close(): void;
  }
}
