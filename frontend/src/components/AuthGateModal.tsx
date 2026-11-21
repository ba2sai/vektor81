import React, { useState } from 'react';
import { ShieldCheck, KeyRound, Eye, EyeOff, AlertCircle, X } from 'lucide-react';

interface AuthGateModalProps {
  isOpen: boolean;
  initialToken: string;
  errorMessage?: string | null;
  canClose?: boolean;
  onSubmitToken: (token: string) => void;
  onClose?: () => void;
}

export function AuthGateModal({
  isOpen,
  initialToken,
  errorMessage,
  canClose = false,
  onSubmitToken,
  onClose,
}: AuthGateModalProps) {
  const [tokenInput, setTokenInput] = useState(initialToken);
  const [showToken, setShowToken] = useState(false);

  if (!isOpen) return null;

  const isDevEnv = Boolean(import.meta.env.DEV);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cleaned = tokenInput.trim();
    if (!cleaned) return;
    onSubmitToken(cleaned);
  };

  const handleFillLocalDevToken = () => {
    if (!isDevEnv) return;
    const devToken =
      (import.meta.env.VITE_DEV_API_TOKEN as string | undefined) || 'vektor81-local-dev-token';
    setTokenInput(devToken);
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="auth-gate-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/85 p-4 backdrop-blur-md"
    >
      <div className="w-full max-w-md rounded-2xl border border-slate-700/80 bg-slate-900 p-6 shadow-2xl shadow-black/70">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-sky-500/40 bg-sky-500/15 text-sky-400">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <h2 id="auth-gate-title" className="text-base font-bold text-white">
                SOC / CISO Authentication Gate
              </h2>
              <p className="text-xs text-slate-400">
                Vektor81 Control Plane · Bearer API Token
              </p>
            </div>
          </div>
          {canClose && onClose && (
            <button
              type="button"
              onClick={onClose}
              aria-label="Cerrar autenticación"
              className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>

        <p className="mt-4 text-xs leading-relaxed text-slate-300">
          Ingresa tu Bearer Token (<code className="text-sky-300">MSSP_ADMIN</code>,{' '}
          <code className="text-sky-300">CISO</code>, <code className="text-sky-300">DPO</code> o{' '}
          <code className="text-sky-300">AUDITOR</code>). El token se guarda únicamente en{' '}
          <code className="text-slate-200">sessionStorage</code> para esta sesión.
        </p>

        {errorMessage && (
          <div
            role="alert"
            className="mt-4 flex items-start gap-2 rounded-lg border border-red-500/40 bg-red-950/50 p-3 text-xs text-red-200"
          >
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
            <span>{errorMessage}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="mt-4 space-y-4">
          <div>
            <label
              htmlFor="vektor81-api-token-input"
              className="mb-1.5 block text-xs font-medium text-slate-300"
            >
              API Token (Authorization: Bearer)
            </label>
            <div className="relative">
              <KeyRound className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                id="vektor81-api-token-input"
                type={showToken ? 'text' : 'password'}
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder="v81_live_..."
                required
                autoFocus
                className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-9 pr-10 text-xs font-mono text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setShowToken((prev) => !prev)}
                aria-label={showToken ? 'Ocultar token' : 'Mostrar token'}
                className="absolute right-2.5 top-2 text-slate-400 hover:text-slate-200"
              >
                {showToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>

          {isDevEnv && (
            <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2">
              <span className="text-[11px] text-slate-400">
                Modo Desarrollo Local detectado
              </span>
              <button
                type="button"
                onClick={handleFillLocalDevToken}
                className="rounded-md border border-sky-500/40 bg-sky-500/10 px-2.5 py-1 text-[11px] font-medium text-sky-300 hover:bg-sky-500/20"
              >
                Local Dev Token
              </button>
            </div>
          )}

          <button
            type="submit"
            disabled={!tokenInput.trim()}
            className="w-full rounded-lg bg-sky-600 px-4 py-2.5 text-xs font-semibold text-white shadow-lg shadow-sky-900/30 transition hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Autenticar y Conectar
          </button>
        </form>
      </div>
    </div>
  );
}
