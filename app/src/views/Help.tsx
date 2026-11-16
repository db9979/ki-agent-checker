import { ExternalLink, Play, Rocket } from "lucide-react";
import { Children, isValidElement, useRef, type ReactNode } from "react";
import Markdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import doc from "../../../docs/ANLEITUNG.md?raw";
import { openOnboarding } from "../lib/onboarding";
import { openLink } from "../lib/open";

const REPO_DOC = "https://github.com/db9979/ki-agent-checker/blob/main/docs/ANLEITUNG.md";

/** Gleiche Anker wie GitHub, damit Links wie #promptfoo in App und Repo funktionieren. */
export function slug(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .trim()
    .replace(/\s+/g, "-");
}

function plain(node: ReactNode): string {
  return Children.toArray(node)
    .map((c) => (typeof c === "string" || typeof c === "number" ? String(c) : isValidElement(c) ? plain((c.props as { children?: ReactNode }).children) : ""))
    .join("");
}

const TOC = doc
  .split("\n")
  .filter((l) => l.startsWith("## "))
  .map((l) => l.slice(3).trim());

export function Help({ onStartDemo }: { onStartDemo: () => void }) {
  const box = useRef<HTMLDivElement>(null);
  const jump = (id: string) =>
    box.current?.querySelector(`#${CSS.escape(id)}`)?.scrollIntoView({ behavior: "smooth", block: "start" });

  const components: Components = {
    h1: () => null,
    h2: ({ children }) => (
      <h2 id={slug(plain(children))} className="mt-8 scroll-mt-4 border-b border-line pb-2 text-lg font-semibold text-cyan first:mt-0">
        {children}
      </h2>
    ),
    h3: ({ children }) => (
      <h3 id={slug(plain(children))} className="mt-5 scroll-mt-4 text-sm font-semibold text-text">
        {children}
      </h3>
    ),
    p: ({ children }) => <p className="my-2 text-sm leading-relaxed text-text/90">{children}</p>,
    ul: ({ children }) => <ul className="my-2 list-disc space-y-1 pl-5 text-sm text-text/90">{children}</ul>,
    ol: ({ children }) => <ol className="my-2 list-decimal space-y-1 pl-5 text-sm text-text/90">{children}</ol>,
    blockquote: ({ children }) => (
      <div className="my-3 rounded-lg border border-amber/40 bg-amber/5 px-4 py-1 text-amber [&_p]:text-amber">{children}</div>
    ),
    table: ({ children }) => (
      <div className="my-3 overflow-x-auto rounded-lg border border-line">
        <table className="w-full text-left text-xs">{children}</table>
      </div>
    ),
    th: ({ children }) => <th className="bg-panel-2 px-3 py-2 font-semibold text-muted">{children}</th>,
    td: ({ children }) => <td className="border-t border-line px-3 py-2 align-top">{children}</td>,
    pre: ({ children }) => (
      <pre className="my-3 overflow-x-auto rounded-lg border border-line bg-[#060912] p-3 font-mono text-xs text-green [&_code]:bg-transparent [&_code]:p-0 [&_code]:text-green">
        {children}
      </pre>
    ),
    code: ({ children }) => (
      <code className="rounded bg-[#0b1222] px-1 py-0.5 font-mono text-[0.85em] text-cyan">{children}</code>
    ),
    a: ({ href, children }) => (
      <a
        href={href}
        onClick={(e) => {
          e.preventDefault();
          if (href?.startsWith("#")) jump(href.slice(1));
          else if (href?.startsWith("http")) openLink(href);
          else if (href) openLink(`https://github.com/db9979/ki-agent-checker/blob/main/${href.replace(/^\.?\/?/, "")}`);
        }}
        className="cursor-pointer text-cyan underline decoration-cyan/40 underline-offset-2 hover:decoration-cyan"
      >
        {children}
      </a>
    ),
  };

  return (
    <div className="flex h-full flex-col gap-4">
      <header className="flex shrink-0 flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Hilfe</h1>
          <p className="text-sm text-muted">Anleitung zum Einrichten, Testen und Auswerten</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => openOnboarding(true)}
            className="glow-cyan flex items-center gap-2 rounded-xl bg-cyan/15 px-4 py-2 text-sm font-medium text-cyan transition hover:bg-cyan/25"
          >
            <Rocket size={16} /> Einrichtung starten
          </button>
          <button
            onClick={onStartDemo}
            className="flex items-center gap-2 rounded-xl border border-line px-4 py-2 text-sm text-muted transition hover:text-text"
          >
            <Play size={15} /> Demo-Lauf ansehen
          </button>
          <button
            onClick={() => openLink(REPO_DOC)}
            className="flex items-center gap-2 rounded-xl border border-line px-4 py-2 text-sm text-muted transition hover:text-text"
            title="Anleitung auf GitHub öffnen"
          >
            <ExternalLink size={15} /> GitHub
          </button>
        </div>
      </header>
      <div className="flex min-h-0 flex-1 gap-4">
        <nav className="panel hidden w-56 shrink-0 overflow-y-auto p-3 lg:block">
          <div className="mb-2 px-2 text-[10px] uppercase tracking-[0.18em] text-muted">Inhalt</div>
          {TOC.map((t) => (
            <button
              key={t}
              onClick={() => jump(slug(t))}
              className="block w-full truncate rounded-md px-2 py-1.5 text-left text-xs text-muted transition hover:bg-panel-2 hover:text-text"
            >
              {t}
            </button>
          ))}
        </nav>
        <div ref={box} className="panel min-h-0 flex-1 overflow-y-auto px-6 py-5">
          <div className="max-w-3xl">
            <Markdown remarkPlugins={[remarkGfm]} components={components}>
              {doc}
            </Markdown>
          </div>
        </div>
      </div>
    </div>
  );
}
