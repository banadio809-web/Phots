-- Applied to project ref ogqsngiqokpevjwkzoei (project name: buggy).
create table public.wp_plugin_catalog (
  slug text primary key,
  name text not null default '',
  version text not null,
  active_installs integer not null default 0 check (active_installs >= 0),
  plugin_url text,
  metadata jsonb not null default '{}'::jsonb,
  last_seen_at timestamptz not null default now()
);

create table public.wp_scan_runs (
  id uuid primary key,
  status text not null check (status in ('running', 'completed', 'failed')),
  started_at timestamptz not null default now(),
  completed_at timestamptz,
  catalog_count integer not null default 0 check (catalog_count >= 0),
  scanned_plugins integer not null default 0 check (scanned_plugins >= 0),
  failed_plugins integer not null default 0 check (failed_plugins >= 0),
  signal_count integer not null default 0 check (signal_count >= 0),
  alert_count integer not null default 0 check (alert_count >= 0),
  engine_version text not null default '0.1.0'
);

create table public.wp_scan_signals (
  run_id uuid not null references public.wp_scan_runs(id) on delete cascade,
  signal_id text not null,
  plugin_slug text not null references public.wp_plugin_catalog(slug),
  plugin_version text not null,
  file_path text not null,
  line_number integer not null check (line_number > 0),
  rule_id text not null,
  language text not null default 'php',
  engine text not null default 'heuristic',
  class_hint text,
  confidence text not null,
  excerpt text not null default '',
  signal text not null,
  scope_decision jsonb not null default '{}'::jsonb,
  priority text not null default 'UNCLASSIFIED',
  created_at timestamptz not null default now(),
  primary key (run_id, signal_id)
);

create table public.wp_scope_reviews (
  signal_id text primary key,
  plugin_slug text not null references public.wp_plugin_catalog(slug),
  plugin_version text not null,
  review jsonb not null,
  scope_decision jsonb not null,
  updated_at timestamptz not null default now()
);

create index wp_scan_signals_plugin_idx
  on public.wp_scan_signals (plugin_slug, plugin_version);
create index wp_scan_signals_decision_idx
  on public.wp_scan_signals ((scope_decision ->> 'decision'));
create index wp_scan_runs_started_idx on public.wp_scan_runs (started_at desc);
create index wp_scope_reviews_plugin_idx on public.wp_scope_reviews (plugin_slug);

alter table public.wp_plugin_catalog enable row level security;
alter table public.wp_scan_runs enable row level security;
alter table public.wp_scan_signals enable row level security;
alter table public.wp_scope_reviews enable row level security;

revoke all on public.wp_plugin_catalog, public.wp_scan_runs,
  public.wp_scan_signals, public.wp_scope_reviews from public, anon, authenticated;
grant usage on schema public to service_role;
grant select, insert, update on public.wp_plugin_catalog, public.wp_scan_runs,
  public.wp_scan_signals, public.wp_scope_reviews to service_role;
