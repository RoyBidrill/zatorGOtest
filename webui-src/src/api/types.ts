export interface ClientScopeDiagnostics {
  mode?: string
  mask?: number | string
  shift?: number
  max_scope?: number
  scoped_lock_count?: number
  conflicts?: number
  last_seen_scope?: string
  fallback_reason?: string
}

export interface ProfileInfo {
  profile: string | number
  label: string
  description?: string
  current_lock?: string
  max_strategy?: number
  is_fallback?: boolean
  fallback_enabled?: boolean
  is_udp_games?: boolean
  udp_games_enabled?: boolean
  is_dns_desync?: boolean
  dns_desync_enabled?: boolean
}

export interface HealthPayload {
  overall?: string
  zapret2_running?: boolean
  want_running?: boolean
  watchdog?: boolean
  webui_watchdog?: boolean
  fw_hook_present?: boolean
  fw_ensure?: string
  args_present?: boolean
  post_update_verify?: string
  service_warnings?: number
}

export interface StatusPayload {
  zapret2_running?: boolean
  nfqws_want_running?: boolean
  nfqws_watchdog?: boolean
  strategy_locks_status?: string
  auto_mode?: string
  hostlist_mode?: string
  fwtype?: string
  flowoffload?: string
  tls_blob_mode?: string
  wireguard?: string
  rst_guard?: string
  reasm?: string
  provider?: string
  client_scope?: ClientScopeDiagnostics
  profiles?: ProfileInfo[]
  health?: HealthPayload
  service_warnings?: string[]
  args_present?: boolean
  fw_hook_present?: boolean
  pre_update_backup?: string
  post_update_verify?: string
  post_update_verify_detail?: string
  block_full_restore?: boolean
}

export interface ScopesPayload {
  enabled?: boolean
  warning?: string
  scopes?: string[]
  mask?: string | number
  shift?: number
  max_scope?: number
  mode?: string
}

export interface ClientScopeMapping {
  scope: string
  ip: string
}

export interface ClientScopeMappingsPayload {
  mappings: ClientScopeMapping[]
  max_scope: number
}

export interface CheckDetail {
  text?: string
  state?: string
}

export interface QUICProbeResult {
  offset: number
  count: number
  state: string
  reason: string
  http_code: number
  http_version: string
  bytes: number
  ttfb?: string
  total?: string
  speed?: string
}

export interface QUICProbeSummary {
  ok_count: number
  total_probes: number
  rounds: number
  reason?: string
  details?: QUICProbeResult[]
}

export interface CheckItem {
  label?: string
  target?: string
  verdict?: string
  text?: string
  tls12?: boolean
  tls13?: boolean
  tls12_detail?: CheckDetail
  tls13_detail?: CheckDetail
  download?: CheckDetail
  quic?: QUICProbeSummary
  media?: {
    class?: string
    text?: string
    video_id?: string
    host?: string
    audio_host?: string
    audio_bytes?: number
    video_range_bytes?: number
    video_middle_bytes?: number
    size_16k?: number
    size_64k?: number
    resolver_status?: string
  }
}

export interface CheckPayload {
  results?: CheckItem[]
  message?: string
  profile?: number
  scope?: string
  lock?: string
  zapret2_running?: boolean
  waited_apply?: boolean
  applied?: boolean
  retried?: boolean
}

export interface LockResult {
  ok?: boolean
  previous?: string
  lock?: string
  changed?: boolean
  scope?: string
  profile?: number
  warning?: string
}

export interface TlsBlobSettings {
  current_mode?: string
  current_blob?: string
  available_blobs?: string[]
  quic_blobs?: string[]
  // «профиль -> значение»: "" = как глобальный, fake_default_tls | файл слота
  profile_blobs?: Record<string, string>
  // «профиль -> режим фейков»: classic | clone (нет строки = classic)
  profile_modes?: Record<string, string>
  // «профиль -> SNI клона»: "" = невинный дефолт (www.google.com)
  profile_snis?: Record<string, string>
  // «профиль -> лимит клонов в байтах»: "" = без ограничения (граница ТСПУ 1200)
  profile_sizes?: Record<string, string>
  global_clone_size?: string
}

export interface WgBlobSettings {
  current_blob?: string
  current_repeats?: string
  available_blobs?: string[]
}

export interface WgStateSettings {
  enabled?: boolean
}

export interface FallbackSettings {
  state?: string
  enabled?: boolean
}

export interface UdpGamesSettings {
  enabled?: boolean
  ports?: string
}

export interface WssizeRampSettings {
  enabled: boolean
  mode: 'full' | 'lite'
  scale: number
  googlevideo_ips: number
  googlevideo_ipv4_fresh?: boolean
  googlevideo_generated?: string
  googlevideo_feed_enabled?: boolean
  googlevideo_hosts?: number
  googlevideo_local_ips?: number
  googlevideo_local_collection: 'enabled' | 'disabled' | 'unsupported'
}

export interface ModeSettingData {
  enabled?: boolean
  auto?: boolean
  lua_available?: boolean
}

export interface PortInfo {
  full?: string
  user?: string[]
  base?: string
}

export interface PortsSettings {
  tcp?: PortInfo
  udp?: PortInfo
}

export interface RecommendationProfile {
  samples: number
  top: { strategy: number; success_pct: number; samples: number; mode: 'classic' | 'clone' | 'mixed' }[]
  clone_recommended: boolean
  classic_pct: number | null
  clone_pct: number | null
}

export interface Recommendations {
  provider: string
  samples: number
  minimum: 10
  generated_at: number
  status: 'ready' | 'insufficient' | 'unavailable' | 'unknown_provider' | 'stale'
  profiles: Record<string, RecommendationProfile>
}

export interface SupersweepPayload {
  available: boolean
  state: 'idle' | 'starting' | 'running' | 'applying' | 'done' | 'cancelled' | 'interrupted'
  active: boolean
  source: 'none' | 'live' | 'saved'
  started: number
  updated: number
  scope: string
  phase: string
  completed: number
  total: number
  error?: string
  workers: {
    name: string
    label: string
    profile: number
    completed: number
    total: number
    ok: number
    warn: number
    fail: number
    current_strategy: number | null
    current_target: string
    greens: string
    warns: string
    applied: string
  }[]
  applied: { kind: 'profile' | 'domain'; target: string; strategy: number }[]
  domains: {
    domain: string
    best_strategy: number | null
    verdict: 'ok' | 'warn' | 'fail'
    applied: number | null
  }[]
}

export interface ProviderSettings {
  provider?: string
}

export interface BackupItem {
  name: string
  date?: string
  size?: number
}

export interface BackupsPayload {
  items?: BackupItem[]
}

export interface DomainItem {
  value: string
  strategy?: number
  ip?: string
  observed_at?: number
  source?: string
}

export interface GooglevideoAutoLock {
  host: string
  strategy: number
  scope?: string
  askey?: string
  /** seed = фоновый TLS-пробой; learned = живой circular_quality */
  source?: 'seed' | 'learned' | string
}

export interface GooglevideoSeedStatus {
  state?: string
  host_key?: string
  strategy?: number
  last_host?: string
  last_strategy?: number
  last_result?: string
  last_error?: string
  updated_at?: number
  pending?: number
}

export interface DomainsListPayload {
  title?: string
  description?: string
  items?: DomainItem[]
  is_custom_rkn?: boolean
  max_strategy?: number
  collection?: string
  /** Per-SNI (sn-*) auto-locks for profile 2 */
  auto_locks?: GooglevideoAutoLock[]
  seed?: GooglevideoSeedStatus
}

export interface ApplyResult {
  restarted?: boolean
  restart_required?: boolean
  apply_required?: boolean
  id?: number
  moved?: number
  dropped?: number
  added?: number
  skipped?: string
  name?: string
  provider?: string
  duplicate?: boolean
  check?: CheckPayload
}

export interface UpdateCheckResult {
  update_available: boolean
  release?: string
  latest_zator_date?: string
  latest_webui_date?: string
  checked_at?: string
  error?: string
}

export interface DomainsImportResult {
  added?: number
  duplicates?: number
  skipped?: number
}

export interface VersionInfo {
  zapret2_version: string
  zapret2_source?: 'fork' | 'official' | ''
  zapret2_arch?: string
  zator_version: string
  zator_date: string
  webui_version: string
  webui_date: string
  tracking: string
  update_available: boolean
  latest_release: string
  latest_zator_date: string
  latest_webui_date: string
  config_date: string
  config_default_date: string
  config_update_pending: boolean
}

export interface ValueSetting {
  state?: string
  value?: string
}

export interface IfaceInfo {
  name: string
  up?: boolean
  addrs?: string[]
  kind?: string
}

export interface IfacesSettings {
  wan?: string
  lan?: string
  wan6?: string
  suggested?: { wan?: string; lan?: string; source?: string }
  available?: IfaceInfo[]
  needs_autodetect?: boolean
}

export interface TelemetrySettings {
  decided: boolean
  enabled: boolean
  configured: boolean
}

export interface StatePayload {
  auth_required?: boolean
  status: StatusPayload
  version: VersionInfo
  scopes: ScopesPayload
  tls_blob: TlsBlobSettings
  wg_blob: WgBlobSettings
  wg_state: WgStateSettings
  fallback: FallbackSettings
  udp_games: UdpGamesSettings
  wssize_ramp: WssizeRampSettings
  auto_mode: ModeSettingData
  hostlist: ModeSettingData
  rst_guard: ModeSettingData
  reasm: ModeSettingData
  dns_desync: ModeSettingData
  ports: PortsSettings
  provider: ProviderSettings
  telemetry: TelemetrySettings
  fwtype?: ValueSetting
  flowoffload?: ValueSetting
  ifaces?: IfacesSettings
  client_scope?: ScopesPayload
  nfqws2_errors?: { available?: boolean; content?: string; path?: string; lines?: number; suppressed_conntrack?: number }
  backups: BackupsPayload
}

export interface H3CurlStatus {
  found?: boolean
  path?: string
  arch?: string
  managed?: boolean
}

export interface CustomBlockInfo {
  block: string
  label: string
  profiles: string
  transport: 'tcp' | 'udp' | 'both' | string
}

export interface CustomStrategy {
  id: number
  block: string
  spec: string
  enabled: boolean
  comment: string
  assigned: string
}

export interface CustomListPayload {
  blocks?: CustomBlockInfo[]
  strategies?: CustomStrategy[]
}

export interface CustomImportResult {
  added?: number
  dups?: number
  skipped?: number
  failed?: number
  errors?: { line: string; reason: string }[]
  notes?: string[]
  total?: number
  limit?: number
  apply_required?: boolean
}

export interface CustomBlobInfo {
  id: number
  name: string
  file: string
  comment: string
  refs: number
}

export interface SniProfileInfo {
  id: string
  title: string
  pin?: string
  pool?: string
  set?: string
  policy?: string
  effective?: string[]
}

export interface SniSetInfo {
  name: string
  origin: 'user' | 'zator'
  domains: string[]
}

export interface SniState {
  profiles?: SniProfileInfo[]
  sets?: SniSetInfo[]
}

export interface CustomBlobsPayload {
  dir?: string
  blobs?: CustomBlobInfo[]
  files?: string[]
  stock?: string[]
  config_dirty?: boolean
  sni?: SniState | null
}

export interface ZapretRelease {
  source: 'fork' | 'official'
  version: string
  tag: string
  name?: string
  published_at?: string
  prerelease?: boolean
  url?: string
}

export interface ZapretReleasesPayload {
  installed: {
    version: string
    source: 'fork' | 'official' | ''
    arch: string
  }
  platform_arch?: string
  embedded?: boolean
  default_source?: 'fork' | 'official'
  fork: ZapretRelease[]
  official: ZapretRelease[]
  errors?: Record<string, string>
  checked_at?: string
  cached?: boolean
}

export interface ZapretSwitchResult {
  ok: boolean
  version: string
  source: 'fork' | 'official'
  arch: string
  skipped?: boolean
  restarted?: boolean
}
