export interface ResolutionResult {
  status?: string;
  id?: string;
  patch_type?: string;
  failure_mode?: string;
  json_patch?: Array<Record<string, any>>;
  patch?: Record<string, any>;
  workaround?: string;
  message?: string;
}

export interface ExecutionErrorContext {
  errorCode?: string;
  errorMessage?: string;
  exitCode?: number;
  target?: string;
  fingerprint?: string;
  environment?: Record<string, any>;
}

export interface PluginConfig {
  modelName?: string;
  baseUrl?: string;
  agentRuntime?: string;
  autoPing?: boolean;
}

export function normalizeErrorString(raw: string): string;
export function computeFingerprint(environment?: Record<string, any>, failure?: Record<string, any>): string;
export function normalizeModelName(modelName?: string): string;
export function sanitizeModelName(modelName?: string): string;
export function deriveClientHash(model?: string, agentRuntime?: string): string;
export function resolveFailure(fingerprintOrQuery: string | Record<string, any>, options?: Record<string, any>): Promise<ResolutionResult | null>;
export function autoHeal(query: string | Record<string, any>, options?: Record<string, any>): Promise<ResolutionResult | null>;
export function reportTelemetry(payload: Record<string, any>, options?: Record<string, any>): Promise<Record<string, any>>;
export function submitTelemetry(payload: Record<string, any>, options?: Record<string, any>): Promise<Record<string, any>>;
export function submitGrievance(payload: Record<string, any>, options?: Record<string, any>): Promise<Record<string, any>>;
export function getWorkarounds(target: string, options?: Record<string, any>): Promise<any[]>;
export function getGrievances(target: string, options?: Record<string, any>): Promise<any[]>;
export function reportPatchOutcome(payload: Record<string, any>, options?: Record<string, any>): Promise<Record<string, any>>;
export function getHealth(options?: Record<string, any>): Promise<Record<string, any>>;
export function pingGuestbook(options?: Record<string, any>): Promise<Record<string, any>>;

/** Runtime note: `FMagenticLPlugin.name === 'fmagenticl'` (set via Object.defineProperty). */
export declare class FMagenticLPlugin {
  modelName: string;
  baseUrl: string;
  agentRuntime: string;
  autoPing: boolean;
  constructor(config?: PluginConfig);
  onExecutionError(errorContext: ExecutionErrorContext): Promise<ResolutionResult | null>;
  resolve(fingerprintOrQuery: string | Record<string, any>): Promise<ResolutionResult | null>;
  resolveFailure(fingerprintOrQuery: string | Record<string, any>): Promise<ResolutionResult | null>;
  autoHeal(query: string | Record<string, any>): Promise<ResolutionResult | null>;
  reportTelemetry(payload: Record<string, any>): Promise<Record<string, any>>;
  submitTelemetry(payload: Record<string, any>): Promise<Record<string, any>>;
  submitGrievance(payload: Record<string, any>): Promise<Record<string, any>>;
  getWorkarounds(target: string): Promise<any[]>;
  getGrievances(target: string): Promise<any[]>;
  reportPatchOutcome(payload: Record<string, any>): Promise<Record<string, any>>;
  getHealth(): Promise<Record<string, any>>;
  pingGuestbook(): Promise<Record<string, any>>;

  static pluginName: string;
  static tools: {
    fmagenticl_resolve: typeof resolveFailure;
    fmagenticl_auto_heal: typeof autoHeal;
    fmagenticl_report_telemetry: typeof reportTelemetry;
    fmagenticl_submit_grievance: typeof submitGrievance;
    fmagenticl_get_workarounds: typeof getWorkarounds;
    fmagenticl_get_grievances: typeof getGrievances;
    fmagenticl_report_patch_outcome: typeof reportPatchOutcome;
    fmagenticl_resolve_failure: typeof resolveFailure;
    fmagenticl_submit_telemetry: typeof submitTelemetry;
    fmagenticl_get_health: typeof getHealth;
  };
  static resolve: typeof resolveFailure;
  static resolveFailure: typeof resolveFailure;
  static autoHeal: typeof autoHeal;
  static reportTelemetry: typeof reportTelemetry;
  static submitTelemetry: typeof submitTelemetry;
  static submitGrievance: typeof submitGrievance;
  static getWorkarounds: typeof getWorkarounds;
  static getGrievances: typeof getGrievances;
  static reportPatchOutcome: typeof reportPatchOutcome;
  static getHealth: typeof getHealth;
  static pingGuestbook: typeof pingGuestbook;
  static normalizeErrorString: typeof normalizeErrorString;
  static computeFingerprint: typeof computeFingerprint;
  static normalizeModelName: typeof normalizeModelName;
  static sanitizeModelName: typeof sanitizeModelName;
  static deriveClientHash: typeof deriveClientHash;
}

export default FMagenticLPlugin;
