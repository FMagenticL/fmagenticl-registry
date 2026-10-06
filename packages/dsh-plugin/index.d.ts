export interface ResolutionResult {
  status: string;
  patch?: Record<string, any>;
  message?: string;
}

export function resolveFailure(fingerprint: string): Promise<ResolutionResult | null>;
export function submitTelemetry(payload: Record<string, any>): Promise<Record<string, any>>;
export function submitGrievance(payload: Record<string, any>): Promise<Record<string, any>>;
export function getGrievances(target: string): Promise<any[]>;
export function getHealth(): Promise<Record<string, any>>;

declare const plugin: {
  name: string;
  tools: {
    fmagenticl_resolve_failure: typeof resolveFailure;
    fmagenticl_submit_telemetry: typeof submitTelemetry;
    fmagenticl_submit_grievance: typeof submitGrievance;
    fmagenticl_get_grievances: typeof getGrievances;
    fmagenticl_get_health: typeof getHealth;
  };
};

export default plugin;
export = plugin;
