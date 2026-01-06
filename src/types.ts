export interface Env {
  DB: D1Database;
  KV: KVNamespace;
  DOCUMENTS: R2Bucket;
  CENTRALREACH_API_KEY: string;
  CENTRALREACH_BASE_URL: string;
  CENTRALREACH_ORG_ID: string;
  QUICKBOOKS_CLIENT_ID: string;
  QUICKBOOKS_CLIENT_SECRET: string;
  JWT_SECRET: string;
  APP_ORIGIN: string;
  ENVIRONMENT: string;
}

export interface ContextVariables {
  user_id: string;
  user_role: string;
  user_email: string;
  user_type: 'tenant' | 'platform';
  tenant_id: string;
  read_only: boolean;
  user_ip: string;
}

export type HonoEnv = { Bindings: Env; Variables: ContextVariables };
