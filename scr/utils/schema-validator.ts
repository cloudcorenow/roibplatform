import { D1Database } from '@cloudflare/workers-types';
import { TABLE_PHI_FIELDS, PHI_BEARING_TABLES, getTablePHIFields } from '../types/phi-registry';

export interface SchemaValidationResult {
  valid: boolean;
  warnings: string[];
  errors: string[];
  missingTables: string[];
  missingFields: { table: string; field: string }[];
  unmappedPHIFields: { table: string; field: string }[];
}

const KNOWN_PHI_COLUMN_PATTERNS = [
  /ssn/i,
  /social_security/i,
  /date_of_birth/i,
  /dob/i,
  /phone/i,
  /email/i,
  /address/i,
  /medical_record/i,
  /diagnosis/i,
  /treatment/i,
  /prescription/i,
  /insurance/i,
  /client_name/i,
  /patient/i,
  /health/i,
  /^notes$/i,
  /^description$/i,
  /^results$/i,
  /^responses$/i
];

function isPotentialPHIField(columnName: string): boolean {
  return KNOWN_PHI_COLUMN_PATTERNS.some(pattern => pattern.test(columnName));
}

export async function validateTablePHIFieldMapping(
  db: D1Database
): Promise<SchemaValidationResult> {
  const result: SchemaValidationResult = {
    valid: true,
    warnings: [],
    errors: [],
    missingTables: [],
    missingFields: [],
    unmappedPHIFields: []
  };

  for (const tableName of PHI_BEARING_TABLES) {
    try {
      const tableInfo = await db.prepare(
        `PRAGMA table_info(${tableName})`
      ).all();

      if (!tableInfo.results || tableInfo.results.length === 0) {
        result.missingTables.push(tableName);
        result.errors.push(
          `Table '${tableName}' is declared as PHI-bearing but does not exist in schema`
        );
        result.valid = false;
        continue;
      }

      const actualColumns = tableInfo.results.map((col: any) => col.name.toLowerCase());
      const declaredPHIFields = getTablePHIFields(tableName).map(f => f.toLowerCase());

      for (const phiField of declaredPHIFields) {
        if (!actualColumns.includes(phiField)) {
          result.missingFields.push({ table: tableName, field: phiField });
          result.warnings.push(
            `PHI field '${phiField}' declared for table '${tableName}' but column does not exist in schema`
          );
        }
      }

      for (const columnName of actualColumns) {
        if (isPotentialPHIField(columnName) && !declaredPHIFields.includes(columnName)) {
          result.unmappedPHIFields.push({ table: tableName, field: columnName });
          result.warnings.push(
            `Column '${columnName}' in table '${tableName}' looks like PHI but is not declared in TABLE_PHI_FIELDS`
          );
        }
      }
    } catch (error) {
      result.errors.push(
        `Failed to validate table '${tableName}': ${error instanceof Error ? error.message : String(error)}`
      );
      result.valid = false;
    }
  }

  if (result.errors.length > 0) {
    result.valid = false;
  }

  return result;
}

export async function logSchemaValidation(
  db: D1Database,
  logger: Console = console
): Promise<void> {
  logger.log('[HIPAA] Validating TABLE_PHI_FIELDS against database schema...');

  const validation = await validateTablePHIFieldMapping(db);

  if (validation.valid && validation.warnings.length === 0) {
    logger.log('[HIPAA] ✅ Schema validation passed - all PHI fields properly mapped');
    return;
  }

  if (validation.errors.length > 0) {
    logger.error('[HIPAA] ❌ CRITICAL: Schema validation failed!');
    for (const error of validation.errors) {
      logger.error(`  - ${error}`);
    }
  }

  if (validation.warnings.length > 0) {
    logger.warn('[HIPAA] ⚠️  Schema validation warnings:');
    for (const warning of validation.warnings) {
      logger.warn(`  - ${warning}`);
    }
  }

  if (validation.missingTables.length > 0) {
    logger.error('[HIPAA] Missing tables:', validation.missingTables);
  }

  if (validation.unmappedPHIFields.length > 0) {
    logger.warn(
      '[HIPAA] ⚠️  Found potential PHI fields not declared in TABLE_PHI_FIELDS:',
      validation.unmappedPHIFields
    );
    logger.warn('[HIPAA] Please review and add these to src/types/phi-registry.ts if they contain PHI');
  }

  if (!validation.valid) {
    throw new Error(
      'HIPAA schema validation failed! TABLE_PHI_FIELDS does not match database schema. ' +
      'This creates a security risk where PHI fields may be unprotected. ' +
      'See logs above for details.'
    );
  }
}

export function generatePHIFieldMappingFromSchema(
  schemaResults: Record<string, any[]>
): string {
  const mappings: Record<string, string[]> = {};

  for (const [tableName, columns] of Object.entries(schemaResults)) {
    if (!PHI_BEARING_TABLES.includes(tableName as any)) {
      continue;
    }

    const phiFields: string[] = [];

    for (const col of columns) {
      const columnName = col.name;
      if (isPotentialPHIField(columnName)) {
        phiFields.push(columnName);
      }
    }

    if (phiFields.length > 0) {
      mappings[tableName] = phiFields;
    }
  }

  const tsCode = `export const TABLE_PHI_FIELDS: Record<string, PHIField[]> = {\n${
    Object.entries(mappings)
      .map(([table, fields]) =>
        `  ${table}: [${fields.map(f => `'${f}'`).join(', ')}],`
      )
      .join('\n')
  }\n};`;

  return tsCode;
}
