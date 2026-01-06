export function createCorsHeaders(origin: string, allowedOrigins: string[]) {
  const isAllowed = allowedOrigins.includes(origin);

  return {
    'Access-Control-Allow-Origin': isAllowed ? origin : allowedOrigins[0],
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Tenant-ID',
    'Access-Control-Max-Age': '86400',
    'Access-Control-Allow-Credentials': 'true'
  };
}

export function handlePreflight(origin: string, allowedOrigins: string[]) {
  const headers = createCorsHeaders(origin, allowedOrigins);

  return new Response(null, {
    status: 204,
    headers
  });
}
