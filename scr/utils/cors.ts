export function withCors(response: Response, origin: string): Response {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Vary', 'Origin');
  return new Response(response.body, { 
    status: response.status, 
    statusText: response.statusText, 
    headers 
  });
}

export function createCorsHeaders(origin: string, allowedOrigins: string[]) {
  const isAllowed = allowedOrigins.includes(origin);
  
  return {
    'Access-Control-Allow-Origin': isAllowed ? origin : allowedOrigins[0],
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

export function handlePreflight(origin: string, allowedOrigins: string[]): Response {
  return new Response(null, {
    status: 200,
    headers: createCorsHeaders(origin, allowedOrigins)
  });
}