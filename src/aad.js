export function buildAAD(type, fields = {}) {
  const contextTag = `skid:v3:${type}`;
  const base = {
    context: contextTag,
    version: 3,
    ...fields
  };
  
  return new TextEncoder().encode(JSON.stringify(base));
}