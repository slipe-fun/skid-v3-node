export function numberToBytes(number) {
  const buf = new ArrayBuffer(8)
  const view = new DataView(buf)

  view.setBigUint64(0, BigInt(number), false)

  return new Uint8Array(buf)
}

export function base64ToBytes(base64) {
  const binString = atob(base64);
  const len = binString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binString.charCodeAt(i);
  }
  return bytes;
}