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

export function prepareForSigning(obj) {
    if (obj === null || typeof obj !== 'object') {
        return obj;
    }

    if (obj instanceof Uint8Array) {
        return btoa(Array.from(obj, byte => String.fromCharCode(byte)).join(''));
    }

    if (Array.isArray(obj)) {
        return obj.map(item => prepareForSigning(item));
    }

    const cleaned = {};
    for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
            cleaned[key] = prepareForSigning(obj[key]);
        }
    }
    return cleaned;
}