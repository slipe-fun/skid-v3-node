export function numberToBytes(number) {
  const buf = new ArrayBuffer(8)
  const view = new DataView(buf)

  view.setBigUint64(0, BigInt(number), false)

  return new Uint8Array(buf)
}