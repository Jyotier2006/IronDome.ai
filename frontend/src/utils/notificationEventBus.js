let idCounter = 0
const listeners = new Set()

export function subscribeToast(fn) {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

export function toast(message, type = 'info', duration = 2600) {
  const id = ++idCounter
  listeners.forEach((fn) => fn({ id, message, type, duration }))
  return id
}
