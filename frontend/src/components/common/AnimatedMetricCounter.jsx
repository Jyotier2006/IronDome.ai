import { useEffect, useRef, useState } from 'react'

/**
 * Animates a numeric value change with an eased tween instead of an instant jump.
 * Falls back to displaying `value` as-is when it isn't a finite number.
 */
export default function CountUp({ value, duration = 500, decimals = 0, className = '' }) {
  const [display, setDisplay] = useState(value)
  const shownRef = useRef(value)   // the number currently on screen, mid-tween included
  const rafRef = useRef(null)

  useEffect(() => {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      shownRef.current = value
      setDisplay(value)
      return undefined
    }

    // tween from what is on screen, so a change mid-animation never jumps
    const from = typeof shownRef.current === 'number' && Number.isFinite(shownRef.current) ? shownRef.current : value
    const start = performance.now()
    cancelAnimationFrame(rafRef.current)

    const tick = (now) => {
      const t = Math.min(1, Math.max(0, (now - start) / duration))
      const eased = 1 - Math.pow(1 - t, 3)
      shownRef.current = from + (value - from) * eased
      setDisplay(shownRef.current)
      if (t < 1) rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafRef.current)
  }, [value, duration])

  const formatted = typeof display === 'number'
    ? display.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals })
    : display

  return <span className={`tabular ${className}`}>{formatted}</span>
}
