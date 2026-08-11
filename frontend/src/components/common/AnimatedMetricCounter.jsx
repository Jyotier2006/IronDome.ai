import { useEffect, useRef, useState } from 'react'

/**
 * Animates a numeric value change with an eased tween instead of an instant jump.
 * Falls back to displaying `value` as-is when it isn't a finite number.
 */
export default function CountUp({ value, duration = 500, decimals = 0, className = '' }) {
  const [display, setDisplay] = useState(value)
  const fromRef = useRef(value)
  const rafRef = useRef(null)

  useEffect(() => {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      setDisplay(value)
      return
    }

    const from = typeof fromRef.current === 'number' ? fromRef.current : value
    const start = performance.now()
    cancelAnimationFrame(rafRef.current)

    const tick = (now) => {
      const t = Math.min(1, (now - start) / duration)
      const eased = 1 - Math.pow(1 - t, 3)
      setDisplay(from + (value - from) * eased)
      if (t < 1) {
        rafRef.current = requestAnimationFrame(tick)
      } else {
        fromRef.current = value
      }
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafRef.current)
  }, [value, duration])

  const formatted = typeof display === 'number'
    ? display.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals })
    : display

  return <span className={`tabular ${className}`}>{formatted}</span>
}
