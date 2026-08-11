import { useState, useEffect, useMemo, useRef } from 'react'
import { AnimatePresence, motion } from 'framer-motion'

export default function CommandPalette({ isOpen, onClose, actions }) {
  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const inputRef = useRef(null)
  const listRef = useRef(null)

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return actions
    return actions.filter(
      (a) => a.label.toLowerCase().includes(q) || a.keywords?.toLowerCase().includes(q)
    )
  }, [query, actions])

  useEffect(() => {
    if (isOpen) {
      setQuery('')
      setActiveIndex(0)
      requestAnimationFrame(() => inputRef.current?.focus())
    }
  }, [isOpen])

  useEffect(() => {
    setActiveIndex(0)
  }, [query])

  useEffect(() => {
    if (!isOpen) return undefined
    const handler = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
      } else if (e.key === 'ArrowDown') {
        e.preventDefault()
        setActiveIndex((i) => Math.min(i + 1, filtered.length - 1))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setActiveIndex((i) => Math.max(i - 1, 0))
      } else if (e.key === 'Enter') {
        e.preventDefault()
        const action = filtered[activeIndex]
        if (action) {
          action.run()
          onClose()
        }
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [isOpen, filtered, activeIndex, onClose])

  useEffect(() => {
    const el = listRef.current?.querySelector(`[data-index="${activeIndex}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [activeIndex])

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-[70] flex items-start justify-center pt-[12vh] px-4">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            onClick={onClose}
          />
          <motion.div
            initial={{ opacity: 0, y: -16, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -12, scale: 0.98 }}
            transition={{ type: 'spring', stiffness: 380, damping: 30 }}
            className="relative w-full max-w-lg glass-panel overflow-hidden shadow-2xl"
          >
            <div className="flex items-center gap-2.5 px-4 py-3 border-b border-white/10">
              <svg className="w-4 h-4 text-text-muted shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-4.35-4.35M17 11a6 6 0 11-12 0 6 6 0 0112 0z" />
              </svg>
              <input
                ref={inputRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Type a command or search..."
                className="flex-1 bg-transparent outline-none text-body text-text-primary placeholder:text-text-muted"
              />
              <kbd className="px-1.5 py-0.5 rounded bg-white/5 text-[10px] text-text-muted border border-white/10">ESC</kbd>
            </div>

            <div ref={listRef} className="max-h-[50vh] overflow-y-auto thin-scrollbar py-1.5">
              {filtered.length === 0 ? (
                <p className="px-4 py-6 text-caption text-text-muted text-center">No matching commands</p>
              ) : (
                filtered.map((action, i) => (
                  <button
                    key={action.id}
                    data-index={i}
                    onMouseEnter={() => setActiveIndex(i)}
                    onClick={() => {
                      action.run()
                      onClose()
                    }}
                    className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                      i === activeIndex ? 'bg-accent-cyan/15 text-text-primary' : 'text-text-secondary'
                    }`}
                  >
                    <span className={`shrink-0 ${i === activeIndex ? 'text-accent-cyan' : 'text-text-muted'}`}>
                      {action.icon}
                    </span>
                    <span className="flex-1 text-body">{action.label}</span>
                    {action.hint && <span className="text-caption text-text-muted">{action.hint}</span>}
                  </button>
                ))
              )}
            </div>

            <div className="flex items-center gap-4 px-4 py-2 border-t border-white/10 text-[11px] text-text-muted">
              <span className="flex items-center gap-1">
                <kbd className="px-1 py-0.5 rounded bg-white/5 border border-white/10">↑↓</kbd> Navigate
              </span>
              <span className="flex items-center gap-1">
                <kbd className="px-1 py-0.5 rounded bg-white/5 border border-white/10">Enter</kbd> Run
              </span>
              <span className="flex items-center gap-1">
                <kbd className="px-1 py-0.5 rounded bg-white/5 border border-white/10">Esc</kbd> Close
              </span>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  )
}
