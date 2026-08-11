import { useEffect, useState, useCallback } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { subscribeToast } from '@utils/notificationEventBus'

const toneDot = {
  info: 'bg-accent-cyan',
  success: 'bg-accent-green',
  warning: 'bg-status-warning',
}

const toneBorder = {
  info: 'border-accent-cyan/25',
  success: 'border-accent-green/25',
  warning: 'border-status-warning/25',
}

export default function ToastHost() {
  const [items, setItems] = useState([])

  const remove = useCallback((id) => {
    setItems((prev) => prev.filter((t) => t.id !== id))
  }, [])

  useEffect(() => subscribeToast((entry) => {
    setItems((prev) => [...prev.slice(-3), entry])
    setTimeout(() => remove(entry.id), entry.duration)
  }), [remove])

  return (
    <div
      className="fixed top-4 right-4 z-[60] flex flex-col gap-2 items-end pointer-events-none"
      style={{ maxWidth: 320 }}
    >
      <AnimatePresence>
        {items.map((item) => (
          <motion.div
            key={item.id}
            layout
            initial={{ opacity: 0, x: 32, scale: 0.95 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 32, scale: 0.95 }}
            transition={{ type: 'spring', stiffness: 420, damping: 32 }}
            className={`glass-card bg-background-secondary/95 border px-3.5 py-2.5 pointer-events-auto flex items-center gap-2.5 shadow-lg ${toneBorder[item.type] || toneBorder.info}`}
          >
            <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${toneDot[item.type] || toneDot.info}`} />
            <span className="text-caption text-text-secondary whitespace-nowrap">{item.message}</span>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  )
}
