import { Component } from 'react'

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    console.error('Dashboard crashed:', error, info)
  }

  render() {
    if (this.state.error) {
      if (this.props.compact) {
        return (
          <div style={{
            height: 200,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 8,
            padding: 16,
            background: 'rgba(239,68,68,0.08)',
            color: '#ef4444',
            fontSize: 13,
          }}>
            <p style={{ fontWeight: 600, margin: 0 }}>This panel crashed:</p>
            <p style={{ fontFamily: 'monospace', margin: 0, textAlign: 'center' }}>
              {this.state.error?.message || String(this.state.error)}
            </p>
            <button
              style={{ padding: '4px 12px', borderRadius: 4, background: 'rgba(255,255,255,0.08)', color: '#fff', border: 'none', cursor: 'pointer' }}
              onClick={() => this.setState({ error: null })}
            >
              Retry
            </button>
          </div>
        )
      }
      return (
        <div className="h-screen flex items-center justify-center bg-background-primary text-text-primary p-6">
          <div className="glass-panel p-6 max-w-md text-center">
            <p className="text-section font-medium text-status-critical mb-2">Something went wrong</p>
            <p className="text-caption text-text-muted mb-4">
              {this.state.error?.message || 'An unexpected error occurred while rendering the dashboard.'}
            </p>
            <button className="btn-primary" onClick={() => this.setState({ error: null })}>
              Try again
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
