export const hex = bytes => (bytes || []).map(b => b.toString(16).padStart(2, '0')).join('')
export const comparisonCode = hash => /^[0-9a-f]{16,}$/i.test(hash || '') ? hash.slice(0, 16).toUpperCase().match(/.{4}/g).join(' ') : 'Unavailable'
export const secondsRemaining = (expiry, now = Date.now()) => Math.max(0, Math.ceil((Number(expiry) * 1000 - now) / 1000) || 0)
export const displayValue = value => value === null || value === undefined || value === '' ? 'Unavailable' : String(value)
export const uuid = bytes => { const value = hex(bytes); return value.length === 32 ? `${value.slice(0,8)}-${value.slice(8,12)}-${value.slice(12,16)}-${value.slice(16,20)}-${value.slice(20)}` : 'Unavailable' }
