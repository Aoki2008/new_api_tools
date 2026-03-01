import { useCallback, useEffect, useMemo, useState } from 'react'
import { Copy, Info, Loader2, RefreshCw, Search, ShieldCheck } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { useToast } from './Toast'
import { Button } from './ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Input } from './ui/input'
import { Badge } from './ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import { cn } from '../lib/utils'

interface AuditListItem {
  id: number
  received_at: number
  event_timestamp: number
  request_id: string
  method: string
  path: string
  status_code: number
  user_id: number
  username: string
  model: string
  request_body_bytes: number
  request_body_truncated: boolean
}

interface AuditListResult {
  items: AuditListItem[]
  next_before_id?: number
}

interface AuditEventDetail {
  id: number
  received_at: number
  type: string
  timestamp: number
  request_id: string
  method: string
  path: string
  status_code: number
  duration_ms: number
  user_id: number
  username: string
  token_id: number
  token_name: string
  group: string
  channel_id: number
  channel_name: string
  channel_type: number
  model: string
  content_type: string
  request_body: string
  request_body_encoding: string
  request_body_bytes: number
  request_body_truncated: boolean
  signature_valid: boolean
}

interface AuditConfig {
  retention_days: number
  retention_days_source?: string
}

interface AuditCleanupResult {
  deleted: number
  cutoff_received_at?: number
  retention_days: number
  retention_days_source?: string
  message?: string
}

function formatTs(ts: number) {
  if (!ts) return '-'
  return new Date(ts * 1000).toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function formatBodyForDisplay(body: string) {
  const trimmed = (body || '').trim()
  if (!trimmed) return ''
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2)
    } catch {
      return body
    }
  }
  return body
}

export function Audit() {
  const { token } = useAuth()
  const { showToast } = useToast()
  const apiUrl = import.meta.env.VITE_API_URL || ''

  const [retentionDays, setRetentionDays] = useState('')
  const [retentionSource, setRetentionSource] = useState<string | null>(null)
  const [configLoading, setConfigLoading] = useState(false)
  const [configSaving, setConfigSaving] = useState(false)
  const [cleanupRunning, setCleanupRunning] = useState(false)

  const [requestId, setRequestId] = useState('')
  const [path, setPath] = useState('')
  const [userId, setUserId] = useState('')
  const [statusCode, setStatusCode] = useState('')

  const [items, setItems] = useState<AuditListItem[]>([])
  const [nextBeforeId, setNextBeforeId] = useState<number | null>(null)
  const [loading, setLoading] = useState(false)

  const [detailOpen, setDetailOpen] = useState(false)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detail, setDetail] = useState<AuditEventDetail | null>(null)
  const [helpOpen, setHelpOpen] = useState(false)

  const webhookUrl = useMemo(() => {
    const trimmedApiUrl = (apiUrl || '').trim().replace(/\/+$/, '')
    const base = trimmedApiUrl.startsWith('http') ? trimmedApiUrl : (typeof window !== 'undefined' ? window.location.origin : '')
    return `${base}/webhook/newapi`
  }, [apiUrl])

  const getAuthHeaders = useCallback(() => ({
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
  }), [token])

  const fetchAuditConfig = useCallback(async () => {
    setConfigLoading(true)
    try {
      const res = await fetch(`${apiUrl}/api/audit/config`, { headers: getAuthHeaders() })
      const json = await res.json()
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || json?.error?.message || '请求失败')
      }
      const data = json.data as AuditConfig
      setRetentionDays(String(data?.retention_days ?? ''))
      setRetentionSource(data?.retention_days_source || null)
    } catch (e) {
      console.error(e)
      showToast('error', '加载审计配置失败')
    } finally {
      setConfigLoading(false)
    }
  }, [apiUrl, getAuthHeaders, showToast])

  const saveAuditConfig = useCallback(async () => {
    const days = Number(retentionDays)
    if (!Number.isFinite(days) || !Number.isInteger(days) || days < 0 || days > 3650) {
      showToast('error', '保留天数需为 0~3650 的整数')
      return
    }

    setConfigSaving(true)
    try {
      const res = await fetch(`${apiUrl}/api/audit/config`, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: JSON.stringify({ retention_days: days }),
      })
      const json = await res.json()
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || json?.error?.message || '请求失败')
      }
      const data = json.data as AuditConfig
      setRetentionDays(String(data?.retention_days ?? days))
      setRetentionSource(data?.retention_days_source || 'runtime')
      showToast('success', '已保存')
    } catch (e) {
      console.error(e)
      showToast('error', '保存失败')
    } finally {
      setConfigSaving(false)
    }
  }, [apiUrl, getAuthHeaders, retentionDays, showToast])

  const runAuditCleanup = useCallback(async () => {
    setCleanupRunning(true)
    try {
      const res = await fetch(`${apiUrl}/api/audit/cleanup`, { method: 'POST', headers: getAuthHeaders() })
      const json = await res.json()
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || json?.error?.message || '请求失败')
      }
      const data = json.data as AuditCleanupResult
      setRetentionDays(String(data?.retention_days ?? retentionDays))
      setRetentionSource(data?.retention_days_source || retentionSource)

      const deleted = Number(data?.deleted ?? 0)
      if (deleted > 0) {
        showToast('success', `已清理 ${deleted} 条`)
      } else {
        showToast('success', data?.message || '无可清理记录')
      }
    } catch (e) {
      console.error(e)
      showToast('error', '清理失败')
    } finally {
      setCleanupRunning(false)
    }
  }, [apiUrl, getAuthHeaders, retentionDays, retentionSource, showToast])

  const copyToClipboard = useCallback(async (text: string, label: string) => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text)
        showToast('success', `${label}已复制`)
        return
      }
      const textArea = document.createElement('textarea')
      textArea.value = text
      textArea.style.position = 'fixed'
      textArea.style.left = '-9999px'
      document.body.appendChild(textArea)
      textArea.select()
      document.execCommand('copy')
      document.body.removeChild(textArea)
      showToast('success', `${label}已复制`)
    } catch {
      showToast('error', '复制失败，请手动复制')
    }
  }, [showToast])

  const buildQuery = useCallback((beforeId?: number) => {
    const params = new URLSearchParams()
    params.set('limit', '50')
    if (beforeId && beforeId > 0) params.set('before_id', String(beforeId))
    if (requestId.trim()) params.set('request_id', requestId.trim())
    if (path.trim()) params.set('path', path.trim())
    if (userId.trim()) params.set('user_id', userId.trim())
    if (statusCode.trim()) params.set('status_code', statusCode.trim())
    return params.toString()
  }, [path, requestId, statusCode, userId])

  const fetchList = useCallback(async (mode: 'reset' | 'more') => {
    setLoading(true)
    try {
      const beforeId = mode === 'more' ? nextBeforeId ?? undefined : undefined
      const query = buildQuery(beforeId)
      const res = await fetch(`${apiUrl}/api/events?${query}`, { headers: getAuthHeaders() })
      const json = await res.json()
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || json?.error?.message || '请求失败')
      }
      const data = json.data as AuditListResult
      const newItems = data?.items || []
      setItems(prev => mode === 'more' ? [...prev, ...newItems] : newItems)
      setNextBeforeId(data?.next_before_id ? data.next_before_id : null)
    } catch (e) {
      console.error(e)
      showToast('error', '加载审计日志失败')
      if (mode === 'reset') {
        setItems([])
        setNextBeforeId(null)
      }
    } finally {
      setLoading(false)
    }
  }, [apiUrl, buildQuery, getAuthHeaders, nextBeforeId, showToast])

  const openDetail = useCallback(async (id: number) => {
    setDetailOpen(true)
    setDetailLoading(true)
    setDetail(null)
    try {
      const res = await fetch(`${apiUrl}/api/events/${id}`, { headers: getAuthHeaders() })
      const json = await res.json()
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || json?.error?.message || '请求失败')
      }
      setDetail(json.data as AuditEventDetail)
    } catch (e) {
      console.error(e)
      showToast('error', '加载详情失败')
      setDetailOpen(false)
    } finally {
      setDetailLoading(false)
    }
  }, [apiUrl, getAuthHeaders, showToast])

  useEffect(() => {
    fetchList('reset')
    fetchAuditConfig()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const statusBadgeVariant = (code: number) => {
    if (code >= 200 && code < 300) return 'success' as const
    if (code >= 400 && code < 500) return 'warning' as const
    if (code >= 500) return 'destructive' as const
    return 'outline' as const
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <Card className="border-border/50 bg-background/60 backdrop-blur-sm">
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-xl">
              <ShieldCheck className="h-5 w-5 text-primary" />
              日志审计
            </CardTitle>
            <CardDescription className="leading-relaxed">
              接收 new-api 外部审计 Webhook，并在此处查看事件明细。Webhook 地址：
              <code className="ml-2 font-mono text-xs">{webhookUrl}</code>
            </CardDescription>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="h-9"
              onClick={() => copyToClipboard(webhookUrl, 'Webhook 地址')}
            >
              <Copy className="h-4 w-4 mr-2" />
              复制地址
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-9"
              onClick={() => setHelpOpen(true)}
            >
              <Info className="h-4 w-4 mr-2" />
              配置说明
            </Button>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          <div className="rounded-xl border border-border/50 p-3 bg-muted/10">
            <div className="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-3">
              <div className="space-y-1">
                <label className="text-xs font-medium text-muted-foreground">审计保留天数</label>
                <div className="flex items-center gap-2">
                  <Input
                    value={retentionDays}
                    onChange={(e) => setRetentionDays(e.target.value)}
                    placeholder="例如 30"
                    inputMode="numeric"
                    className="h-9 w-[140px]"
                    disabled={configLoading || configSaving || cleanupRunning}
                  />
                  {retentionSource ? (
                    <Badge variant="outline" className="text-[11px]">
                      source: {retentionSource}
                    </Badge>
                  ) : null}
                </div>
                <p className="text-[11px] text-muted-foreground">设置为 0 可关闭自动清理。</p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <Button
                  onClick={saveAuditConfig}
                  disabled={configLoading || configSaving || cleanupRunning}
                  className="h-9"
                >
                  {configSaving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
                  保存
                </Button>
                <Button
                  variant="outline"
                  onClick={runAuditCleanup}
                  disabled={configLoading || configSaving || cleanupRunning}
                  className="h-9"
                >
                  {cleanupRunning ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
                  立即清理
                </Button>
                <Button
                  variant="ghost"
                  onClick={fetchAuditConfig}
                  disabled={configLoading || configSaving || cleanupRunning}
                  className="h-9"
                >
                  {configLoading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-2" />}
                  刷新配置
                </Button>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">request_id</label>
              <Input value={requestId} onChange={(e) => setRequestId(e.target.value)} placeholder="精确匹配" />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">path</label>
              <Input value={path} onChange={(e) => setPath(e.target.value)} placeholder="模糊匹配，例如 /v1/chat" />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">user_id</label>
              <Input value={userId} onChange={(e) => setUserId(e.target.value)} placeholder="例如 1" inputMode="numeric" />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">status_code</label>
              <Input value={statusCode} onChange={(e) => setStatusCode(e.target.value)} placeholder="例如 200" inputMode="numeric" />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button onClick={() => fetchList('reset')} disabled={loading} className="h-9">
              {loading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Search className="h-4 w-4 mr-2" />}
              查询
            </Button>
            <Button variant="outline" onClick={() => fetchList('reset')} disabled={loading} className="h-9">
              <RefreshCw className={cn("h-4 w-4 mr-2", loading ? "animate-spin" : "")} />
              刷新
            </Button>
            <Button
              variant="ghost"
              onClick={() => { setRequestId(''); setPath(''); setUserId(''); setStatusCode('') }}
              disabled={loading}
              className="h-9"
            >
              清空筛选
            </Button>
          </div>

          <div className="rounded-xl border border-border/50 overflow-hidden bg-background">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[90px]">ID</TableHead>
                  <TableHead className="min-w-[180px]">时间</TableHead>
                  <TableHead className="w-[90px]">方法</TableHead>
                  <TableHead>路径</TableHead>
                  <TableHead className="w-[110px]">状态</TableHead>
                  <TableHead className="min-w-[160px]">用户</TableHead>
                  <TableHead className="min-w-[140px]">模型</TableHead>
                  <TableHead className="w-[140px]">Body</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="py-10 text-center text-sm text-muted-foreground">
                      {loading ? '加载中…' : '暂无事件'}
                    </TableCell>
                  </TableRow>
                ) : (
                  items.map((it) => (
                    <TableRow
                      key={it.id}
                      className="cursor-pointer hover:bg-muted/40"
                      onClick={() => openDetail(it.id)}
                    >
                      <TableCell className="font-mono text-xs text-muted-foreground">{it.id}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        <div className="space-y-0.5">
                          <div>接收：{formatTs(it.received_at)}</div>
                          <div>事件：{formatTs(it.event_timestamp)}</div>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs font-medium">{it.method}</TableCell>
                      <TableCell className="text-xs">
                        <code className="font-mono">{it.path}</code>
                        {it.request_id && (
                          <div className="text-[11px] text-muted-foreground mt-1 font-mono">
                            request_id: {it.request_id}
                          </div>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant={statusBadgeVariant(it.status_code)} className="text-[11px]">
                          {it.status_code}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs">
                        {it.username ? `${it.username} (${it.user_id})` : String(it.user_id || '-')}
                      </TableCell>
                      <TableCell className="text-xs">{it.model || '-'}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {it.request_body_bytes || 0} bytes{it.request_body_truncated ? ' (truncated)' : ''}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              共 {items.length} 条{nextBeforeId ? '（可继续加载）' : ''}
            </p>
            <Button
              variant="outline"
              size="sm"
              className="h-9"
              onClick={() => fetchList('more')}
              disabled={loading || !nextBeforeId}
            >
              {loading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
              加载更多
            </Button>
          </div>
        </CardContent>
      </Card>

      <Dialog open={detailOpen} onOpenChange={setDetailOpen}>
        <DialogContent className="max-w-4xl">
          <DialogHeader>
            <DialogTitle>审计事件详情</DialogTitle>
            <DialogDescription>点击字段右侧按钮可复制。</DialogDescription>
          </DialogHeader>

          {detailLoading || !detail ? (
            <div className="flex items-center justify-center py-16 text-muted-foreground">
              <Loader2 className="h-5 w-5 mr-2 animate-spin" />
              加载中…
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="rounded-xl border border-border/50 p-3">
                  <div className="text-xs text-muted-foreground mb-1">request_id</div>
                  <div className="flex items-center justify-between gap-2">
                    <code className="font-mono text-xs break-all">{detail.request_id || '-'}</code>
                    {!!detail.request_id && (
                      <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => copyToClipboard(detail.request_id, 'request_id')}>
                        <Copy className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                </div>

                <div className="rounded-xl border border-border/50 p-3">
                  <div className="text-xs text-muted-foreground mb-1">path</div>
                  <div className="flex items-center justify-between gap-2">
                    <code className="font-mono text-xs break-all">{detail.path}</code>
                    <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => copyToClipboard(detail.path, 'path')}>
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="rounded-xl border border-border/50 p-3">
                  <div className="text-xs text-muted-foreground mb-1">时间</div>
                  <div className="text-sm">
                    <div>接收：{formatTs(detail.received_at)}</div>
                    <div>事件：{formatTs(detail.timestamp)}</div>
                  </div>
                </div>
                <div className="rounded-xl border border-border/50 p-3">
                  <div className="text-xs text-muted-foreground mb-1">状态</div>
                  <div className="flex items-center gap-2">
                    <Badge variant={statusBadgeVariant(detail.status_code)}>{detail.status_code}</Badge>
                    <span className="text-xs text-muted-foreground">{detail.method}</span>
                    <span className="text-xs text-muted-foreground">{detail.duration_ms}ms</span>
                  </div>
                </div>
                <div className="rounded-xl border border-border/50 p-3">
                  <div className="text-xs text-muted-foreground mb-1">用户</div>
                  <div className="text-sm">{detail.username ? `${detail.username} (${detail.user_id})` : String(detail.user_id || '-')}</div>
                  <div className="text-xs text-muted-foreground mt-1">签名：{detail.signature_valid ? 'valid' : 'n/a'}</div>
                </div>
              </div>

              <div className="rounded-xl border border-border/50 overflow-hidden">
                <div className="flex items-center justify-between px-4 py-3 border-b bg-muted/20">
                  <div className="text-sm font-medium">request_body</div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">
                      {detail.request_body_bytes || 0} bytes{detail.request_body_truncated ? ' (truncated)' : ''}
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-8"
                      onClick={() => copyToClipboard(detail.request_body, 'request_body')}
                      disabled={!detail.request_body}
                    >
                      <Copy className="h-4 w-4 mr-2" />
                      复制
                    </Button>
                  </div>
                </div>
                <pre className="p-4 text-xs font-mono whitespace-pre-wrap break-words max-h-[50vh] overflow-y-auto custom-scrollbar">
                  {detail.request_body_encoding === 'base64'
                    ? `[base64]\n${detail.request_body}`
                    : formatBodyForDisplay(detail.request_body)}
                </pre>
              </div>
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setDetailOpen(false)}>关闭</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={helpOpen} onOpenChange={setHelpOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>如何接入审计 Webhook</DialogTitle>
            <DialogDescription>在 new-api 管理后台配置后，即可在此页看到审计事件。</DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="rounded-xl border border-border/50 p-4 bg-muted/10">
              <div className="text-sm font-medium mb-2">new-api 配置位置</div>
              <p className="text-sm text-muted-foreground">运营设置 → 日志设置</p>
            </div>

            <div className="rounded-xl border border-border/50 p-4">
              <div className="text-sm font-medium mb-2">推荐配置</div>
              <pre className="text-xs font-mono whitespace-pre-wrap break-words bg-muted/20 rounded-lg p-3 border border-border/50">
{`LogRequestBodyEnabled = true
LogRequestBodyMaxBytes = 8192
AuditWebhookUrl = ${webhookUrl}
AuditWebhookSecret = <与本工具 AUDIT_WEBHOOK_SECRET 相同（可选）>
AuditWebhookTimeoutSeconds = 5`}
              </pre>
            </div>

            <p className="text-xs text-muted-foreground leading-relaxed">
              安全建议：生产环境建议启用 <code className="font-mono">AUDIT_WEBHOOK_SECRET</code> 并使用 HTTPS。
            </p>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setHelpOpen(false)}>关闭</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
