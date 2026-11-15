export class ApiError extends Error {
  constructor(message: string, readonly status: number, readonly code?: string, readonly retryAfter?: number) {
    super(message)
  }
}

export type Identity = { service: string; operator: 'duty_operator' | 'observer' }

export async function request<T>(url: string, options?: RequestInit, token = ''): Promise<T> {
  const headers = new Headers(options?.headers)
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const response = await fetch(url, { ...options, headers })
  if (!response.headers.get('content-type')?.includes('application/json')) {
    throw new Error('Сервер вернул неожиданный ответ. Проверьте запуск FastAPI.')
  }
  const data = await response.json()
  if (!response.ok) {
    const retryAfter = response.headers.get('Retry-After')
    throw new ApiError(
      typeof data.detail === 'string' ? data.detail : 'Запрос к API завершился ошибкой.',
      response.status,
      typeof data.code === 'string' ? data.code : undefined,
      retryAfter && /^\d+$/.test(retryAfter) ? Number(retryAfter) : undefined,
    )
  }
  return data
}
