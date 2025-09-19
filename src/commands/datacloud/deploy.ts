import {flags} from '@heroku-cli/command'
import {ux} from '@oclif/core'
import axios from 'axios'
import AdmZip from 'adm-zip'
import fs from 'node:fs'
import path from 'node:path'
import Base from '../../lib/base'

type AuthorizationResponse = {
  org: {
    developer_name: string
  }
  // Access token and instance URL are provided by AppLink for datacloud authorizations
  access_token: string
  instance_url: string
}

export default class Deploy extends Base {
  static description = 'Zip and deploy Data Cloud Custom Code directly via Salesforce SSOT APIs using stored AppLink authorization'

  // Keep non-strict to allow future compatibility with Python CLI flags
  static strict = false as const

  // Format API error payloads consistently (arrays/objects/strings)
  protected formatErrorData(data: any, fallback: string): string {
    if (Array.isArray(data)) return JSON.stringify(data)
    if (data && typeof data === 'object') return JSON.stringify(data)
    if (typeof data === 'string' && data.trim().length > 0) return data
    return fallback
  }

  static flags = {
    app: flags.app({required: true}),
    addon: flags.string({description: 'unique name or ID of an AppLink add-on'}),
    remote: flags.remote(),

    // Mirror Python CLI deploy flags (core subset)
    'authorization-name': flags.string({required: true, description: 'AppLink Data Cloud authorization developer name to use'}),
    path: flags.string({required: false, default: 'payload', description: 'Path to source directory to zip and deploy. Defaults to \'payload\' (expects payload/config.json and payload/entrypoint.py)'}),
    name: flags.string({required: true, description: 'Data Custom Code package/function name'}),
    description: flags.string({description: 'Package description'}),
    env: flags.string({multiple: true, description: 'Environment variables as KEY=VALUE; repeatable'}),
    timeout: flags.integer({description: 'Function timeout in seconds'}),
    memory: flags.integer({description: 'Memory size in MB'}),
    'override-token': flags.string({description: 'Override the access token for testing'}),
  }

  protected deployDebug(message: string, info?: Record<string, unknown>): void {
    try {
      if (!process.env.DEBUG) return
      const line = `[datacloud:deploy] ${message}`
      if (info && Object.keys(info).length > 0) {
        process.stderr.write(`${line} ${JSON.stringify(info)}\n`)
      } else {
        process.stderr.write(`${line}\n`)
      }
    } catch {
      // ignore debug logging errors
    }
  }

  protected async zipDirectory(dir: string, opts?: {zipRoot?: string}): Promise<Buffer> {
    const abs = path.resolve(dir)
    if (!fs.existsSync(abs)) {
      ux.error(`The path ${abs} doesn't exist.`, {exit: 1})
    }

    const stat = fs.statSync(abs)
    if (!stat.isDirectory()) {
      ux.error(`The path ${abs} must be a directory.`, {exit: 1})
    }

    const zip = new AdmZip()
    // Add entire directory (excluding common ignores)
    zip.addLocalFolder(abs, opts?.zipRoot, filePath => {
      const rel = path.relative(abs, filePath)
      // Skip node_modules and .git by default
      return !rel.split(path.sep).includes('node_modules') && !rel.split(path.sep).includes('.git')
    })
    return zip.toBuffer()
  }

  protected parseEnv(env?: string[]): Record<string, string> | undefined {
    if (!env || env.length === 0) return undefined
    const map: Record<string, string> = {}
    for (const entry of env) {
      const idx = entry.indexOf('=')
      if (idx === -1) {
        ux.warn(`Ignoring env entry without '=': ${entry}`)

        continue
      }

      const key = entry.slice(0, idx).trim()
      const value = entry.slice(idx + 1)
      if (!key) {
        ux.warn(`Ignoring env entry with empty key: ${entry}`)

        continue
      }

      map[key] = value
    }

    return map
  }

  protected async retrieveAuthorization(authorizationName: string, app: string, addon?: string): Promise<{accessToken: string, instanceUrl: string, apiVersion?: string}> {
    ux.action.start('Retrieving Data Cloud authorization')

    // Try direct developer_name endpoint first (as used by applink:authorizations:info)
    let detail: any
    try {
      const {body} = await this.applinkClient.get<any>(`/addons/${this.addonId}/authorizations/${authorizationName}`,
        {
          headers: {authorization: `Bearer ${this._applinkToken}`},
          retryAuth: false,
        })
      detail = body
    } catch (error: any) {
      // Fallback: resolve developer_name -> id via index, then fetch single by id
      try {
        const {body: list} = await this.applinkClient.get<any[]>(`/addons/${this.addonId}/authorizations`, {
          headers: {authorization: `Bearer ${this._applinkToken}`},
          retryAuth: false,
        })

        const match = (list || []).find((a: any) => a?.org?.developer_name === authorizationName)
        if (!match?.id) {
          throw error
        }

        const authId = match.id as string
        const {body} = await this.applinkClient.get<any>(`/addons/${this.addonId}/authorizations/${authId}`,
          {
            headers: {authorization: `Bearer ${this._applinkToken}`},
            retryAuth: false,
          })
        detail = body
      } catch (error: any) {
        ux.action.stop('failed')
        const guidance = `Data Cloud authorization '${authorizationName}' was not found for this app/add-on.
        - Verify the developer name using: heroku applink:authorizations --app ${app}${addon ? ` --addon ${addon}` : ''}
        - If it doesn't exist, create it with: heroku datacloud:authorizations:add ${authorizationName} --app ${app}${addon ? ` --addon ${addon}` : ''}`
        const message = error?.body?.message || error?.message
        ux.error(message ? `${guidance}\n${message}` : guidance, {exit: 1})
      }
    }

    // Attempt to read credentials from the single-authorization response
    // Primary (as seen from applink:authorizations:info): detail.org.user_auth.access_token and detail.org.instance_url
    let accessToken = detail?.org?.user_auth?.access_token as string | undefined
    let instanceUrl = detail?.org?.instance_url as string | undefined
    // Secondary fallbacks: top-level or nested credentials
    if (!accessToken || !instanceUrl) {
      accessToken = accessToken || (detail?.access_token as string | undefined)
      instanceUrl = instanceUrl || (detail?.instance_url as string | undefined)
    }
    if (!accessToken || !instanceUrl) {
      accessToken = accessToken || (detail?.credentials?.access_token as string | undefined)
      instanceUrl = instanceUrl || (detail?.credentials?.instance_url as string | undefined)
    }

    // Step 3: if still missing, try id-scoped credential endpoints used in some environments
    if (!accessToken || !instanceUrl) {
      const authId = detail?.id as string | undefined
      const attempts = authId ? [
        `/addons/${this.addonId}/authorizations/${authId}/datacloud`,
        `/addons/${this.addonId}/authorizations/${authId}/data-cloud`,
        `/addons/${this.addonId}/authorizations/${authId}/credentials`,
      ] : []
      for (const url of attempts) {
        try {
          const {body} = await this.applinkClient.get<AuthorizationResponse | any>(url, {
            headers: {authorization: `Bearer ${this._applinkToken}`},
            retryAuth: false,
          })
          accessToken = (body as any)?.access_token || (body as any)?.credentials?.access_token
          instanceUrl = (body as any)?.instance_url || (body as any)?.credentials?.instance_url
          if (accessToken && instanceUrl) break
        } catch {
          // try next
        }
      }
    }

    if (!accessToken || !instanceUrl) {
      ux.error('Authorization did not return access_token and instance_url. Ensure the authorization is completed.', {exit: 1})
    }

    ux.action.stop()

    const apiVersion = (detail?.org?.api_version as string | undefined) || undefined
    this.deployDebug('Authorization resolved', {
      developer_name: authorizationName,
      instance_url: instanceUrl,
      token_present: Boolean(accessToken),
      access_token: accessToken,
      api_version: apiVersion,
    })

    return {accessToken: accessToken as string, instanceUrl: instanceUrl as string, apiVersion}
  }

  protected buildMetadata(pkgName: string, options: {description?: string, envVars?: Record<string, string>, timeout?: number, memory?: number, version?: string, computeType?: string}): Record<string, unknown> {
    const description = options.description ?? ''
    const version = options.version ?? '0.0.1'
    const computeType = options.computeType ?? 'CPU_S'
    return {
      label: pkgName,
      name: pkgName,
      description,
      version,
      computeType,
    }
  }

  // Retained in case we need multipart in other flows; not used in the 2-step deploy
  protected createFormData(zipBuffer: Buffer, metadata: Record<string, unknown>, names?: {artifact: string, meta: string}): FormData {
    const artifactField = names?.artifact || 'artifact'
    const metaField = names?.meta || 'deployment'
    const formData = new FormData()
    formData.append(artifactField, new Blob([zipBuffer], {type: 'application/zip'}))
    formData.append(metaField, new Blob([JSON.stringify(metadata)], {type: 'application/json'}))
    return formData
  }

  protected async deployAndPoll(opts: {instanceUrl: string, accessToken: string, zipBuffer: Buffer, metadata: Record<string, unknown>, pkgName: string, apiVersion?: string}): Promise<void> {
    const {instanceUrl, accessToken, zipBuffer, metadata, pkgName, apiVersion} = opts

    const candidates = this.buildSsotCandidates(instanceUrl, apiVersion)
    this.deployDebug('SSOT candidates', {candidates})
    if (process.env.DEBUG) {
      ux.info(`[datacloud:deploy] SSOT candidates ${JSON.stringify({candidates})}`)
    }

    ux.action.start(`Deploying ${pkgName} to Data Cloud`)

    // Step 1: Create deployment (JSON body)
    const createResp = await this.tryCreateDeployment({accessToken, body: metadata, candidates})

    // Step 2: Upload artifact (PUT zip)
    const uploadUrl = this.extractUploadUrl(createResp)
    if (!uploadUrl) {
      ux.action.stop('failed')

      ux.error('Create deployment response did not include file upload URL', {exit: 1})
    }
    const uploadResp = await this.uploadArtifact({accessToken, uploadUrl: uploadUrl as string, zipBuffer})

    // Derive status URL and poll (from either create or upload response)
    const statusUrl = this.extractStatusUrl(uploadResp) || this.extractStatusUrl(createResp)
    const resolvedStatusUrl = statusUrl ? this.resolveStatusUrl(instanceUrl, statusUrl) : undefined
    this.deployDebug('SSOT status URL', {status_url: statusUrl, resolved_status_url: resolvedStatusUrl})
    if (process.env.DEBUG) {
      ux.info(`[datacloud:deploy] SSOT status URL ${JSON.stringify({status_url: statusUrl})}`)
    }
    if (resolvedStatusUrl) {
      await this.pollUntilComplete({statusUrl: resolvedStatusUrl, accessToken})
    }

    ux.action.stop('done')
  }

  protected buildSsotCandidates(instanceUrl: string, apiVersion?: string): string[] {
    const version = apiVersion ? `v${apiVersion}` : 'v63.0'
    const base = `${instanceUrl.replace(/\/?$/, '')}/services/data/${version}`
    return [
      `${base}/ssot/data-custom-code`,
      `${base}/ssot/custom-code`,
    ]
  }

  protected async tryCreateDeployment(args: {accessToken: string, body: Record<string, unknown>, candidates: string[]}): Promise<{data?: any, headers?: Record<string, any>}> {
    const {accessToken, body, candidates} = args
    let lastError: any
    for (const ssotUrl of candidates) {
      const reqHeaders = {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
        'Content-Type': 'application/json',
      }

      this.deployDebug('SSOT POST (create)', {url: ssotUrl, headers: reqHeaders, json_body: body})
      const curlSnippet = `curl -X POST '${ssotUrl}' -H 'Authorization: ${reqHeaders.Authorization}' -H 'Accept: ${reqHeaders.Accept}' -H 'Content-Type: application/json' --data '${JSON.stringify(body)}'`
      this.deployDebug('SSOT POST curl', {snippet: curlSnippet})
      if (process.env.DEBUG) {
        ux.info('[datacloud:deploy] SSOT POST curl')
        ux.info(curlSnippet)
      }
      const postCreateInfo = {url: ssotUrl, headers: reqHeaders}
      if (process.env.DEBUG) {
        ux.info(`[datacloud:deploy] SSOT POST (create) ${JSON.stringify(postCreateInfo)}`)
      }

      try {
        const response = await axios.post(ssotUrl, body, {
          headers: reqHeaders,
          maxBodyLength: Number.POSITIVE_INFINITY,
          maxContentLength: Number.POSITIVE_INFINITY,
        })
        const successInfo = {
          url: ssotUrl,
          data_keys: response?.data ? Object.keys(response.data) : [],
          header_keys: response?.headers ? Object.keys(response.headers) : [],
        }
        this.deployDebug('SSOT POST success (create)', successInfo)
        if (process.env.DEBUG) {
          ux.info(`[datacloud:deploy] SSOT POST success (create) ${JSON.stringify(successInfo)}`)
          if (ssotUrl.includes('/ssot/data-custom-code')) {
            ux.info('[datacloud:deploy] Data Custom Code create API (/ssot/data-custom-code) succeeded')
          }
        }
        return response
      } catch (error: any) {
        const status = error?.response?.status
        const data = error?.response?.data
        const message: string = this.formatErrorData(data, error?.message || 'Deployment failed')
        this.deployDebug('SSOT POST failed (create)', {url: ssotUrl, status, data, data_keys: data ? Object.keys(data) : [], message})
        ux.warn('[datacloud:deploy] SSOT POST failed (create)')
        if (data !== undefined) ux.warn(typeof data === 'string' ? data : JSON.stringify(data))
        ux.warn(`[datacloud:deploy] Status ${status} Message ${message}`)
        lastError = error
        if (status && status !== 404) break
      }
    }

    const data = lastError?.response?.data
    const msg: string = this.formatErrorData(data, lastError?.message || 'Deployment failed')
    ux.action.stop('failed')
    ux.error(msg, {exit: 1})
  }

  protected extractStatusUrl(response: {data?: any, headers?: Record<string, any>}): string | undefined {
    return (
      (response?.data?.status_url)
      || (response?.data?.statusUrl)
      || (response?.data?.url)
      || (response?.data?.status)
      || (response?.headers?.location)
    )
  }

  protected resolveStatusUrl(instanceUrl: string, url: string): string {
    // If absolute (http/https), return as-is
    if (/^https?:\/\//i.test(url)) return url
    const base = instanceUrl.replace(/\/?$/, '')
    const path = url.startsWith('/') ? url : `/${url}`
    return `${base}${path}`
  }

  protected extractUploadUrl(response: {data?: any, headers?: Record<string, any>}): string | undefined {
    const raw = (
      (response?.data?.fileUploadUrl)
      || (response?.data?.file_upload_url)
      || (response?.data?.uploadUrl)
      || (response?.data?.upload_url)
    ) as string | undefined
    return raw ? this.normalizeUploadUrl(raw) : undefined
  }

  // Some environments return the pre-signed URL with HTML-escaped ampersands.
  // S3 requires exact signed query params, so we must unescape before using.
  protected normalizeUploadUrl(url: string): string {
    return url.replace(/&amp;/g, '&').trim()
  }

  protected async uploadArtifact(args: {uploadUrl: string, accessToken: string, zipBuffer: Buffer}): Promise<{data?: any, headers?: Record<string, any>}> {
    const {uploadUrl, accessToken: _accessToken, zipBuffer} = args
    // IMPORTANT: fileUploadUrl is a pre-signed S3 URL. Do NOT send Authorization header.
    const headers = {
      'Content-Type': 'application/zip',
      'Content-Length': String(zipBuffer.byteLength),
    }
    const curlSnippet = `curl -X PUT '${uploadUrl}' -H 'Content-Type: application/zip' --data-binary '@/tmp/deployment.zip'`
    this.deployDebug('SSOT PUT (upload)', {url: uploadUrl, headers, bytes: zipBuffer.byteLength})
    if (process.env.DEBUG) {
      ux.info('[datacloud:deploy] SSOT PUT curl')
      ux.info(curlSnippet)
    }

    try {
      const response = await axios.put(uploadUrl, zipBuffer, {headers, maxBodyLength: Number.POSITIVE_INFINITY})
      const putSuccessInfo = {url: uploadUrl, data_keys: response?.data ? Object.keys(response.data) : [], header_keys: response?.headers ? Object.keys(response.headers) : []}
      this.deployDebug('SSOT PUT success (upload)', putSuccessInfo)
      if (process.env.DEBUG) {
        ux.info(`[datacloud:deploy] SSOT PUT success (upload) ${JSON.stringify(putSuccessInfo)}`)
        ux.info('[datacloud:deploy] File upload (artifact PUT) succeeded')
      }
      return response
    } catch (error: any) {
      const status = error?.response?.status
      const data = error?.response?.data
      const s3Body = typeof data === 'string' ? data : (data ? JSON.stringify(data) : undefined)
      const message: string = data?.message || error?.message || 'Artifact upload failed'
      this.deployDebug('SSOT PUT failed (upload)', {url: uploadUrl, status, data_keys: data ? Object.keys(data) : [], message, s3_body: s3Body})
      ux.warn(`[datacloud:deploy] SSOT PUT failed (upload)`)
      if (s3Body) ux.warn(s3Body)
      ux.warn(`[datacloud:deploy] Status ${status} Message ${message}`)
      ux.action.stop('failed')
      ux.error(message, {exit: 1})
    }
  }

  protected async pollUntilComplete(args: {statusUrl: string, accessToken: string}): Promise<void> {
    const {statusUrl, accessToken} = args
    let status: string = 'pending'
    while (['pending', 'building', 'deploying', 'queued', 'processing'].includes(status)) {
      await new Promise<void>(resolve => {
        setTimeout(resolve, 3000)
      })
      try {
        const {data}: {data: any} = await axios.get(statusUrl, {headers: {Authorization: `Bearer ${accessToken}`}})
        status = (data?.status || data?.state || '').toString()
        this.deployDebug('Polling status', {status})
        if (process.env.DEBUG) {
          ux.info(`[datacloud:deploy] Polling status ${JSON.stringify({status})}`)
        }
        ux.action.status = status
        if (['failed', 'error'].includes(status)) {
          const errMsg: string = data?.message || 'Deployment failed'
          this.deployDebug('Polling indicates failure', {message: errMsg})
          ux.warn(`[datacloud:deploy] Polling indicates failure ${JSON.stringify({message: errMsg})}`)
          ux.action.stop('failed')
          ux.error(errMsg, {exit: 1})
        }
      } catch (error: any) {
        this.deployDebug('Polling request failed', {message: error?.message, status: error?.response?.status})
        ux.warn(`[datacloud:deploy] Polling request failed ${JSON.stringify({message: error?.message, status: error?.response?.status})}`)
        break
      }
    }
  }

  public async run(): Promise<void> {
    const {flags} = await this.parse(Deploy)
    const {
      app,
      addon,
      description,
      memory,
      name,
      path: srcPath,
      timeout,
    } = flags as unknown as {
      app: string
      addon?: string
      description?: string
      memory?: number
      name: string
      path?: string
      timeout?: number
      env?: string[]
      'authorization-name': string
      'override-token'?: string
    }

    const authorizationName = (flags as any)['authorization-name'] as string
    const envVars = this.parseEnv((flags as any).env as string[] | undefined)
    const pkgName = name

    // Configure AppLink client to locate addon and headers
    await this.configureAppLinkClient(app, addon)

    const {accessToken, instanceUrl, apiVersion} = await this.retrieveAuthorization(authorizationName, app, addon)

    const envOverrideUrl = process.env.DEPLOY_INSTANCE_URL
    const effectiveInstanceUrl = envOverrideUrl && envOverrideUrl.trim().length > 0 ? envOverrideUrl.trim() : instanceUrl
    this.deployDebug('Effective instance URL', {instance_url: effectiveInstanceUrl, overridden: Boolean(envOverrideUrl)})

    const envOverrideToken = process.env.DEPLOY_ACCESS_TOKEN
    const flagOverrideToken = (flags as any)['override-token'] as string | undefined
    const effectiveAccessToken = (flagOverrideToken && flagOverrideToken.trim()) || (envOverrideToken && envOverrideToken.trim()) || accessToken
    this.deployDebug('Effective access token', {overridden: Boolean(flagOverrideToken || envOverrideToken), access_token: effectiveAccessToken})

    // Resolve source path
    // Behavior:
    // - If --path not provided: default to 'payload' directory (must exist) and zip with top-level 'payload/'
    // - If --path payload (or ends with /payload): zip with top-level 'payload/'
    // - Otherwise: zip the provided directory as-is
    const providedPath = (srcPath && srcPath.trim().length > 0) ? srcPath.trim() : undefined
    const defaultingToPayload = !providedPath
    const isPayloadPath = providedPath ? (providedPath === 'payload' || providedPath === './payload' || providedPath.endsWith(`${path.sep}payload`)) : true
    const basePath = defaultingToPayload ? 'payload' : (providedPath as string)
    this.deployDebug('Effective source path', {path: basePath, defaulted_to_payload: defaultingToPayload, payload_mode: isPayloadPath})

    // Validate payload dir if in payload mode
    if (isPayloadPath) {
      const absPayload = path.resolve(basePath)
      if (!fs.existsSync(absPayload) || !fs.statSync(absPayload).isDirectory()) {
        ux.error(`Required 'payload' directory not found at ${absPayload}. Expected structure: payload/config.json and payload/entrypoint.py`, {exit: 1})
      }

      const cfg = path.join(absPayload, 'config.json')
      const entry = path.join(absPayload, 'entrypoint.py')
      const missingCfg = !fs.existsSync(cfg)
      const missingEntry = !fs.existsSync(entry)
      if (missingCfg || missingEntry) {
        const parts: string[] = []
        if (missingCfg) parts.push('config.json')
        if (missingEntry) parts.push('entrypoint.py')
        ux.error(`Missing required files inside payload: ${parts.join(' ')}`, {exit: 1})
      }
    }

    // Zip the source directory
    ux.action.start('Creating deployment artifact (zip)')
    const zipBuffer = await this.zipDirectory(basePath, {zipRoot: isPayloadPath ? 'payload' : undefined})
    this.deployDebug('Created zip buffer', {bytes: zipBuffer.byteLength})
    ux.action.stop('done')

    // Save a local copy for manual retries via curl ONLY when DEBUG is enabled
    if (process.env.DEBUG) {
      try {
        const tmpDir = (process.env.TMPDIR && process.env.TMPDIR.trim().length > 0) ? process.env.TMPDIR.trim() : '/tmp'
        const tmpZipPath = path.join(tmpDir, 'deployment.zip')
        fs.writeFileSync(tmpZipPath, zipBuffer)
        this.deployDebug('Saved local zip copy', {path: tmpZipPath, bytes: zipBuffer.byteLength})
        ux.info(`[datacloud:deploy] Saved zip ${JSON.stringify({path: tmpZipPath, bytes: zipBuffer.byteLength})}`)
      } catch (error: any) {
        this.deployDebug('Failed to save local zip copy', {message: error?.message})
      }
    }

    // Build multipart body similar to publish.ts (zip + metadata JSON)
    const metadata = this.buildMetadata(pkgName, {
      description,
      envVars,
      timeout,
      memory,
    })

    this.deployDebug('Metadata prepared', {
      name: pkgName,
      has_description: Boolean(description),
      env_keys: envVars ? Object.keys(envVars) : [],
      timeout: typeof timeout === 'number' ? timeout : undefined,
      memory: typeof memory === 'number' ? memory : undefined,
    })

    // Redact env var values for debug
    const redactedMetadata: Record<string, unknown> = {
      ...metadata,
      ...(metadata as any).env
        ? {env: Object.fromEntries(Object.keys(((metadata as any).env as Record<string, string>) || {}).map(k => [k, '<redacted>']))}
        : {},
    }

    this.deployDebug('Request payload', {
      artifact_bytes: zipBuffer.byteLength,
      metadata: redactedMetadata,
    })

    await this.deployAndPoll({
      instanceUrl: effectiveInstanceUrl,
      accessToken: effectiveAccessToken,
      zipBuffer,
      metadata,
      pkgName,
      apiVersion,
    })
  }
}
