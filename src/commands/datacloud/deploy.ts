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

  static flags = {
    app: flags.app({required: true}),
    addon: flags.string({description: 'unique name or ID of an AppLink add-on'}),
    remote: flags.remote(),

    // Mirror Python CLI deploy flags (core subset)
    'authorization-name': flags.string({required: true, description: 'AppLink Data Cloud authorization developer name to use'}),
    path: flags.string({required: true, description: 'Path to source directory to zip and deploy'}),
    name: flags.string({required: true, description: 'Data Custom Code package/function name'}),
    runtime: flags.string({required: true, description: 'Runtime, e.g., python3.11'}),
    description: flags.string({description: 'Package description'}),
    env: flags.string({multiple: true, description: 'Environment variables as KEY=VALUE; repeatable'}),
    timeout: flags.integer({description: 'Function timeout in seconds'}),
    memory: flags.integer({description: 'Memory size in MB'}),
  }

  protected async zipDirectory(dir: string): Promise<Buffer> {
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
    zip.addLocalFolder(abs, undefined, filePath => {
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

  public async run(): Promise<void> {
    const {flags} = await this.parse(Deploy)
    const {
      app,
      addon,
      description,
      memory,
      name,
      path: srcPath,
      runtime,
      timeout,
    } = flags as unknown as {
      app: string
      addon?: string
      description?: string
      memory?: number
      name: string
      path: string
      runtime: string
      timeout?: number
      env?: string[]
      'authorization-name': string
    }

    const authorizationName = (flags as any)['authorization-name'] as string
    const envVars = this.parseEnv((flags as any).env as string[] | undefined)
    const pkgName = name

    // Configure AppLink client to locate addon and headers
    await this.configureAppLinkClient(app, addon)

    // Retrieve authorization (access_token, instance_url) from AppLink
    ux.action.start('Retrieving Data Cloud authorization')
    const {body: auth} = await this.applinkClient.get<AuthorizationResponse>(
      `/addons/${this.addonId}/authorizations/datacloud/${authorizationName}`,
      {
        headers: {authorization: `Bearer ${this._applinkToken}`},
        retryAuth: false,
      }
    )
    const accessToken = (auth as any).access_token as string
    const instanceUrl = (auth as any).instance_url as string
    if (!accessToken || !instanceUrl) {
      ux.error('Authorization did not return access_token and instance_url. Ensure the authorization is completed.', {exit: 1})
    }
    ux.action.stop()

    // Zip the source directory
    ux.action.start('Creating deployment artifact (zip)')
    const zipBuffer = await this.zipDirectory(srcPath)
    ux.action.stop('done')

    // Build multipart body similar to publish.ts (zip + metadata JSON)
    const metadata: Record<string, unknown> = {
      name: pkgName,
      runtime,
      ...(description ? {description} : {}),
      ...(envVars ? {env: envVars} : {}),
      ...(typeof timeout === 'number' ? {timeout} : {}),
      ...(typeof memory === 'number' ? {memory} : {}),
    }

    const formData = new FormData()
    formData.append('artifact', new Blob([zipBuffer], {type: 'application/zip'}))
    formData.append('metadata', new Blob([JSON.stringify(metadata)], {type: 'application/json'}))

    // POST to SSOT data-custom-code endpoint
    const ssotUrl = `${instanceUrl.replace(/\/?$/, '')}/services/data/v63.0/ssot/data-custom-code`
    ux.action.start(`Deploying ${pkgName} to Data Cloud`)
    let response: {data?: any}
    try {
      response = await axios.post(ssotUrl, formData, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
          // Content-Type will be set by axios based on FormData boundary
        },
        maxBodyLength: Number.POSITIVE_INFINITY,
        maxContentLength: Number.POSITIVE_INFINITY,
      })
    } catch (error: any) {
      const msg: string = error?.response?.data?.message || error?.message || 'Deployment failed'
      ux.action.stop('failed')
      ux.error(msg, {exit: 1})
    }

    // If API returns a status URL, poll until completion
    const statusUrl: string | undefined = response?.data?.status_url || response?.data?.statusUrl || response?.data?.url
    if (statusUrl) {
      let status: string = 'pending'
      // Best-effort polling
      while (['pending', 'building', 'deploying', 'queued', 'processing'].includes(status)) {
        await new Promise<void>(resolve => {
          setTimeout(resolve, 3000)
        })

        try {
          const {data}: {data: any} = await axios.get(statusUrl, {headers: {Authorization: `Bearer ${accessToken}`}})
          status = (data?.status || data?.state || '').toString()
          ux.action.status = status
          if (['failed', 'error'].includes(status)) {
            const errMsg: string = data?.message || 'Deployment failed'
            ux.action.stop('failed')
            ux.error(errMsg, {exit: 1})
          }
        } catch {
          // If polling endpoint fails, break gracefully
          break
        }
      }
    }

    ux.action.stop('done')
  }
}
