import {expect} from 'chai'
import nock from 'nock'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {stderr, stdout} from 'stdout-stderr'
import {runCommand} from '../../run-command'
import Cmd from '../../../src/commands/datacloud/deploy'
import {
  addon,
  addonAttachment,
  app,
  sso_response,
} from '../../helpers/fixtures'

// Helper to create a small temp folder with one file
const createTempSource = (): string => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dcc-deploy-'))
  fs.writeFileSync(path.join(dir, 'index.txt'), 'hello')
  return dir
}

describe('datacloud:deploy', function () {
  const {env} = process
  let api: nock.Scope
  let applinkApi: nock.Scope
  let salesforceApi: nock.Scope

  beforeEach(function () {
    process.env = {}
    // Heroku app + AppLink config
    api = nock('https://api.heroku.com')
      .get('/apps/my-app')
      .reply(200, app)
      .get('/apps/my-app/addons')
      .reply(200, [addon])
      .get('/apps/my-app/addon-attachments')
      .reply(200, [addonAttachment])
      .get('/apps/my-app/config-vars')
      .reply(200, {
        HEROKU_APPLINK_API_URL: 'https://applink-api.heroku.com/addons/01234567-89ab-cdef-0123-456789abcdef',
        HEROKU_APPLINK_TOKEN: 'token',
      })
      .get('/apps/my-app/addons/01234567-89ab-cdef-0123-456789abcdef/sso')
      .reply(200, sso_response)

    applinkApi = nock('https://applink-api.heroku.com')
    salesforceApi = nock('https://instance.test.salesforce.com')
  })

  afterEach(function () {
    process.env = env
    api.done()
    applinkApi.done()
    salesforceApi.done()
    nock.cleanAll()
  })

  it('zips and deploys via SSOT using stored authorization', async function () {
    const src = createTempSource()

    // AppLink returns access token + instance url for authorization
    applinkApi
      .get('/addons/01234567-89ab-cdef-0123-456789abcdef/authorizations/datacloud/my-auth')
      .reply(200, {
        org: {developer_name: 'my-auth'},
        access_token: 'ATOKEN',
        instance_url: 'https://instance.test.salesforce.com',
      })

    // SSOT deploy accepts form and returns a status URL to poll
    salesforceApi
      .post('/services/data/v63.0/ssot/data-custom-code')
      .reply(200, {
        status_url: 'https://instance.test.salesforce.com/services/data/v63.0/ssot/deploy-status/abc',
      })

    // Polling returns success
    salesforceApi
      .get('/services/data/v63.0/ssot/deploy-status/abc')
      .times(1)
      .reply(200, {status: 'succeeded'})

    await runCommand(Cmd, [
      '--app=my-app',
      '--authorization-name=my-auth',
      `--path=${src}`,
      '--name=my-func',
      '--runtime=python3.11',
    ])

    expect(stderr.output).to.contain('Retrieving Data Cloud authorization')
    expect(stderr.output).to.contain('Creating deployment artifact (zip)')
    expect(stderr.output).to.contain('Deploying my-func to Data Cloud')
    expect(stdout.output).to.eq('')
  })
})
