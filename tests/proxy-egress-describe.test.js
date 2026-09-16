const test = require('node:test')
const assert = require('node:assert/strict')

const config = require('../src/config/index.js')
const { describeEgress } = require('../src/utils/proxy-helper')

// The WAF challenge is per egress IP. Every parse failure names its egress so a
// burnt proxy can be told apart from a Qwen-side outage in one log line.

const withGlobalProxy = (value, fn) => {
  const saved = config.proxyUrl
  config.proxyUrl = value
  try {
    return fn()
  } finally {
    config.proxyUrl = saved
  }
}

test('describeEgress: "direct" when neither the account nor PROXY_URL sets a proxy', () => {
  withGlobalProxy(null, () => {
    assert.equal(describeEgress({ email: 'a@example.com' }), 'direct')
    assert.equal(describeEgress(null), 'direct')
    assert.equal(describeEgress(undefined), 'direct')
  })
})

test('describeEgress: the account proxy wins over PROXY_URL and is trimmed', () => {
  withGlobalProxy('http://global.example:8080', () => {
    assert.equal(
      describeEgress({ proxy: '  socks5://lohari-warp-qwen:9091  ' }),
      'socks5://lohari-warp-qwen:9091'
    )
  })
})

test('describeEgress: falls back to PROXY_URL when the account has no proxy', () => {
  withGlobalProxy('socks5://127.0.0.1:1080', () => {
    assert.equal(describeEgress({ proxy: '' }), 'socks5://127.0.0.1:1080')
    assert.equal(describeEgress({}), 'socks5://127.0.0.1:1080')
  })
})

test('describeEgress: proxy credentials never reach the log line', () => {
  withGlobalProxy(null, () => {
    assert.equal(
      describeEgress({ proxy: 'http://user:s3cr3t@proxy.example:3128' }),
      'http://***@proxy.example:3128'
    )
    assert.equal(
      describeEgress({ proxy: 'socks5://u:p@10.0.0.2:1080' }),
      'socks5://***@10.0.0.2:1080'
    )
  })
})
