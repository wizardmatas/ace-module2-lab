/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import dns from 'node:dns/promises'
import net from 'node:net'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIpV4 (ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) {
    return true
  }
  const [a, b, c] = parts
  if (a === 0) return true
  if (a === 10) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 127) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 0 && c === 0) return true
  if (a === 192 && b === 0 && c === 2) return true
  if (a === 192 && b === 168) return true
  if (a === 198 && (b === 18 || b === 19)) return true
  if (a === 198 && b === 51 && c === 100) return true
  if (a === 203 && b === 0 && c === 113) return true
  if (a >= 224) return true
  return false
}

function isPrivateIpV6 (ip: string): boolean {
  const normalized = ip.toLowerCase().replace(/^\[|\]$/g, '')
  if (normalized === '::1' || normalized === '::') return true
  if (normalized.startsWith('::ffff:')) {
    const v4Part = normalized.substring(7)
    if (net.isIPv4(v4Part)) {
      return isPrivateIpV4(v4Part)
    }
    return true
  }
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true
  if (/^fe[89ab]/i.test(normalized)) return true
  if (normalized.startsWith('100::') || normalized.startsWith('2001:db8:')) return true
  if (normalized.startsWith('ff')) return true
  return false
}

function isPrivateIp (ip: string): boolean {
  if (net.isIPv4(ip)) return isPrivateIpV4(ip)
  if (net.isIPv6(ip)) return isPrivateIpV6(ip)
  return true
}

async function isSafeUrl (urlString: string): Promise<boolean> {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(urlString)
  } catch {
    return false
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return false
  }

  let hostname = parsedUrl.hostname
  if (!hostname) {
    return false
  }

  hostname = hostname.replace(/^\[|\]$/g, '')

  const lowerHost = hostname.toLowerCase()
  if (
    lowerHost === 'localhost' ||
    lowerHost.endsWith('.localhost') ||
    lowerHost.endsWith('.local') ||
    lowerHost.endsWith('.internal') ||
    lowerHost.endsWith('.lan') ||
    lowerHost.endsWith('.localdomain') ||
    lowerHost.endsWith('.home') ||
    lowerHost.endsWith('.arpa') ||
    lowerHost === 'instance-data'
  ) {
    return false
  }

  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      return false
    }
  } else {
    try {
      const addresses = await dns.lookup(hostname, { all: true })
      if (!addresses || addresses.length === 0) {
        return false
      }
      for (const addr of addresses) {
        if (isPrivateIp(addr.address)) {
          return false
        }
      }
    } catch {
      return false
    }
  }

  return true
}

async function fetchSafeImage (url: string, maxRedirects = 3): Promise<globalThis.Response> {
  let currentUrl = url
  for (let i = 0; i <= maxRedirects; i++) {
    if (!await isSafeUrl(currentUrl)) {
      throw new Error('Unsafe or invalid URL')
    }
    const response = await fetch(currentUrl, { redirect: 'manual' })
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location')
      if (!location) {
        throw new Error('Redirect without Location header')
      }
      currentUrl = new URL(location, currentUrl).toString()
      continue
    }
    return response
  }
  throw new Error('Too many redirects')
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (typeof url === 'string' && await isSafeUrl(url)) {
          try {
            const response = await fetchSafeImage(url)
            if (!response.ok || !response.body) {
              throw new Error('url returned a non-OK status code or an empty body')
            }
            const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
            const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
            await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
          } catch (error) {
            try {
              const user = await UserModel.findByPk(loggedInUser.data.id)
              await user?.update({ profileImage: url })
              logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
            } catch (error) {
              next(error)
              return
            }
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
