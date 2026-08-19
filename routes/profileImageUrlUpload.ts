/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns/promises'
import net from 'node:net'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function parseIPv4 (ip: string): number[] | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  const octets = []
  for (const part of parts) {
    const num = Number(part)
    if (isNaN(num) || num < 0 || num > 255 || part.trim() === '') {
      return null
    }
    octets.push(num)
  }
  return octets
}

function isPrivateIPv4 (ip: string): boolean {
  const octets = parseIPv4(ip)
  if (!octets) return true

  const o0 = octets[0]
  const o1 = octets[1]
  const o2 = octets[2]

  if (o0 === 127) return true
  if (o0 === 10) return true
  if (o0 === 172 && o1 >= 16 && o1 <= 31) return true
  if (o0 === 192 && o1 === 168) return true
  if (o0 === 169 && o1 === 254) return true
  if (o0 === 0) return true
  if (o0 >= 224) return true
  if (o0 === 100 && o1 >= 64 && o1 <= 127) return true
  if (o0 === 192 && o1 === 0 && o2 === 0) return true
  if (o0 === 198 && o1 >= 18 && o1 <= 19) return true

  return false
}

function isPrivateIp (ip: string): boolean {
  if (net.isIP(ip) === 0) {
    return false
  }
  const cleanIp = ip.trim().toLowerCase()
  if (cleanIp.includes(':')) {
    if (cleanIp === '::1' || cleanIp === '0:0:0:0:0:0:0:1' || /^0+:(0+:){5}0+:[01]$/.test(cleanIp)) {
      return true
    }
    if (cleanIp === '::' || cleanIp === '0:0:0:0:0:0:0:0' || /^0+:(0+:){6}0+$/.test(cleanIp)) {
      return true
    }
    if (/^fe[89ab]/i.test(cleanIp)) {
      return true
    }
    if (/^f[cd]/i.test(cleanIp)) {
      return true
    }
    const lastColonIdx = cleanIp.lastIndexOf(':')
    if (lastColonIdx !== -1) {
      const remaining = cleanIp.substring(lastColonIdx + 1)
      if (remaining.includes('.')) {
        return isPrivateIPv4(remaining)
      }
    }
    return false
  } else {
    return isPrivateIPv4(cleanIp)
  }
}

async function isSafeUrl (urlStr: string): Promise<boolean> {
  try {
    const parsedUrl = new URL(urlStr)
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }

    const hostname = parsedUrl.hostname
    if (!hostname) {
      return false
    }

    if (isPrivateIp(hostname)) {
      return false
    }

    const lowerHostname = hostname.toLowerCase()
    if (lowerHostname === 'localhost' || lowerHostname.endsWith('.local') || lowerHostname.endsWith('.localhost')) {
      return false
    }

    const lookupResult = await dns.lookup(hostname, { all: true }).catch(() => [])
    if (lookupResult.length === 0) {
      return false
    }

    for (const entry of lookupResult) {
      if (isPrivateIp(entry.address)) {
        return false
      }
    }

    return true
  } catch (err) {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (typeof url !== 'string') {
        res.status(400)
        next(new Error('Invalid URL format'))
        return
      }
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (!(await isSafeUrl(url))) {
          res.status(400)
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
          return
        }
        try {
          const response = await fetch(url)
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
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
