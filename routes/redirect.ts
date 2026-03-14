/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const allowedUrls = [
      'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
      'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
      'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
    ];

    const toUrl = String(query.to || '');

    if (allowedUrls.includes(toUrl)) {
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => allowedUrls.includes(toUrl));
      res.redirect(toUrl);
    } else {
      res.status(406);
      next(new Error('Unrecognized target URL for redirect'));
    }
  }
}

function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}
