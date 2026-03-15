/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import fs from 'fs';
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

export function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify(file: string, res: Response, next: NextFunction) {
    if (!file || !(endsWithAllowlistedFileType(file) || file === 'incident-support.kdbx')) {
      res.status(403);
      return next(new Error('Only .md and .pdf files are allowed!'));
    }

    file = security.cutOffPoisonNullByte(file);

    challengeUtils.solveIf(challenges.directoryListingChallenge, () => file.toLowerCase() === 'acquisitions.md');
    verifySuccessfulPoisonNullByteExploit(file);

    const ftpDir = path.resolve('ftp');
    const requestedPath = path.join(ftpDir, file);
    const resolvedPath = path.resolve(requestedPath);

    const ftpDirWithSep = ftpDir + path.sep;
    if (!resolvedPath.startsWith(ftpDirWithSep)) {
      res.status(403);
      return next(new Error('Invalid file path – access denied'));
    }

    if (!fs.existsSync(resolvedPath)) {
      res.status(404);
      return next(new Error('File not found or invalid path'));
    }

    const safeFileName = path.basename(resolvedPath);
    if (!endsWithAllowlistedFileType(safeFileName) && safeFileName !== 'incident-support.kdbx') {
      res.status(403);
      return next(new Error('Only .md and .pdf files are allowed!'));
    }

    res.sendFile(resolvedPath);
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
