/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import fs from 'fs';
import { type Request, type Response, type NextFunction } from 'express'

export function serveQuarantineFiles() {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file;

    if (!file) {
      res.status(400);
      return next(new Error('File parameter is required'));
    }

    const quarantineDir = path.resolve('ftp/quarantine');
    const requestedPath = path.join(quarantineDir, file);
    const resolvedPath = path.resolve(requestedPath);

    const quarantineDirWithSep = quarantineDir + path.sep;
    if (!resolvedPath.startsWith(quarantineDirWithSep)) {
      res.status(403);
      return next(new Error('Invalid file path – access denied'));
    }

    if (!fs.existsSync(resolvedPath)) {
      res.status(404);
      return next(new Error('File not found'));
    }

    res.sendFile(resolvedPath);
  };
}
