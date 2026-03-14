/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import fs from 'fs';
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles() {
  return ({params}: Request, res: Response, next: NextFunction) => {
    const file = params.file;

    if (!file) {
      res.status(400);
      return next(new Error('File parameter is required'));
    }

    const logsDir = path.resolve('logs');
    const requestedPath = path.join(logsDir, file);
    const resolvedPath = path.resolve(requestedPath);

    const logsDirWithSep = logsDir + path.sep;
    if (!resolvedPath.startsWith(logsDirWithSep)) {
      res.status(403);
      return next(new Error('Invalid file path – access denied'));
    }

    if (!fs.existsSync(resolvedPath)) {
      res.status(404);
      return next(new Error('File not found'));
    }

    res.sendFile(resolvedPath);
  }
}
