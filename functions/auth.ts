import { Request, Response, NextFunction } from "express";
import { promises as fs } from "fs";
import path from "path";
import Key from "../types/api/keys/key";

const apiKeysPath = path.resolve(__dirname, "../apiKeys.json");

async function loadKeys(): Promise<Key[]> {
    try {
        const data = await fs.readFile(apiKeysPath, "utf-8");
        return JSON.parse(data);
    } catch (err) {
        return [];
    }
}

interface AuthRequest extends Request {
    apiKey?: Key;
}

function authenticate(requiredPermissions?: string[]) {
    return async (req: AuthRequest, res: Response, next: NextFunction) => {
        const apiKey: string = req.headers['x-api-key'] as string || 
                               req.headers['authorization']?.replace('Bearer ', '') || 
                               (req.query.apiKey as string);

        if (!apiKey) {
            return res.status(401).json({
                error: "HTTP 401 Unauthorized",
                message: "No API key provided."
            });
        }

        const keys = await loadKeys();
        const foundKey = keys.find(k => k.key === apiKey);

        if (!foundKey) {
            return res.status(401).json({
                error: "HTTP 401 Unauthorized",
                message: "Invalid API key."
            });
        }

        if (requiredPermissions && requiredPermissions.length > 0) {
            const missingPermissions = requiredPermissions.filter(perm => {
                return !(foundKey.permissions as any)[perm];
            });

            if (missingPermissions.length > 0) {
                return res.status(403).json({
                    error: "HTTP 403 Forbidden",
                    message: "Insufficient permissions.",
                    required: requiredPermissions,
                    missing: missingPermissions
                });
            }
        }

        req.apiKey = foundKey;
        next();
    };
}

export default authenticate;
export { AuthRequest };