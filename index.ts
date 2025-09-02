import express from "express";
import { Request, Response } from "express";
import bodyParser from "body-parser";
import cors from "cors";
import limiter from "./functions/rateLimit";
import authenticate, { AuthRequest } from "./functions/auth";
import createApiKey from "./functions/keys/createKey";
import { deleteApiKey } from "./functions/keys/deleteKey";
import listKeys from "./functions/keys/manageKey";
import Permissions from "./types/api/keys/permissions";

const app = express();
const port = 4000;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(bodyParser.json());
app.use(limiter);

app.get("/health", (req, res) => {
    res.status(200).send("OK");
});

// API Key Management Endpoints
app.post("/api/keys", authenticate(["createApiKey"]), async (req: AuthRequest, res: Response) => {
    const { name, permissions } = req.body;
    
    if (!name || typeof name !== "string") {
        return res.status(400).json({ error: "Name is required" });
    }
    
    const defaultPermissions: Permissions = {
        viewStats: true,
        createApiKey: false,
        deleteApiKey: false,
        viewApiKeys: false,
        usePowerCommands: false
    };
    
    const finalPermissions = { ...defaultPermissions, ...(permissions || {}) };
    
    try {
        const key = await createApiKey(name, finalPermissions);
        res.status(201).json(key);
    } catch (error) {
        res.status(500).json({ error: "Failed to create API key" });
    }
});

app.get("/api/keys", authenticate(["viewApiKeys"]), async (req: AuthRequest, res: Response) => {
    try {
        const keys = await listKeys.list();
        const sanitizedKeys = keys.map(k => ({
            uuid: k.uuid,
            name: k.name,
            permissions: k.permissions,
            createdAt: k.createdAt
        }));
        res.status(200).json(sanitizedKeys);
    } catch (error) {
        res.status(500).json({ error: "Failed to list API keys" });
    }
});

app.delete("/api/keys/:identifier", authenticate(["deleteApiKey"]), async (req: AuthRequest, res: Response) => {
    const { identifier } = req.params;
    
    if (!identifier) {
        return res.status(400).json({ error: "Key identifier is required" });
    }
    
    try {
        const success = await deleteApiKey(identifier);
        if (success) {
            res.status(200).json({ message: "API key deleted successfully" });
        } else {
            res.status(404).json({ error: "API key not found" });
        }
    } catch (error) {
        res.status(500).json({ error: "Failed to delete API key" });
    }
});

import runSpeedtest from "./functions/stats/speedtest";
import { SpeedtestResult } from "./types/statistics/speedtest";
app.get("/stats/speedtest", authenticate(["viewStats"]), (req: AuthRequest, res: Response) => {
    runSpeedtest()
        .then((result: SpeedtestResult) => {
            res.status(200).json(result);
        })
        .catch((error) => {
            res.status(500).json({ error: error.message });
        });
});

import * as SYSTEM from "./types/statistics/system";
import * as systeminfo from "./functions/stats/utils/system";
// Get all system information
app.get("/data", authenticate(["viewStats"]), async (req: AuthRequest, res: Response) => {
    const data = {
        cpu: await systeminfo.getCPUInfo(), 
        gpu: await systeminfo.getGPUInfo(),
        disk: await systeminfo.getDiskInfo(),
        ram: await systeminfo.getRAMInfo(),
        mainboard: await systeminfo.getMainboardInfo(),
        os: await systeminfo.getOSInfo()
    };
    res.status(200).json(data);
});
// Get individual system information
// Get CPU information
app.get("/data/cpu", authenticate(["viewStats"]), async (req: AuthRequest, res: Response) => {
    const data: SYSTEM.CPU = await systeminfo.getCPUInfo();
    res.status(200).json(data);
});
// Get GPU information
app.get("/data/gpu", authenticate(["viewStats"]), async (req: AuthRequest, res: Response) => {
    const data: SYSTEM.Graphics[] = await systeminfo.getGPUInfo();
    res.status(200).json(data);
});
// Get Disk information
app.get("/data/disk", authenticate(["viewStats"]), async (req: AuthRequest, res: Response) => {
    const data: SYSTEM.DiskLayout[] = await systeminfo.getDiskInfo();
    res.status(200).json(data);
});
// Get RAM information
app.get("/data/ram", authenticate(["viewStats"]), async (req: AuthRequest, res: Response) => {
    const data: SYSTEM.RAM = await systeminfo.getRAMInfo();
    res.status(200).json(data);
});
// Get Mainboard information
app.get("/data/mainboard", authenticate(["viewStats"]), async (req: AuthRequest, res: Response) => {
    const data: SYSTEM.Mainboard = await systeminfo.getMainboardInfo();
    res.status(200).json(data);
}); 
// Get OS information
app.get("/data/os", authenticate(["viewStats"]), async (req: AuthRequest, res: Response) => {
    const data: SYSTEM.OS = await systeminfo.getOSInfo();
    res.status(200).json(data);
});

import * as PROCESS from "./functions/stats/utils/process";
import ProcessInfo from "./types/statistics/process";
// List processes
app.get("/processes", authenticate(["viewStats"]), async (req: AuthRequest, res: Response) => {
    const processes: ProcessInfo[] = await PROCESS.listProcesses();
    res.status(200).json(processes);
});
// Kill a process by PID
app.post("/processes/kill", authenticate(["viewStats"]), async (req: AuthRequest, res: Response) => {
    const pid: number = req.body.pid;
    if (typeof pid !== 'number') {
        return res.status(400).json({ error: "Invalid PID" });
    }  
    const success: boolean = await PROCESS.killProcess(pid);
    if (success) {
        res.status(200).json({ message: `Process ${pid} killed successfully` });
    }
    else {
        res.status(500).json({ error: `Failed to kill process ${pid}` });
    }
});

import * as POWER from "./functions/stats/power";
// Reboot the system
app.post("/power/reboot", authenticate(["usePowerCommands"]), async (req: AuthRequest, res: Response) => {
    try {
        await POWER.rebootSystem();
        res.status(200).json({ message: "System reboot initiated" });
    } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        res.status(500).json({ error: message });
    }
});
// Shutdown the system
app.post("/power/shutdown", authenticate(["usePowerCommands"]), async (req: AuthRequest, res: Response) => {
    try {
        await POWER.shutdownSystem();
        res.status(200).json({ message: "System shutdown initiated" });
    } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        res.status(500).json({ error: message });
    }
});

// Network sniffer endpoints
import { NetworkSniffer } from "./functions/logs/network/sniffer";
import { NetworkPacket } from "./types/logs/network";
let sniffer: NetworkSniffer | null = null;
const packetLogs: NetworkPacket[] = [];
let allPacketLogs: NetworkPacket[] = []; // Store all packets without limit

// Start Sniffer
app.post("/network/sniffer/start", authenticate(["viewStats"]), (req: AuthRequest, res: Response) => {
  const interfaceName: unknown = req.body.interface;

  if (typeof interfaceName !== "string" || interfaceName.trim().length === 0) {
    return res.status(400).json({ error: "Invalid network interface" });
  }

  if (sniffer) {
    return res.status(400).json({ error: "Sniffer is already running" });
  }

  try {
    sniffer = new NetworkSniffer(interfaceName.trim());
    sniffer.start();

    sniffer.onPacket((packet: NetworkPacket) => {
      packetLogs.push(packet);
      allPacketLogs.push(packet);
      if (packetLogs.length > 1000) packetLogs.shift(); // max 1000 for recent logs
      // Optional: Limit all logs to prevent memory issues (e.g., 100k packets)
      if (allPacketLogs.length > 100000) allPacketLogs.shift();
    });

    res
      .status(200)
      .json({ message: `Network sniffer started on ${interfaceName.trim()}` });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("Failed to start sniffer:", message);
    res.status(500).json({ error: message });
  }
});

// Stop Sniffer
app.post("/network/sniffer/stop", authenticate(["viewStats"]), (req: AuthRequest, res: Response) => {
  if (!sniffer) {
    return res.status(400).json({ error: "Sniffer is not running" });
  }

  try {
    sniffer.stop();
    sniffer = null;
    res.status(200).json({ message: "Network sniffer stopped" });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("Failed to stop sniffer:", message);
    res.status(500).json({ error: message });
  }
});

// Get last packets (recent 1000)
app.get("/network/sniffer/logs", authenticate(["viewStats"]), (req: AuthRequest, res: Response) => {
  res.json(packetLogs);
});

// Get all packets
app.get("/network/sniffer/logs/all", authenticate(["viewStats"]), (req: AuthRequest, res: Response) => {
  res.json({
    total: allPacketLogs.length,
    packets: allPacketLogs
  });
});

// Clear all logs
app.delete("/network/sniffer/logs", authenticate(["viewStats"]), (req: AuthRequest, res: Response) => {
  packetLogs.length = 0;
  allPacketLogs.length = 0;
  res.status(200).json({ message: "All network logs cleared" });
});


app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});